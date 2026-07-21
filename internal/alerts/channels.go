// Package alerts implements the notification channel dispatcher that fans
// events (rotation results, expiring secrets) out to configured channels.
// Trustissues ships two channel types: webhook (HMAC-signed POST, SSRF
// guarded) and slog (structured log line). The dispatcher surface mirrors
// dockyard's audited ChannelDispatcher so rotation code copied from dockyard
// needs minimal adaptation: NewChannelDispatcher(ctx, queries, decrypter)
// and Dispatch(event, source, host, data). The single-team build drops the
// orgID parameter dockyard's Dispatch carries.
package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/brightinteraction/trustissues/internal/db"
)

// ChannelType represents the notification channel type.
type ChannelType string

const (
	ChannelWebhook ChannelType = "webhook"
	ChannelSlog    ChannelType = "slog"
)

// Event type constants for Trustissues alerts.
const (
	EventRotationPartial = "vault.rotation_partial"
	EventRotationFailed  = "vault.rotation_failed"
	EventSecretExpiring  = "vault.secret_expiring"
	EventTest            = "test.notification"
)

// ConfigDecrypter decrypts encrypted channel configs. The vault handler
// satisfies this with its AES-256-GCM column crypto.
type ConfigDecrypter interface {
	DecryptValue(ciphertext, nonce []byte, encVersion int) ([]byte, error)
}

// NotificationChannel represents a configured notification channel.
type NotificationChannel struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Type   ChannelType `json:"type"`
	Config string      `json:"config"` // JSON config (decrypted)
	Events string      `json:"events"` // Comma-separated event types
}

// WebhookConfig holds generic webhook configuration.
type WebhookConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}

// ChannelDispatcher sends notifications to all enabled channels.
type ChannelDispatcher struct {
	queries   *db.Queries
	decrypter ConfigDecrypter
	client    *http.Client
	// ctx is the parent context for outgoing DB queries and HTTP calls so
	// in-flight work cancels on shutdown.
	ctx context.Context
}

// NewChannelDispatcher creates a new channel dispatcher. The parent ctx
// scopes outgoing work to the caller's lifetime; pass context.Background()
// if there is no shutdown signal to thread. decrypter may be nil when no
// encrypted channel configs exist yet (encryption_version 0 rows pass
// through untouched).
func NewChannelDispatcher(ctx context.Context, queries *db.Queries, decrypter ConfigDecrypter) *ChannelDispatcher {
	if ctx == nil {
		ctx = context.Background()
	}
	return &ChannelDispatcher{
		queries:   queries,
		decrypter: decrypter,
		client:    GuardedWebhookClient(10 * time.Second),
		ctx:       ctx,
	}
}

// GuardedWebhookClient builds an http.Client hardened against SSRF for
// sending to user-configured webhook URLs. It refuses to follow redirects (a
// public URL that 3xx-redirects to a private/metadata address is an SSRF
// vector) and re-checks the RESOLVED IP at DIAL time (not just at config
// time) so a DNS-rebinding domain that flips to a private/metadata address
// between save and send is blocked at the request boundary. Every path that
// POSTs to a user webhook must use this instead of a bare http.Client.
func GuardedWebhookClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
				Control: func(_, address string, _ syscall.RawConn) error {
					host, _, err := net.SplitHostPort(address)
					if err != nil {
						return err
					}
					if ip := net.ParseIP(host); ip != nil && isPrivateAlertIP(ip) {
						return fmt.Errorf("blocked outbound to private address %s", address)
					}
					return nil
				},
			}).DialContext,
		},
	}
}

// decryptConfig decrypts a notification channel config if encrypted.
func (d *ChannelDispatcher) decryptConfig(config string, nonce []byte, encVersion sql.NullInt64) (string, error) {
	version := int64(0)
	if encVersion.Valid {
		version = encVersion.Int64
	}

	// Not encrypted
	if version == 0 || nonce == nil {
		return config, nil
	}

	if d.decrypter == nil {
		return "", fmt.Errorf("channel config is encrypted but no decrypter is configured")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(config)
	if err != nil {
		return "", fmt.Errorf("decoding config: %w", err)
	}

	plaintext, err := d.decrypter.DecryptValue(ciphertext, nonce, int(version))
	if err != nil {
		return "", fmt.Errorf("decrypting config: %w", err)
	}

	return string(plaintext), nil
}

// Dispatch fans an event out to every enabled notification channel that has
// the event type enabled. source names the thing the event is about (e.g. a
// vault entry name), host is the instance identifier (usually the base URL
// host, may be empty). Sends run in goroutines; Dispatch never blocks on
// delivery.
func (d *ChannelDispatcher) Dispatch(event, source, host string, data map[string]string) {
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	defer cancel()
	channels, err := d.queries.ListEnabledNotificationChannels(ctx)
	if err != nil {
		slog.Error("channel dispatcher: query failed", "error", err)
		return
	}

	for _, row := range channels {
		config, err := d.decryptConfig(row.Config, row.ConfigNonce, row.EncryptionVersion)
		if err != nil {
			slog.Error("channel dispatcher: decrypt failed", "channel", row.Name, "error", err)
			continue
		}

		ch := NotificationChannel{
			ID:     row.ID,
			Name:   row.Name,
			Type:   ChannelType(row.Type),
			Config: config,
			Events: row.Events,
		}

		if !eventEnabled(ch.Events, event) {
			continue
		}

		go d.sendToChannel(ch, event, source, host, data)
	}
}

// DispatchTest sends a test notification directly to one channel, bypassing
// the per-channel event filter so a test button always exercises the real
// send path. Synchronous: the caller gets the actual send error.
func (d *ChannelDispatcher) DispatchTest(row db.GetNotificationChannelRow) error {
	config, err := d.decryptConfig(row.Config, row.ConfigNonce, row.EncryptionVersion)
	if err != nil {
		return fmt.Errorf("decrypting config: %w", err)
	}

	ch := NotificationChannel{
		ID:     row.ID,
		Name:   row.Name,
		Type:   ChannelType(row.Type),
		Config: config,
		Events: row.Events,
	}
	return d.send(ch, EventTest, "Test Secret", "test.example.com", map[string]string{
		"message": "This is a test notification from Trustissues",
	})
}

func (d *ChannelDispatcher) sendToChannel(ch NotificationChannel, event, source, host string, data map[string]string) {
	err := d.send(ch, event, source, host, data)

	if err != nil {
		slog.Error("channel dispatcher: send failed",
			"channel", ch.Name, "type", ch.Type, "error", err)
	} else {
		slog.Info("channel dispatcher: notification sent",
			"channel", ch.Name, "type", ch.Type, "event", event)
	}
}

func (d *ChannelDispatcher) send(ch NotificationChannel, event, source, host string, data map[string]string) error {
	switch ch.Type {
	case ChannelWebhook:
		return d.sendWebhook(ch, event, source, host, data)
	case ChannelSlog:
		return d.sendSlog(ch, event, source, host, data)
	default:
		return fmt.Errorf("unknown channel type %q", ch.Type)
	}
}

// sendSlog emits the event as a structured log line. Always available, useful
// as a default sink and in air-gapped deployments.
func (d *ChannelDispatcher) sendSlog(ch NotificationChannel, event, source, host string, data map[string]string) error {
	args := []any{"channel", ch.Name, "event", event, "source", source, "host", host}
	for k, v := range data {
		args = append(args, "data."+k, v)
	}
	slog.Warn("trustissues alert", args...)
	return nil
}

// sendWebhook sends a notification via generic webhook with optional
// HMAC-SHA256 signing.
func (d *ChannelDispatcher) sendWebhook(ch NotificationChannel, event, source, host string, data map[string]string) error {
	var cfg WebhookConfig
	if err := json.Unmarshal([]byte(ch.Config), &cfg); err != nil {
		return fmt.Errorf("invalid webhook config: %w", err)
	}

	if cfg.URL == "" {
		return fmt.Errorf("webhook url required")
	}

	parsedURL, err := url.Parse(cfg.URL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
		return fmt.Errorf("invalid webhook URL")
	}

	payload := formatGeneric(event, source, host, data)
	body := mustMarshal(payload)

	req, err := http.NewRequestWithContext(d.ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	if cfg.Secret != "" {
		sig, ts := SignPayload(cfg.Secret, body)
		req.Header.Set("X-Trustissues-Signature", "sha256="+sig)
		req.Header.Set("X-Trustissues-Timestamp", ts)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook error: status %d", resp.StatusCode)
	}

	return nil
}

// SignPayload produces an HMAC-SHA256 signature and a Unix timestamp for
// webhook request signing. The signed content is "timestamp.body".
func SignPayload(secret string, body []byte) (signature, timestamp string) {
	timestamp = strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + string(body)))
	signature = hex.EncodeToString(mac.Sum(nil))
	return
}

// formatGeneric produces a flat JSON payload suitable for n8n, Zapier, or any
// generic webhook consumer.
func formatGeneric(event, source, host string, data map[string]string) map[string]any {
	return map[string]any{
		"event":     event,
		"source":    source,
		"host":      host,
		"data":      data,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}

// mustMarshal marshals v, returning "{}" on the (never expected) failure so
// webhook sends never post nil bodies.
func mustMarshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		slog.Error("alerts: marshal failed", "error", err)
		return []byte("{}")
	}
	return data
}

// eventEnabled checks whether the given event type appears in the
// comma-separated list of enabled events.
func eventEnabled(enabledCSV, event string) bool {
	for _, e := range strings.Split(enabledCSV, ",") {
		if strings.TrimSpace(e) == event {
			return true
		}
	}
	return false
}

// isPrivateAlertIP reports whether ip is in a private/loopback/link-local/
// metadata range that an outbound notification must never reach (SSRF guard
// applied at dial time, after DNS resolution).
func isPrivateAlertIP(ip net.IP) bool {
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10",
		"::1/128", "fc00::/7", "fe80::/10",
	} {
		if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(ip) {
			return true
		}
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
