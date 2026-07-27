package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/brightinteraction/trustissues/internal/alerts"
	"github.com/brightinteraction/trustissues/internal/db"
)

// RotationTarget defines where a rotated key should be delivered.
//
// Trustissues supports three target types: "webhook" (HMAC-signed POST of the
// new value to a user-configured URL), "forgejo_secret" (update an Actions
// secret on a Forgejo/Gitea repository), and "notify" (fire the notification
// channels only, no value delivery). The control-plane target types dockyard
// carried (env_var, file_write, reload_endpoint) are deliberately not ported:
// they require a managed-server agent fleet that this standalone product does
// not have.
type RotationTarget struct {
	Type string `json:"type"` // "webhook", "forgejo_secret", "notify"

	// forgejo_secret target
	Instance   string `json:"instance,omitempty"`
	Repo       string `json:"repo,omitempty"`
	SecretName string `json:"secret_name,omitempty"`
	AuthToken  string `json:"auth_token,omitempty"` // vault entry name for the Forgejo token

	// webhook target
	WebhookURL    string `json:"webhook_url,omitempty"`
	WebhookSecret string `json:"webhook_secret,omitempty"` // HMAC secret for signing

	// Label for display
	Label string `json:"label,omitempty"`

	// ConfiguredBy is the user id that last wrote this target. AuthToken names
	// another vault entry, and it MUST be resolved against the identity that
	// CONFIGURED the target, never against the entry's owner: on a shared
	// collection entry any editor can add a target, so resolving as the owner
	// lets that editor name one of the owner's unrelated personal secrets and
	// have it delivered to a destination the editor controls. UpdateTargets
	// stamps this server-side on every write and overwrites whatever the client
	// sent, so it cannot be forged.
	ConfiguredBy string `json:"configured_by,omitempty"`
}

// DeliveryResult records the outcome of delivering a key to a target.
type DeliveryResult struct {
	Target  RotationTarget `json:"target"`
	Success bool           `json:"success"`
	Error   string         `json:"error,omitempty"`
}

// ParseRotationTargets parses the rotation_targets JSON column. It always
// returns a non-nil slice so callers that marshal the result straight into a
// JSON response (GET /api/vault/{id}/targets) emit `[]` for an entry with no
// targets, never `null`.
func ParseRotationTargets(raw string) []RotationTarget {
	targets := make([]RotationTarget, 0)
	if raw != "" && raw != "[]" {
		_ = json.Unmarshal([]byte(raw), &targets)
	}
	return targets
}

// DeliverRotatedKey pushes a new key value to all configured targets for a vault entry.
// Returns results for each target. Failures are logged but don't block other targets.
//
// oldValue is the pre-rotation value. None of the remaining target types
// consume it (only the cut reload_endpoint grace flow did), but the parameter
// is kept so callers ported from dockyard, which always have it in hand, need
// no signature change.
//
// userID is the ENTRY OWNER and is used for logging context only. Vault
// references inside a target (forgejo_secret's auth_token) resolve as
// target.ConfiguredBy instead; see the RotationTarget doc comment for why.
func DeliverRotatedKey(ctx context.Context, queries *db.Queries, vault *VaultHandler, entryName string, oldValue string, newValue string, targets []RotationTarget, userID string) []DeliveryResult {
	results := make([]DeliveryResult, 0, len(targets))

	for _, target := range targets {
		var err error
		switch target.Type {
		case "forgejo_secret":
			err = deliverToForgejoSecret(ctx, queries, vault, target, newValue, userID)
		case "webhook":
			err = deliverToWebhook(ctx, target, entryName, newValue)
		case "notify":
			// Notification is handled separately by the caller via ChannelDispatcher
			continue
		default:
			err = fmt.Errorf("unknown target type: %s", target.Type)
		}

		result := DeliveryResult{Target: target, Success: err == nil}
		if err != nil {
			// summarizeDelivery folds result.Error into last_rotation_error,
			// which the API returns, the browser renders verbatim, AND
			// dispatchRotationAlert ships to notification channels off-box. Two
			// different leaks have to be closed here:
			//
			//   - a transport failure is a *url.Error whose Error() embeds the
			//     full target URL (internal IPs for an SSRF-blocked webhook,
			//     plus any query/userinfo). redactUpstreamError rewrites it.
			//   - a non-2xx used to be built with fmt.Errorf including up to
			//     200 bytes of the raw upstream body, which redactUpstreamError
			//     does NOT touch (it only matches *url.Error), so the body went
			//     straight through. Those sites now return upstreamHTTPError,
			//     whose Error() is structural and whose body is slog-only.
			//
			// The unredacted cause stays in the slog line below.
			result.Error = redactUpstreamError(err)
			slog.Error("vault delivery: target failed",
				"type", target.Type,
				"entry", entryName,
				"error", err)
		} else {
			slog.Info("vault delivery: target succeeded",
				"type", target.Type,
				"entry", entryName,
				"label", target.Label)
		}
		results = append(results, result)
	}

	return results
}

// summarizeDelivery inspects delivery results and returns a rotation status
// ("success" only if every target delivered, otherwise "partial") plus a
// human summary naming the failed targets for last_rotation_error. This is
// what makes a rotation that didn't reach a consumer VISIBLE instead of
// silently logged as success.
func summarizeDelivery(results []DeliveryResult) (status, summary string) {
	var failures []string
	for _, r := range results {
		if !r.Success {
			label := r.Target.Label
			if label == "" {
				label = r.Target.Type
			}
			failures = append(failures, label+": "+r.Error)
		}
	}
	if len(failures) == 0 {
		return "success", ""
	}
	return "partial", fmt.Sprintf("%d/%d delivery targets failed: %s", len(failures), len(results), strings.Join(failures, "; "))
}

// dispatchRotationAlert fires a notification to configured channels when a
// rotation's value was stored but one or more targets failed to apply.
// Best-effort: a no-op if no channel subscribes, and never panics the caller.
func dispatchRotationAlert(ctx context.Context, queries *db.Queries, decrypter alerts.ConfigDecrypter, entryName, detail string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("vault rotation: alert dispatch panicked", "recover", r)
		}
	}()
	alerts.NewChannelDispatcher(ctx, queries, decrypter).Dispatch(
		alerts.EventRotationPartial, "", "",
		map[string]string{"secret": entryName, "detail": detail},
	)
}

// deliverToForgejoSecret updates an Actions secret on a Forgejo/Gitea repository.
func deliverToForgejoSecret(ctx context.Context, queries *db.Queries, vault *VaultHandler, target RotationTarget, newValue string, userID string) error {
	if target.Instance == "" || target.Repo == "" || target.SecretName == "" {
		return fmt.Errorf("instance, repo, and secret_name are required for forgejo_secret target")
	}

	// Get the auth token for this Forgejo instance from the vault
	authToken := target.AuthToken
	if authToken == "" {
		return fmt.Errorf("auth_token (vault entry name for Forgejo access) is required")
	}

	// Resolve the auth token as the user who CONFIGURED this target, never as
	// the entry owner. ResolveVaultReference is scoped to entries that identity
	// owns, so a collection editor can only ever reach their OWN secrets here.
	// Targets written before ConfiguredBy existed carry no identity and are
	// refused rather than falling back to the owner, which is the exact
	// exfiltration path this closes.
	if target.ConfiguredBy == "" {
		return fmt.Errorf("target has no recorded configuring user; re-save this entry's rotation targets to authorize the auth_token lookup")
	}

	// Resolve the auth token from vault
	row, err := queries.ResolveVaultReference(ctx, db.ResolveVaultReferenceParams{
		Name:   authToken,
		UserID: target.ConfiguredBy,
	})
	if err != nil {
		slog.Error("vault delivery: auth_token resolve failed",
			"auth_token", authToken,
			"configured_by", target.ConfiguredBy,
			"entry_owner", userID,
			"error", err)
		return fmt.Errorf("resolve Forgejo auth token %q from the configuring user's vault: %w", authToken, err)
	}

	tokenPlaintext, err := vault.DecryptValue(row.EncryptedValue, row.Nonce, 2)
	if err != nil {
		return fmt.Errorf("decrypt Forgejo auth token: %w", err)
	}
	defer func() {
		for i := range tokenPlaintext {
			tokenPlaintext[i] = 0
		}
	}()

	// PUT /api/v1/repos/{owner}/{repo}/actions/secrets/{secretname}
	payload, _ := json.Marshal(map[string]string{"data": newValue})
	url := strings.TrimRight(target.Instance, "/") + "/api/v1/repos/" + target.Repo + "/actions/secrets/" + target.SecretName

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+string(tokenPlaintext))
	req.Header.Set("Content-Type", "application/json")

	resp, err := providerHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		return newUpstreamHTTPError(resp.StatusCode, body)
	}

	return nil
}

// deliverToWebhook POSTs the new key to a webhook URL with HMAC-SHA256 signing.
func deliverToWebhook(ctx context.Context, target RotationTarget, entryName string, newValue string) error {
	if target.WebhookURL == "" {
		return fmt.Errorf("webhook_url is required")
	}

	payload, _ := json.Marshal(map[string]string{
		"event":      "vault.key_rotated",
		"entry_name": entryName,
		"new_value":  newValue,
		"rotated_at": time.Now().UTC().Format(time.RFC3339),
	})

	req, err := http.NewRequestWithContext(ctx, "POST", target.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Trustissues-Vault/1.0")

	// HMAC-SHA256 signature if secret is provided
	if target.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(target.WebhookSecret))
		mac.Write(payload)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Vault-Signature", "sha256="+sig)
	}

	resp, err := providerHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return newUpstreamHTTPError(resp.StatusCode, body)
	}

	return nil
}

// NOTE: UpdateTargets (PUT /api/vault/{id}/targets) lives in vault.go with
// the other per-entry HTTP handlers. Its validation switch must accept
// exactly the three types this file implements delivery for: webhook,
// forgejo_secret, notify. TestUpdateTargetsValidationSetMatchesDelivery in
// vault_targets_test.go guards that contract.
