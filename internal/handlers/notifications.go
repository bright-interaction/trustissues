package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/go-chi/chi/v5"
)

// ConfigEncrypter encrypts notification channel configs at rest. The vault
// handler satisfies this with its AES-256-GCM column crypto (EncryptValue).
type ConfigEncrypter interface {
	EncryptValue(plaintext []byte) (ciphertext, nonce []byte, err error)
}

// NotificationChannelsHandler handles admin CRUD for alert channels
// (webhook + slog). Configs are encrypted at rest with the vault key.
type NotificationChannelsHandler struct {
	queries    *db.Queries
	encrypter  ConfigEncrypter
	dispatcher *alerts.ChannelDispatcher
}

// NewNotificationChannelsHandler creates a new NotificationChannelsHandler.
func NewNotificationChannelsHandler(queries *db.Queries, encrypter ConfigEncrypter, dispatcher *alerts.ChannelDispatcher) *NotificationChannelsHandler {
	return &NotificationChannelsHandler{queries: queries, encrypter: encrypter, dispatcher: dispatcher}
}

var validChannelTypes = map[string]bool{"webhook": true, "slog": true}

var validChannelEvents = map[string]bool{
	alerts.EventRotationSucceeded: true,
	alerts.EventRotationPartial:   true,
	alerts.EventRotationFailed:    true,
	alerts.EventSecretExpiring:    true,
}

// rotation_succeeded is default-ON: a "Notify only" target is useless without it, and
// an operator who does not want success noise can untick it per channel. Defaulting it
// off would recreate the silent no-op it exists to fix.
const defaultChannelEvents = "vault.rotation_succeeded,vault.rotation_partial,vault.rotation_failed,vault.secret_expiring"

type notificationChannelResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Enabled   bool   `json:"enabled"`
	Events    string `json:"events"`
	CreatedAt string `json:"created_at"`
}

// List handles GET /api/admin/notification-channels. Configs are never
// returned (they can hold webhook secrets).
func (h *NotificationChannelsHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.queries.ListNotificationChannels(r.Context())
	if err != nil {
		logError(r, "notifications.list: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	channels := make([]notificationChannelResponse, 0, len(rows))
	for _, row := range rows {
		channels = append(channels, notificationChannelResponse{
			ID:        row.ID,
			Name:      row.Name,
			Type:      row.Type,
			Enabled:   nullInt64Is1(row.Enabled),
			Events:    row.Events,
			CreatedAt: nullTimeRFC3339(row.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, channels)
}

type createChannelRequest struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
	Events []string        `json:"events"`
}

// Create handles POST /api/admin/notification-channels. The config is
// validated per type and encrypted at rest with the vault key.
func (h *NotificationChannelsHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeValidationError(w, r, "name is required")
		return
	}
	if !validChannelTypes[req.Type] {
		writeValidationError(w, r, "type must be one of: webhook, slog")
		return
	}

	configJSON := "{}"
	if len(req.Config) > 0 {
		configJSON = string(req.Config)
	}
	if req.Type == "webhook" {
		var cfg alerts.WebhookConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			writeValidationError(w, r, "invalid webhook config")
			return
		}
		parsed, err := url.Parse(cfg.URL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			writeValidationError(w, r, "webhook config requires a valid http(s) url")
			return
		}
	}

	events := defaultChannelEvents
	if len(req.Events) > 0 {
		for _, e := range req.Events {
			if !validChannelEvents[e] {
				writeValidationError(w, r, fmt.Sprintf("unknown event type %q", e))
				return
			}
		}
		events = strings.Join(req.Events, ",")
	}

	// Encrypt the config at rest (it can carry webhook signing secrets).
	ciphertext, nonce, err := h.encrypter.EncryptValue([]byte(configJSON))
	if err != nil {
		logError(r, "notifications.create: config encryption failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	id, err := h.queries.CreateNotificationChannel(r.Context(), db.CreateNotificationChannelParams{
		Name:              req.Name,
		Type:              req.Type,
		Enabled:           sql.NullInt64{Int64: 1, Valid: true},
		Config:            base64.StdEncoding.EncodeToString(ciphertext),
		ConfigNonce:       nonce,
		EncryptionVersion: sql.NullInt64{Int64: 2, Valid: true},
		Events:            events,
	})
	if err != nil {
		logError(r, "notifications.create: insert failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	LogActivityFromRequest(h.queries, r, "settings.notification_channel_created",
		fmt.Sprintf("Notification channel %s (%s) created", req.Name, req.Type))

	writeJSON(w, http.StatusCreated, notificationChannelResponse{
		ID: id, Name: req.Name, Type: req.Type, Enabled: true, Events: events,
	})
}

type updateChannelRequest struct {
	Enabled *bool `json:"enabled"`
}

// Update handles PATCH /api/admin/notification-channels/{id} (enable/disable).
func (h *NotificationChannelsHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req updateChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, r, "invalid request body")
		return
	}
	if req.Enabled == nil {
		writeBadRequest(w, r, "enabled is required")
		return
	}

	enabled := int64(0)
	if *req.Enabled {
		enabled = 1
	}
	result, err := h.queries.UpdateNotificationChannelEnabled(r.Context(), db.UpdateNotificationChannelEnabledParams{
		Enabled: sql.NullInt64{Int64: enabled, Valid: true},
		ID:      id,
	})
	if err != nil {
		logError(r, "notifications.update: update failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		writeNotFound(w, r, "channel not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"enabled": *req.Enabled})
}

// Delete handles DELETE /api/admin/notification-channels/{id}.
func (h *NotificationChannelsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	result, err := h.queries.DeleteNotificationChannel(r.Context(), id)
	if err != nil {
		logError(r, "notifications.delete: delete failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		writeNotFound(w, r, "channel not found")
		return
	}

	LogActivityFromRequest(h.queries, r, "settings.notification_channel_deleted",
		fmt.Sprintf("Notification channel %s deleted", id))

	w.WriteHeader(http.StatusNoContent)
}

// Test handles POST /api/admin/notification-channels/{id}/test. Sends a test
// notification through the real delivery path and returns the actual result.
func (h *NotificationChannelsHandler) Test(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	row, err := h.queries.GetNotificationChannel(r.Context(), id)
	if err == sql.ErrNoRows {
		writeNotFound(w, r, "channel not found")
		return
	}
	if err != nil {
		logError(r, "notifications.test: query failed", "error", err)
		writeInternalError(w, r, "internal server error")
		return
	}

	if err := h.dispatcher.DispatchTest(row); err != nil {
		logError(r, "notifications.test: send failed", "channel", row.Name, "error", err)
		writeBadRequest(w, r, "test notification failed; check the server logs for detail")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "test notification sent"})
}
