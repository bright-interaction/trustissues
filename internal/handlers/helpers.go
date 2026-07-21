package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// --- sql.NullString helpers ------------------------------------------------

// nullStringPtr converts a sql.NullString to *string (nil if not valid).
func nullStringPtr(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

// nullStringToString converts a sql.NullString to a plain string (empty if not valid).
func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// toNullString converts a string to a sql.NullString (empty string = NULL).
func toNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// ptrToStr safely dereferences a *string, returning "" if nil.
func ptrToStr(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// --- sql.NullTime helpers --------------------------------------------------

// nullTimeStr converts a sql.NullTime to a formatted string ("2006-01-02 15:04:05").
func nullTimeStr(nt sql.NullTime) string {
	if nt.Valid {
		return nt.Time.Format("2006-01-02 15:04:05")
	}
	return ""
}

// nullTimeRFC3339 converts a sql.NullTime to an RFC3339 string (empty if not valid).
func nullTimeRFC3339(nt sql.NullTime) string {
	if nt.Valid {
		return nt.Time.Format(time.RFC3339)
	}
	return ""
}

// --- sql.NullInt64 helpers -------------------------------------------------

// nullInt64Is1 reports whether a sql.NullInt64 holds the value 1 (SQLite bool).
func nullInt64Is1(ni sql.NullInt64) bool {
	return ni.Valid && ni.Int64 == 1
}

// --- JSON response helper --------------------------------------------------

// writeJSON encodes a value as JSON and writes it to the response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

// --- Structured error response helpers -------------------------------------

// APIError represents a structured error response with error code and request ID.
type APIError struct {
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Common error codes for consistent API responses.
const (
	ErrCodeBadRequest   = "BAD_REQUEST"
	ErrCodeUnauthorized = "UNAUTHORIZED"
	ErrCodeForbidden    = "FORBIDDEN"
	ErrCodeNotFound     = "NOT_FOUND"
	ErrCodeConflict     = "CONFLICT"
	ErrCodeRateLimited  = "RATE_LIMITED"
	ErrCodeInternal     = "INTERNAL_ERROR"
	ErrCodeValidation   = "VALIDATION_ERROR"
)

// getRequestID extracts the request ID from chi middleware.
func getRequestID(r *http.Request) string {
	return chimiddleware.GetReqID(r.Context())
}

// logError logs an error with request context (request ID). Use this for all
// handler error logging so client-facing errors stay generic while the server
// keeps the detail.
func logError(r *http.Request, msg string, args ...any) {
	reqID := getRequestID(r)
	allArgs := append([]any{"request_id", reqID}, args...)
	slog.Error(msg, allArgs...)
}

// mustMarshalJSON marshals v to JSON. On the rare marshal failure it logs an
// error and returns an empty JSON object so callers never get nil bytes.
func mustMarshalJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		slog.Error("mustMarshalJSON: marshal failed", "error", err)
		return []byte("{}")
	}
	return data
}

// writeError writes a structured error response with request ID.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, APIError{
		Error:     message,
		Code:      code,
		RequestID: getRequestID(r),
	})
}

func writeBadRequest(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusBadRequest, ErrCodeBadRequest, message)
}

func writeUnauthorized(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusUnauthorized, ErrCodeUnauthorized, message)
}

func writeForbidden(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusForbidden, ErrCodeForbidden, message)
}

func writeNotFound(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusNotFound, ErrCodeNotFound, message)
}

func writeConflict(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusConflict, ErrCodeConflict, message)
}

func writeInternalError(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusInternalServerError, ErrCodeInternal, message)
}

func writeValidationError(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusBadRequest, ErrCodeValidation, message)
}

func writeRateLimited(w http.ResponseWriter, r *http.Request, message string) {
	writeError(w, r, http.StatusTooManyRequests, ErrCodeRateLimited, message)
}

// --- Input validation helpers ----------------------------------------------

// ValidationError holds details about a validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error implements the error interface for ValidationError.
func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}

// ValidateEmail validates an email address using net/mail.
func ValidateEmail(email string) error {
	if email == "" {
		return nil // Empty is allowed; use ValidateRequired for mandatory fields
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return &ValidationError{Field: "email", Message: "invalid email address format"}
	}
	return nil
}

// ValidateRequired validates that a string is not empty.
func ValidateRequired(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{Field: field, Message: "is required"}
	}
	return nil
}

// ValidateStringLength validates a string's length is within bounds.
func ValidateStringLength(field, value string, minLen, maxLen int) error {
	length := utf8.RuneCountInString(value)
	if length < minLen {
		return &ValidationError{Field: field, Message: fmt.Sprintf("must be at least %d characters", minLen)}
	}
	if maxLen > 0 && length > maxLen {
		return &ValidationError{Field: field, Message: fmt.Sprintf("must be at most %d characters", maxLen)}
	}
	return nil
}

// validatePassword enforces the shared password rules: at least 12 characters
// (matching the UI floor) and at most 72 bytes (bcrypt truncates input at 72
// bytes; reject longer passwords to prevent surprise even though new hashes
// use argon2id). Use validatePasswordWithPolicy where a *db.Queries is
// available so the admin-configurable minimum applies too.
func validatePassword(password string) error {
	if len(password) < 12 {
		return &ValidationError{Field: "password", Message: "must be at least 12 characters"}
	}
	if len(password) > 72 {
		return &ValidationError{Field: "password", Message: "must be at most 72 characters"}
	}
	return nil
}

// generateID returns a 32-character hex ID for database identifiers.
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure means the system is unusable; fall back to a
		// timestamp-derived ID rather than panic in a request path.
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
