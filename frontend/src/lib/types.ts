// Shared platform types for the Trustissues frontend.
// Vault-entry types live in src/lib/vault-types.ts (owned by the vault module).

export type Role = 'admin' | 'user' | 'vault_only';

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  totp_enabled: boolean;
  created_at: string;
  // Set by the server when the vault policy requires 2FA and this account has
  // not set it up. Login is not refused (ticking the policy would otherwise
  // lock out every user at once), so the UI nags instead.
  totp_enrollment_required?: boolean;
}

export interface ManagedUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  disabled: boolean;
  entry_count: number;
  created_at: string;
}

// Session is a cookie; the body only carries the user (or the TOTP challenge).
export interface AuthResponse {
  user?: User;
  totp_required?: boolean;
}

export interface AuthStatus {
  setup_required: boolean;
}

export interface TOTPSetupResponse {
  secret: string;
  qr_uri: string;
}

export interface TOTPVerifyResponse {
  recovery_codes: string[];
}

export interface LoginAttempt {
  id: number;
  email: string;
  ip_address: string;
  success: boolean;
  created_at: string;
}

export interface ActivityEntry {
  id: number;
  user_id: string | null;
  user_email: string | null;
  action: string;
  detail: string | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
}

export interface ActivityListResponse {
  entries: ActivityEntry[];
  total: number;
}

export interface ActivityParams {
  user_id?: string;
  action?: string;
  limit?: number;
  offset?: number;
}

export interface Invitation {
  id: string;
  code: string;
  email: string;
  name: string;
  role: Role;
  status: 'pending' | 'redeemed' | 'expired';
  expires_at: string;
  created_at: string;
}

export interface SMTPConfig {
  host: string;
  port: string;
  from: string;
  username: string;
  password_set: boolean;
  use_tls: boolean;
}

export interface SessionDurationConfig {
  duration_hours: number;
  /** How long a session survives WITHOUT USE, as opposed to duration_hours
   *  which is its absolute lifetime. Shown alongside it because the two used to
   *  be governed by one control (the vault auto-lock knob), so an operator
   *  widening that silently widened every session and could not see it. */
  idle_minutes: number;
}

// AI + MCP settings. Provider keys point at vault entries by id; Shield is
// operator-configured through an environment variable and reported read-only.
// The gateway and MCP URLs are what a client points at to connect.
export interface AIConfig {
  anthropic_configured: boolean;
  openai_configured: boolean;
  anthropic_entry_id: string;
  openai_entry_id: string;
  shield_enabled: boolean;
  shield_hint_level: string;
  gateway_base_url: string;
  mcp_url: string;
}

// Team-wide vault policy, editable by admins in Settings.
export interface VaultPolicy {
  min_password_length: number;
  require_totp: boolean;
  auto_lock_max_minutes: number;
  rotation_reminder_days: number;
}

// An API key as listed (prefix only, never the secret).
export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  // Set when the key has been cut off (password change, admin revoke). A
  // revoked key is shown, not hidden, so the owner can see it existed.
  revoked_at: string | null;
  last_used_at: string | null;
  expires_at: string | null;
  created_at: string;
}

// Returned once, at creation. `key` is the full secret and is never shown again.
export interface ApiKeyCreated {
  id: string;
  name: string;
  key: string;
  key_prefix: string;
  expires_at: string | null;
  created_at: string;
}

// Role a user holds on a shared-team-vault collection. viewer is read-only,
// editor can add/move entries, manager can also manage members and the
// collection itself.
export type CollectionRole = 'viewer' | 'editor' | 'manager';

// A shared-team-vault collection. The `role` is the CURRENT user's role on it.
// Admins get every collection with role "manager"; others only get theirs.
export interface Collection {
  id: string;
  name: string;
  description: string;
  role: CollectionRole;
  member_count?: number;
  entry_count?: number;
  created_at: string | null;
  updated_at: string | null;
}

// A member of a collection, as returned by GET /collections/{id}/members.
// Membership is consent based: a row with `pending: true` has been invited but
// has not accepted yet and holds no access to the collection's entries.
export interface CollectionMember {
  user_id: string;
  email: string;
  name: string;
  role: CollectionRole;
  added_at: string | null;
  // When the invitation was accepted, or null while it is still pending.
  accepted_at: string | null;
  // True while the invitation is unanswered (no access granted).
  pending: boolean;
}

// An invitation waiting on the CURRENT user, as returned by
// GET /collections/invitations. It grants nothing: the collection and its
// entries only reach the user's vault after POST /collections/{id}/accept.
export interface PendingInvite {
  collection_id: string;
  name: string;
  description: string;
  role: CollectionRole;
  invited_at: string | null;
  invited_by_email: string;
}

// Response from POST /collections/{id}/members. Deliberately identical whether
// or not the email matches an account, so the endpoint cannot be used to probe
// which addresses are registered. It never confirms that a member was added.
export interface CollectionInviteResult {
  status: string;
  detail: string;
}

// The events a notification channel can subscribe to. Must stay in sync with
// validChannelEvents in internal/handlers/notifications.go; the server rejects
// anything it does not recognise.
export const NOTIFICATION_EVENTS = [
  'vault.rotation_failed',
  'vault.rotation_partial',
  'vault.secret_expiring',
] as const;

export type NotificationEvent = (typeof NOTIFICATION_EVENTS)[number];

// A notification channel as returned by GET /admin/notification-channels.
//
// NOTE the asymmetry with the create request: the server returns `events` as a
// comma-separated STRING here but accepts an ARRAY on create. The config
// (webhook URL and signing secret) is encrypted at rest and deliberately never
// serialized into any response, so there is nothing to mask client-side and
// nothing to pre-fill an edit form with. That is why a channel can only be
// enabled, disabled or deleted, never edited: changing a URL means creating a
// replacement channel.
export interface NotificationChannel {
  id: string;
  name: string;
  type: 'webhook' | 'slog';
  enabled: boolean;
  events: string;
  created_at: string;
}

// Master-key rotation status, from GET /admin/vault-key.
//
// Mirrors handlers.RekeyReport. The server never sends a key, only a short
// salted fingerprint, so this type has nowhere to leak one.
export interface RekeySurface {
  table: string;
  column: string;
  setting_key?: string;
  family: string;
  why: string;
  scanned: number;
  on_current: number;
  on_previous: number;
  plaintext: number;
  // Blind indexes only: an HMAC that matches no key on the ring. Repairable by
  // recomputing it, so unlike on_previous it needs no old key.
  stale: number;
  unreadable: number;
  converted: number;
}

// A value no configured key opens. Carries the row id, never the value.
export interface RekeyBlocker {
  table: string;
  column: string;
  setting_key?: string;
  row_id: string;
  reason: string;
}

// status is one of:
//   already_current  every keyed value opens under the current key
//   needs_rekey      at least one value is still on the previous key
//   converted        a sweep just ran and moved everything to the current key
//   blocked          at least one value opens under NEITHER configured key
export interface VaultKeyStatus {
  status: 'already_current' | 'needs_rekey' | 'converted' | 'blocked';
  previous_key_configured: boolean;
  current_key_fingerprint: string;
  previous_key_fingerprint?: string;
  surfaces: RekeySurface[];
  blockers: RekeyBlocker[];
  blockers_total: number;
  values_on_current: number;
  values_on_previous: number;
  // Stale lookup indexes. Kept separate from values_on_previous because the
  // remedy differs: the sweep recomputes these with no previous key, so a store
  // whose only problem is stale indexes must not be told to go and find an old
  // key it never lost.
  values_stale: number;
  values_unreadable: number;
  rows_converted: number;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  error?: string;
}
