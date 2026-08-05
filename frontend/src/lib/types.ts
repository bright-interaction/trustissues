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
//
// A PENDING row carries no `user_id` and no `name`, and carries `email` only for
// a manager (who typed the address). The server withholds them because a pending
// seat used to appear only when the address matched an account, which turned
// this endpoint into a directory of every user on the instance for anyone who
// created a collection. Render pending rows from `email` alone, and fall back to
// a placeholder when it is blank.
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

// One vault entry that migration 00034 refused to stamp with a secret owner.
//
// The migration split vault_entries.user_id into a CUSTODIAN (namespace,
// listing, adoption) and an OWNER (the only principal the secret exit asks
// about), and it would not copy user_id into the owner column wherever the
// database could not prove the custodian is the principal who deposited the
// plaintext. An empty owner denies, so these entries still open, reveal and
// rotate, and refuse NEW delivery destinations until an admin claims them.
export interface UnownedEntry {
  id: string;
  name: string;
  custodian_user_id: string;
  custodian_email: string;
  collection_id: string;
  collection_name: string;
  // True when the append-only audit trail actually records this entry being
  // renamed and adopted by a collection manager. False proves nothing: the
  // audit row only exists for adoptions performed from 2026-08-02 onward.
  adoption_recorded: boolean;
  created_at: string;
  updated_at: string;
  why: string;
  // Set only for the second class on this page: an entry that HAS a recorded
  // owner who may no longer direct it. Empty for the rows the upgrade itself
  // withheld.
  recorded_owner_user_id: string;
  recorded_owner_email: string;
  // Which of the ways to lose manage happened, when the server can tell. The
  // page used to assert one cause for all of them ("removed from the
  // collection"), which sent operators to ask a collection manager about a
  // removal that had not happened. Empty for the withheld class.
  cause: string;
  // The action that puts the row back WITHOUT moving ownership, when one
  // exists. It is the first thing to try: taking ownership is the heavier of
  // the two.
  remedy: string;
  // Whether `remedy` undoes the cause through an ordinary product route. The
  // difference between "somebody's account is gone" and "somebody's collection
  // role changed for an afternoon", which must not be presented as the same
  // situation.
  reversible: boolean;
}

export interface OwnershipReport {
  entries: UnownedEntry[];
  total: number;
}

// What a claim took OUT of the row on its way in.
//
// The destinations recorded on an unowned entry were chosen by whoever held it
// before the migration withheld its owner, and claiming ownership is what would
// otherwise bring them back to life under the new owner's authority. So the
// claim withdraws them and hands them back here. The admin re-enters the ones
// they actually want, through the ordinary edit, with themselves as the
// authority behind the write.
export interface WithdrawnEvidence {
  entry_id: string;
  secret_owner_user_id: string;
  cleared_destination_patterns: string[] | null;
  cleared_provider_meta: Record<string, string> | null;
  why: string;
}

// What undoing a claim put back.
//
// A claim is reachable whenever the recorded owner cannot direct the entry, and
// almost every way to get there is a reversible call a collection manager can
// make without touching the entry at all. Without an undo, the helpful admin
// action on this page is what makes the reversible thing permanent.
//
// The destinations the claim withdrew are NOT put back automatically: they come
// back here so the restored owner can re-enter the ones they want through an
// ordinary save, which goes through the same gate as any other write with a
// live authority behind it.
export interface RestoredOwnership {
  entry_id: string;
  secret_owner_user_id: string;
  previous_custodian_user_id?: string;
  withdrawn_not_restored?: {
    destination_patterns: string[] | null;
    provider_meta: Record<string, string> | null;
  };
  why: string;
}
