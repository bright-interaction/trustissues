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
export interface CollectionMember {
  user_id: string;
  email: string;
  name: string;
  role: CollectionRole;
  added_at: string | null;
}
