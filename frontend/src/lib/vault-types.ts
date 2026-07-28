// Vault module types + API wrappers, owned by the vault module.
// Platform types live in src/lib/types.ts; per FRONTEND-CONTRACT.md the vault
// endpoint wrappers are defined here with request<T>() instead of editing
// api.ts. If frontend-platform later adds an api.vault namespace, fold these in.

import { request } from './api';

// A free-form label/value pair stored alongside a vault entry. `secret` is a
// UI masking hint only; the whole set is encrypted at rest regardless. Present
// on the create response and on unlocked (revealed) entries, absent on the
// plain locked list.
export interface CustomField {
  label: string;
  value: string;
  secret: boolean;
}

export interface VaultEntry {
  id: string;
  name: string;
  url: string;
  alias_url: string;
  username: string;
  value?: string;
  category: string;
  notes: string;
  rotation_interval_days: number | null;
  expires_at: string | null;
  last_rotated_at: string;
  rotation_status: 'fresh' | 'due_soon' | 'overdue' | 'expired';
  provider?: string;
  provider_meta?: string;
  auto_rotate?: boolean;
  last_rotation_error?: string;
  // Which shared collection the entry lives in, or null for a personal entry.
  collection_id: string | null;
  // Arbitrary label/value pairs. Present on the create response and on unlocked
  // entries; absent or empty on the plain locked list.
  custom_fields?: CustomField[];
  // Capability ceiling, returned so the edit form can show what is set. An empty
  // or absent list means no agent token can be minted for this secret at all.
  destination_patterns?: string[];
  created_at: string;
  updated_at: string;
}

// RotationTarget mirrors the Go handlers.RotationTarget struct: where a
// rotated secret is delivered. Trustissues keeps three target types:
// webhook (HMAC-signed POST), forgejo_secret (update a CI secret), and
// notify (alert channels only, no delivery). The dockyard control-plane
// types (env_var, file_write, reload_endpoint) are cut.
export interface RotationTarget {
  // Stamped server-side with the user who saved the target; the rotation
  // engine resolves an auth_token reference as THAT identity.
  configured_by?: string;
  type: 'webhook' | 'forgejo_secret' | 'notify';
  label?: string;
  // webhook
  webhook_url?: string;
  webhook_secret?: string;
  // forgejo_secret
  instance?: string;
  repo?: string;
  secret_name?: string;
  auth_token?: string; // vault entry NAME holding the Forgejo token
}

export interface ImportEntry {
  name: string;
  url: string;
  username: string;
  value: string;
  category?: string;
  notes?: string;
  skip?: boolean; // for conflict resolution
}

export interface VaultImportPreview {
  format: string;
  entries: ImportEntry[];
  conflicts: string[];
  total: number;
}

export interface ServiceIdentity {
  id: string;
  name: string;
  description: string;
  allowed_secrets: string[];
  key_prefix: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

// Returned only by the mint endpoint: the plaintext key is shown ONCE
// and is unrecoverable afterward.
export interface ServiceIdentityWithKey extends ServiceIdentity {
  key: string;
}

export interface ServiceIdentityAuditEntry {
  id: string;
  event: string;
  service_name: string;
  secret_names: string[];
  error?: string;
  remote_ip?: string;
  occurred_at: string;
}

export interface CreateServiceIdentityRequest {
  name: string;
  description?: string;
  allowed_secrets: string[];
  expires_in_days?: number;
}

// Query keys for service identities. queryKeys in src/lib/query-keys.ts is
// platform-owned and only reserves the vault.* keys, so the identity keys
// live here until the platform adopts them.
export const serviceIdentityKeys = {
  all: ['service-identities'] as const,
  list: () => ['service-identities', 'list'] as const,
  audit: (id: string) => ['service-identities', 'audit', id] as const,
};

export const vaultApi = {
  list: () => request<VaultEntry[]>('/vault'),
  create: (data: {
    name: string;
    value: string;
    url?: string;
    alias_url?: string;
    username?: string;
    category?: string;
    notes?: string;
    rotation_interval_days?: number;
    expires_at?: string;
    // Optional destination collection. Requires editor/manager on it; omit or
    // null for a personal entry.
    collection_id?: string | null;
    // Optional arbitrary label/value pairs, encrypted at rest with the entry.
    custom_fields?: CustomField[];
  }) =>
    request<VaultEntry>('/vault', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  update: (
    id: string,
    data: {
      name?: string;
      value?: string;
      url?: string;
      alias_url?: string;
      username?: string;
      category?: string;
      notes?: string;
      rotation_interval_days?: number | null;
      expires_at?: string | null;
      // Sending the array REPLACES the whole set; omit to leave it unchanged;
      // send [] to clear all.
      custom_fields?: CustomField[];
      // The capability ceiling: hosts an agent token minted for this secret may
      // reach ("api.example.com/v1/*"). Omit to leave unchanged; [] clears it,
      // which DISABLES minting rather than widening it. The server rejects host
      // wildcards, private addresses and pasted URLs.
      destination_patterns?: string[];
    }
  ) =>
    request<VaultEntry>(`/vault/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  delete: (id: string) => request<void>(`/vault/${id}`, { method: 'DELETE' }),
  unlock: (password: string) =>
    request<VaultEntry[]>('/vault/unlock', {
      method: 'POST',
      body: JSON.stringify({ password }),
    }),
  rotate: (id: string, password: string) =>
    request<VaultEntry & { value: string }>(`/vault/${id}/rotate`, {
      method: 'POST',
      body: JSON.stringify({ password }),
    }),
  // Move an entry into a collection (editor/manager on the destination) or back
  // to personal (pass null). Requires write access to the entry itself.
  moveToCollection: (id: string, collectionId: string | null) =>
    request<void>(`/vault/${id}/collection`, {
      method: 'PUT',
      body: JSON.stringify({ collection_id: collectionId }),
    }),
  // Rotation delivery targets (where a rotated secret is pushed).
  getTargets: (id: string) => request<RotationTarget[]>(`/vault/${id}/targets`),
  updateTargets: (id: string, targets: RotationTarget[]) =>
    request<RotationTarget[]>(`/vault/${id}/targets`, {
      method: 'PUT',
      body: JSON.stringify(targets),
    }),
  // Auto-rotation schedule: interval (0/30/45/60/90/180/365) + enable flag.
  updateSchedule: (
    id: string,
    data: { rotation_interval_days: number; auto_rotate: boolean }
  ) =>
    request<void>(`/vault/${id}/schedule`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  // Vault import endpoints
  importPreview: (file: File, format: string) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('format', format);

    return request<VaultImportPreview>('/vault/import/preview', {
      method: 'POST',
      body: formData,
    });
  },
  importConfirm: (entries: ImportEntry[]) =>
    request<{ imported: number; skipped?: { name: string; reason: string }[] }>('/vault/import/confirm', {
      method: 'POST',
      body: JSON.stringify({ entries }),
    }),
};

// Service identities: machine credentials that fetch a scoped subset of
// vault secrets at boot via /service-identities/me/secrets. Admin only.
export const serviceIdentitiesApi = {
  list: () => request<ServiceIdentity[]>('/service-identities'),
  create: (data: CreateServiceIdentityRequest) =>
    request<ServiceIdentityWithKey>('/service-identities', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  revoke: (id: string) =>
    request<void>(`/service-identities/${id}/revoke`, { method: 'POST' }),
  delete: (id: string) =>
    request<void>(`/service-identities/${id}`, { method: 'DELETE' }),
  audit: (id: string, limit = 100) =>
    request<ServiceIdentityAuditEntry[]>(
      `/service-identities/${id}/audit?limit=${limit}`
    ),
};
