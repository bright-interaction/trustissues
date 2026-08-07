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
  // Set by the server when a secret:true field was NOT released to this caller.
  // The value comes back blank in that case, so a form that dropped this flag on
  // save would write the blank over the real secret. It is carried back on every
  // save and the server refuses any array containing one.
  withheld?: boolean;
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
  // 'error' is returned whenever last_rotation_error is set, and the server
  // checks it BEFORE the age branches, so it also replaces 'overdue'. The client
  // type omitted it, which rendered an empty pill: the one state an operator
  // most needs to see was the only invisible one.
  rotation_status: 'fresh' | 'due_soon' | 'overdue' | 'expired' | 'error';
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

// ProviderInfo mirrors handlers.ProviderInfo (GET /vault/providers). It is the
// single source for what a rotation provider is called, whether it can
// auto-rotate, what provider_meta fields it needs, and what happens to the key
// it replaces. The frontend must NOT hardcode a second copy of this list: the
// per-provider meta shape (required_meta) and the revoke behavior
// (predecessor_fate) come from here so the two cannot drift.
export interface ProviderInfo {
  name: string;
  label: string;
  can_auto_rotate: boolean;
  // Kept for completeness; predecessor_fate is the field to render (see below).
  revokes_predecessor: boolean;
  // The honest, four-valued answer to "what happens to the key rotation
  // replaces". "unknown" means NOT YET VERIFIED against the vendor's API, not
  // "confirmed both keys stay live" -- render it as a question, not a claim.
  predecessor_fate: 'revokes' | 'leaves_live' | 'not_applicable' | 'unknown';
  predecessor_note?: string;
  dashboard_url: string;
  // provider_meta fields whose absence makes rotation/validation fail for this
  // provider, keyed by field name with a human-readable label as the value.
  // Empty object means the provider needs no extra fields.
  required_meta: Record<string, string>;
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
  /** Rows the parser could not turn into entries, with the reason for each. */
  skipped: Array<{ name: string; reason: string }>;
  /** Row count BEFORE those drops. `total` is the post-drop number, so the two
   *  together are what reveal that part of an export did not arrive. */
  source_rows: number;
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

// Query keys for the provider catalog. Same rationale as serviceIdentityKeys
// above: queryKeys in src/lib/query-keys.ts is platform-owned and does not
// reserve this one.
export const providerKeys = {
  all: ['vault-providers'] as const,
  list: () => ['vault-providers', 'list'] as const,
};

export const vaultApi = {
  list: () => request<VaultEntry[]>('/vault'),
  // The provider catalog: what a rotation provider is called, whether it can
  // auto-rotate, what provider_meta fields it needs, and its predecessor fate.
  // This is the ONLY source for that; see ProviderInfo's doc comment.
  listProviders: () => request<ProviderInfo[]>('/vault/providers'),
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
    // Rotation provider (see vaultApi.listProviders) and its provider_meta,
    // a JSON-encoded object of the fields that provider's Rotate/Validate
    // reads (see ProviderInfo.required_meta). Omit both to create a
    // manually-managed entry.
    provider?: string;
    provider_meta?: string;
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
      // Rotation provider + its provider_meta (JSON-encoded object). Omit
      // either to leave it unchanged; send provider: '' to detach. The server
      // requires the entry's owner or an instance admin to WIDEN where the
      // secret can be sent (a provider/provider_meta change that adds a
      // host); a narrower or same-host change is allowed for any editor. See
      // FRONTEND-CONTRACT.md and internal/handlers/egress_authority.go.
      provider?: string;
      provider_meta?: string;
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
  // Returns the list plus a version pinning the view. Send that version back on
  // save so a panel held open across an offboarding purge cannot resubmit the
  // departed member's webhook and have it re-attributed to whoever saved.
  getTargets: (id: string) =>
    request<{ targets: RotationTarget[]; version: string }>(`/vault/${id}/targets`),
  // `clear` must be set to send an EMPTY array. The server refuses a blind
  // wipe of a non-empty target list, because a failed GET used to render
  // identically to "no targets" and Save is a full replace, so an accidental []
  // deleted real targets (webhook HMAC secrets included) with a success toast.
  // Deleting the last target in the UI is a deliberate act, so the panel opts in.
  updateTargets: (id: string, targets: RotationTarget[], opts?: { clear?: boolean; version?: string }) =>
    request<RotationTarget[]>(
      `/vault/${id}/targets?${new URLSearchParams({
        ...(opts?.clear ? { clear: '1' } : {}),
        ...(opts?.version ? { version: opts.version } : {}),
      }).toString()}`,
      {
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
