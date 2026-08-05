import type {
  AuthResponse,
  AuthStatus,
  User,
  ManagedUser,
  ActivityListResponse,
  ActivityParams,
  LoginAttempt,
  TOTPSetupResponse,
  TOTPVerifyResponse,
  Invitation,
  SMTPConfig,
  SessionDurationConfig,
  AIConfig,
  VaultPolicy,
  NotificationChannel,
  NotificationEvent,
  Role,
  ApiKey,
  ApiKeyCreated,
  Collection,
  CollectionMember,
  CollectionRole,
  CollectionInviteResult,
  PendingInvite,
  OwnershipReport,
  RestoredOwnership,
  WithdrawnEvidence,
  VaultKeyStatus,
} from './types';

export class ApiError extends Error {
  status: number;
  // body is the decoded error response, when there was one.
  //
  // Some failures carry a structured payload that IS the useful part of the
  // answer. The re-encrypt sweep is the first: a 409 means it refused and wrote
  // nothing, and the body names every row no configured key opens. Reducing
  // that to `message` and dropping the rest would leave the operator with
  // "sweep refused" and no way to find out what refused it.
  body?: unknown;
  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
    this.name = 'ApiError';
  }
}

// Optional API key for programmatic access (e.g. the vault page talking to the
// backend on behalf of an integration). Memory-only, never persisted.
let apiKey: string | null = null;

export function setApiKey(key: string | null) {
  apiKey = key;
}

// onUnauthorized is invoked once per 401 so the app can drop its session state.
// AuthProvider sets it at mount. Kept as a plain callback so this module stays
// free of React and router imports, and so a caller that legitimately expects a
// 401 (the /auth/me probe at startup) can opt out with skipAuthRedirect.
let onUnauthorized: (() => void) | undefined;

export function setUnauthorizedHandler(fn: (() => void) | undefined): void {
  onUnauthorized = fn;
}

// Core fetch helper. Auth is a server-set HttpOnly session cookie, so every
// request carries credentials; there is no bearer token in the client.
export async function request<T>(
  path: string,
  opts?: RequestInit & { skipAuthRedirect?: boolean }
): Promise<T> {
  const { skipAuthRedirect, ...fetchOpts } = opts || {};
  const headers: Record<string, string> = {
    ...(fetchOpts?.headers as Record<string, string>),
  };

  // Only set Content-Type for non-FormData bodies (FormData needs the browser
  // to auto-set the multipart boundary)
  if (!(fetchOpts?.body instanceof FormData)) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }

  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }

  const res = await fetch(`/api${path}`, {
    ...fetchOpts,
    credentials: 'same-origin',
    headers,
  });

  if (res.status === 401) {
    // A dead session must return the app to a logged-out state.
    //
    // skipAuthRedirect was destructured and then thrown away with
    // `void skipAuthRedirect`, so the redirect it names did not exist, and no
    // file anywhere tested `status === 401`: ApiError was only ever read for
    // .message. So an expired or revoked session surfaced as a red toast on a
    // still-rendered page showing cached data, and navigating to /login sent
    // the stale client straight back in because AuthProvider only calls
    // /auth/me once at mount.
    //
    // The callback is registered by AuthProvider rather than imported, so this
    // module keeps no dependency on React or the router.
    if (!skipAuthRedirect) {
      onUnauthorized?.();
    }
    throw new ApiError('Unauthorized', 401);
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(body.error || res.statusText, res.status, body);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json();
}

export const api = {
  auth: {
    status: () =>
      request<AuthStatus>('/auth/status', { skipAuthRedirect: true }),
    login: (email: string, password: string, totpCode?: string) =>
      request<AuthResponse>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email,
          password,
          ...(totpCode ? { totp_code: totpCode } : {}),
        }),
      }),
    logout: () => request<void>('/auth/logout', { method: 'POST' }),
    // First-run admin creation; only works while the users table is empty.
    register: (email: string, password: string, name: string) =>
      request<AuthResponse>('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email, password, name }),
      }),
    redeemInvitation: (code: string, password: string) =>
      request<{ user: { id: string; email: string; name: string; role: Role } }>(
        '/invitations/redeem',
        {
          method: 'POST',
          body: JSON.stringify({ code, password }),
          skipAuthRedirect: true,
        }
      ),
    me: () => request<User>('/auth/me', { skipAuthRedirect: true }),
    changePassword: (currentPassword: string, newPassword: string) =>
      request<{ message: string }>('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      }),
    updateProfile: (data: { name?: string }) =>
      request<User>('/auth/me', {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    sessions: () => request<LoginAttempt[]>('/auth/sessions'),
    totpSetup: () =>
      request<TOTPSetupResponse>('/auth/totp/setup', { method: 'POST' }),
    // The password is required to ENABLE 2FA, not just a session. Turning it on is
    // irreversible by the owner (login then needs a code, disable needs a code, the
    // recovery codes go to whoever enrolled, and no admin can reset it), so a stolen
    // session alone must not be able to do it.
    totpVerify: (code: string, password: string) =>
      request<TOTPVerifyResponse>('/auth/totp/verify', {
        method: 'POST',
        body: JSON.stringify({ code, password }),
      }),
    totpDisable: (password: string, code: string) =>
      request<{ message: string }>('/auth/totp/disable', {
        method: 'POST',
        body: JSON.stringify({ password, code }),
      }),
  },

  activity: {
    list: (params?: ActivityParams) => {
      const searchParams = new URLSearchParams();
      if (params?.user_id) searchParams.set('user_id', params.user_id);
      if (params?.action) searchParams.set('action', params.action);
      if (params?.limit) searchParams.set('limit', String(params.limit));
      if (params?.offset != null)
        searchParams.set('offset', String(params.offset));
      const qs = searchParams.toString();
      return request<ActivityListResponse>(`/activity${qs ? `?${qs}` : ''}`);
    },
  },

  admin: {
    listUsers: () => request<ManagedUser[]>('/admin/users'),
    createUser: (data: {
      email: string;
      password: string;
      name: string;
      role?: Role;
    }) =>
      request<ManagedUser>('/admin/users', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    updateUser: (
      id: string,
      data: { role?: Role; disabled?: boolean; name?: string }
    ) =>
      request<ManagedUser>(`/admin/users/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    deleteUser: (id: string) =>
      request<void>(`/admin/users/${id}`, { method: 'DELETE' }),
    resetPassword: (id: string, password: string) =>
      request<void>(`/admin/users/${id}/reset-password`, {
        method: 'POST',
        body: JSON.stringify({ password }),
      }),
    listInvitations: () => request<Invitation[]>('/admin/invitations'),
    createInvitation: (data: {
      email: string;
      name: string;
      role: Role;
      send_email?: boolean;
    }) =>
      request<Invitation>('/admin/invitations', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    deleteInvitation: (id: string) =>
      request<void>(`/admin/invitations/${id}`, { method: 'DELETE' }),
    resendInvitation: (id: string) =>
      request<void>(`/admin/invitations/${id}/resend`, { method: 'POST' }),

    listNotificationChannels: () =>
      request<NotificationChannel[]>('/admin/notification-channels'),
    // `events` goes out as an array even though the list response returns a
    // comma-separated string; that asymmetry is in the server contract.
    // `config` holds the webhook url + optional signing secret and is encrypted
    // at rest, so it is write-only: no response ever returns it.
    createNotificationChannel: (data: {
      name: string;
      type: 'webhook' | 'slog';
      config?: { url?: string; secret?: string };
      events?: NotificationEvent[];
    }) =>
      request<NotificationChannel>('/admin/notification-channels', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    setNotificationChannelEnabled: (id: string, enabled: boolean) =>
      request<{ enabled: boolean }>(`/admin/notification-channels/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled }),
      }),
    deleteNotificationChannel: (id: string) =>
      request<void>(`/admin/notification-channels/${id}`, { method: 'DELETE' }),
    testNotificationChannel: (id: string) =>
      request<void>(`/admin/notification-channels/${id}/test`, {
        method: 'POST',
      }),

    // Migration 00034 split vault_entries.user_id into a custodian and an
    // owner, and refused to guess an owner wherever the database could not
    // prove the custodian deposited the secret. An empty owner denies, so
    // those entries cannot take a NEW delivery destination until an admin
    // claims them. This is the surface that shows what was withheld and the
    // one action that repairs it.
    listUnownedEntries: () =>
      request<OwnershipReport>('/admin/vault/ownership'),
    // Returns what the claim WITHDREW. Answering the ownership question is what
    // would otherwise re-arm destinations the previous holder chose, so the
    // claim clears them in the same transaction and reports them here.
    claimSecretOwnership: (id: string) =>
      request<WithdrawnEvidence>(`/admin/vault/${id}/ownership/claim`, {
        method: 'POST',
      }),
    // The undo. Ownership goes back to the holder the claim recorded it
    // displacing, and to nobody else: the recipient is read from that record,
    // never from this request. Refuses while that holder still cannot reach the
    // entry, because returning it then would strand the row again and spend the
    // undo.
    restoreSecretOwnership: (id: string) =>
      request<RestoredOwnership>(`/admin/vault/${id}/ownership/restore`, {
        method: 'POST',
      }),

    // Master-key rotation. The status read is safe to poll and is deliberately
    // useful even when no rotation is configured: it is how an operator finds
    // out that a naive TRUSTISSUES_VAULT_KEY change left values unreadable,
    // instead of finding out when a teammate opens an entry and sees blanks.
    getVaultKeyStatus: () => request<VaultKeyStatus>('/admin/vault-key'),
    // Runs the re-encrypt sweep. A 409 means either a sweep is already running
    // or the store holds values no configured key opens; in the second case the
    // body is a full VaultKeyStatus naming where they are, and NOTHING was
    // written, so the caller must show it rather than retrying.
    rekeyVault: () =>
      request<VaultKeyStatus>('/admin/vault-key/rekey', { method: 'POST' }),
  },

  settings: {
    getVaultPolicy: () => request<VaultPolicy>('/settings/vault-policy'),
    updateVaultPolicy: (data: VaultPolicy) =>
      request<VaultPolicy>('/settings/vault-policy', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    getSMTP: () => request<SMTPConfig>('/settings/smtp'),
    updateSMTP: (data: Partial<SMTPConfig & { password?: string }>) =>
      request<SMTPConfig>('/settings/smtp', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    testSMTP: () =>
      request<{ message: string }>('/settings/smtp/test', { method: 'POST' }),
    getSessionDuration: () =>
      request<SessionDurationConfig>('/settings/session-duration'),
    updateSessionDuration: (data: { duration_hours: number; idle_minutes?: number }) =>
      request<SessionDurationConfig>('/settings/session-duration', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
  },

  // AI + MCP settings. Reading is open to any signed-in user (they need the
  // connection URLs); updating provider keys is admin-only server-side (403).
  ai: {
    getConfig: () => request<AIConfig>('/settings/ai'),
    updateConfig: (data: {
      anthropic_entry_id?: string | null;
      openai_entry_id?: string | null;
    }) =>
      request<AIConfig>('/settings/ai', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
  },
  apiKeys: {
    list: () => request<ApiKey[]>('/api-keys'),
    create: (data: { name: string; expires_in_days?: number }) =>
      request<ApiKeyCreated>('/api-keys', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    delete: (id: string) =>
      request<void>(`/api-keys/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
  },

  // Shared-team-vault collections with per-collection RBAC. The vault entry
  // move endpoint lives on vaultApi (src/lib/vault-types.ts) beside the other
  // vault wrappers.
  collections: {
    list: () => request<Collection[]>('/collections'),
    get: (id: string) => request<Collection>(`/collections/${id}`),
    create: (data: { name: string; description: string }) =>
      request<Collection>('/collections', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    update: (id: string, data: { name: string; description: string }) =>
      request<Collection>(`/collections/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    remove: (id: string) =>
      request<void>(`/collections/${id}`, { method: 'DELETE' }),
    listMembers: (id: string) =>
      request<CollectionMember[]>(`/collections/${id}/members`),
    // Invites the address (or updates an existing member's role). The response
    // is the same whether or not the address has an account, so it must not be
    // read as "the member was added".
    addMember: (id: string, data: { email: string; role: CollectionRole }) =>
      request<CollectionInviteResult>(`/collections/${id}/members`, {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    removeMember: (id: string, userId: string) =>
      request<void>(`/collections/${id}/members/${encodeURIComponent(userId)}`, {
        method: 'DELETE',
      }),
    // Withdraws a PENDING invitation. It is addressed by email because a pending
    // seat has no user id to remove: the members list withholds it (publishing
    // it told the caller whether the address had an account) and an address with
    // no account never had one. Always 204, so it says nothing either.
    rescindInvite: (id: string, email: string) =>
      request<void>(`/collections/${id}/invitations`, {
        method: 'DELETE',
        body: JSON.stringify({ email }),
      }),
    // Invitations waiting on the current user. Empty array when there are none.
    listPendingInvites: () =>
      request<PendingInvite[]>('/collections/invitations'),
    // Accept an invitation. Until this succeeds the collection grants nothing.
    // 404 when there is no pending invitation for the caller.
    acceptInvite: (id: string) =>
      request<void>(`/collections/${id}/accept`, { method: 'POST' }),
    // Decline an invitation, and also how you LEAVE a collection you already
    // joined: the same endpoint drops your own membership either way. 409 when
    // you are the last manager, 404 when there is nothing to drop.
    declineInvite: (id: string) =>
      request<void>(`/collections/${id}/decline`, { method: 'POST' }),
  },
};
