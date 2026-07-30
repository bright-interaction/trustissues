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
} from './types';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

// Optional API key for programmatic access (e.g. the vault page talking to the
// backend on behalf of an integration). Memory-only, never persisted.
let apiKey: string | null = null;

export function setApiKey(key: string | null) {
  apiKey = key;
}

// Core fetch helper. Auth is a server-set HttpOnly session cookie, so every
// request carries credentials; there is no bearer token in the client.
export async function request<T>(
  path: string,
  opts?: RequestInit & { skipAuthRedirect?: boolean }
): Promise<T> {
  const { skipAuthRedirect, ...fetchOpts } = opts || {};
  void skipAuthRedirect;
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
    throw new ApiError('Unauthorized', 401);
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(body.error || res.statusText, res.status);
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
    updateSessionDuration: (data: { duration_hours: number }) =>
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
