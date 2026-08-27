import type {
  AuthResponse,
  AuthStatus,
  InvitationRedemptionResponse,
  User,
  ManagedUser,
  ActivityListResponse,
  CapabilityLogResponse,
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
  CollectionPrivateAccessPolicy,
  IngressHealth,
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

// The machine-readable code the enrolment gate returns with its 403.
//
// This MUST match middleware.TOTPEnrollmentRequiredCode in
// internal/middleware/totp_enrollment.go. That constant's comment claimed "the
// frontend routes on this string, so it is part of the API contract" while
// nothing in this app read `.code` off an ApiError at all -- the contract was
// documented on one side and imaginary on the other, which is why a gated user
// could sit on /vault watching every query fail with no banner and no redirect.
export const TOTP_ENROLLMENT_REQUIRED_CODE = 'totp_enrollment_required';

// Stable code returned when an authenticated request reached the ordinary
// listener but the collection policy requires the optional private listener.
// Keep this aligned with middleware.PrivateIngressRequiredCode.
export const PRIVATE_INGRESS_REQUIRED_CODE = 'private_ingress_required';

// All existing mutation surfaces already toast ApiError.message. Translating
// the machine code once here makes reveal, export, rotation, membership, and
// collection-policy refusals actionable without each screen growing a subtly
// different interpretation of the same authorization result.
export const PRIVATE_INGRESS_REQUIRED_MESSAGE =
  'This action requires the private TrustIssues URL. Connect to your team\'s Tailscale, Headscale, or other private network and open that URL. Ask your administrator for the exact address if you do not have it. Sign-in, MFA, and permissions still apply.';

// onEnrollmentRequired is invoked when ANY request is refused by the enrolment
// gate. AuthProvider registers it, the same way it registers onUnauthorized.
//
// This is the live signal the SPA otherwise lacks. /auth/me is read once per
// page load and refetchOnWindowFocus is off, so an admin turning the policy on
// mid-session was invisible to every open tab until a manual reload: the user
// saw their pages break with no explanation. Routing on the gate's own 403 means
// the tab learns the moment it touches a gated route, instead of never.
let onEnrollmentRequired: (() => void) | undefined;

export function setEnrollmentRequiredHandler(
  fn: (() => void) | undefined
): void {
  onEnrollmentRequired = fn;
}

// The vault page registers this while mounted so a protected refusal from any
// nested surface (rotation targets, export, collection membership, etc.) can
// seal its decrypted in-memory state immediately instead of waiting for the
// next health poll. The error still reaches the caller for its normal toast.
let onPrivateIngressRequired: (() => void) | undefined;

export function setPrivateIngressRequiredHandler(
  fn: (() => void) | undefined
): void {
  onPrivateIngressRequired = fn;
}

type ApiRequestOptions = RequestInit & { skipAuthRedirect?: boolean };

// Shared authenticated fetch path. Keeping attachment downloads here matters:
// a raw fetch from an export button would otherwise skip the app-wide 401 and
// mandatory-2FA handling that protects every JSON request.
async function apiRequest(
  path: string,
  opts?: ApiRequestOptions
): Promise<Response> {
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
    const errorBody = body as { error?: string; code?: string };

    // The enrolment gate refuses every route except /api/auth while the
    // require_totp policy is on and the caller has not enrolled. Surface it as
    // a routed event rather than as one more red toast, because the user cannot
    // act on it from where they are standing.
    if (
      res.status === 403 &&
      errorBody.code === TOTP_ENROLLMENT_REQUIRED_CODE
    ) {
      onEnrollmentRequired?.();
    }
    if (
      res.status === 403 &&
      errorBody.code === PRIVATE_INGRESS_REQUIRED_CODE
    ) {
      onPrivateIngressRequired?.();
    }

    const message =
      res.status === 403 && errorBody.code === PRIVATE_INGRESS_REQUIRED_CODE
        ? PRIVATE_INGRESS_REQUIRED_MESSAGE
        : errorBody.error || res.statusText;
    throw new ApiError(message, res.status, body);
  }

  return res;
}

// Core JSON helper. Auth is a server-set HttpOnly session cookie, so every
// request carries credentials; there is no bearer token in the client.
export async function request<T>(
  path: string,
  opts?: ApiRequestOptions
): Promise<T> {
  const res = await apiRequest(path, opts);

  if (res.status === 204) return undefined as T;

  return res.json();
}

// Binary/attachment counterpart to request(). The caller receives the response
// filename header alongside the Blob so downloads do not have to invent a name
// when the server supplied one.
export async function requestAttachment(
  path: string,
  opts?: ApiRequestOptions
): Promise<{ blob: Blob; contentDisposition: string | null }> {
  const res = await apiRequest(path, opts);
  return {
    blob: await res.blob(),
    contentDisposition: res.headers.get('content-disposition'),
  };
}

// /health deliberately lives outside /api and is unauthenticated. Keeping the
// path relative is security-relevant: a page loaded from the private hostname
// must verify and call that SAME origin, never a public URL compiled into the
// bundle. The response carries no secret, but no-store avoids a cached private
// stamp masking a connector/routing change.
export async function requestIngressHealth(): Promise<IngressHealth> {
  const controller = new AbortController();
  // A disconnected overlay can leave a browser fetch pending for far longer
  // than the vault's 10-second verification cadence. Bound it so a protected
  // unlocked page actually reaches the fail-closed error path promptly.
  const timeout = globalThis.setTimeout(() => controller.abort(), 5_000);
  let res: Response;
  try {
    res = await fetch('/health', {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: controller.signal,
    });
  } catch {
    throw new Error('Could not verify this TrustIssues ingress');
  } finally {
    globalThis.clearTimeout(timeout);
  }
  if (!res.ok) {
    throw new ApiError('Could not verify this TrustIssues ingress', res.status);
  }
  const health = await res.json() as IngressHealth;
  if (health.ingress !== 'public' && health.ingress !== 'private') {
    throw new Error('TrustIssues returned an invalid ingress stamp');
  }
  return health;
}

export const api = {
  system: {
    health: requestIngressHealth,
  },
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
      request<InvitationRedemptionResponse>('/invitations/redeem', {
        method: 'POST',
        body: JSON.stringify({ code, password }),
        skipAuthRedirect: true,
      }),
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

  capabilityLog: {
    list: (params?: {
      agent_id?: string;
      event?: string;
      secret_id?: string;
      limit?: number;
      offset?: number;
    }) => {
      const searchParams = new URLSearchParams();
      if (params?.agent_id) searchParams.set('agent_id', params.agent_id);
      if (params?.event) searchParams.set('event', params.event);
      if (params?.secret_id) searchParams.set('secret_id', params.secret_id);
      if (params?.limit) searchParams.set('limit', String(params.limit));
      if (params?.offset != null)
        searchParams.set('offset', String(params.offset));
      const qs = searchParams.toString();
      return request<CapabilityLogResponse>(
        `/capability-log${qs ? `?${qs}` : ''}`,
      );
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

  // AI + MCP settings. Reading is open to signed-in non-vault-only users (they
  // need the connection URLs); updating provider keys is admin-only server-side
  // (403). External/client vault_only accounts are barred from both surfaces.
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
    create: (data: {
      name: string;
      description: string;
      private_access_policy?: CollectionPrivateAccessPolicy;
    }) =>
      request<Collection>('/collections', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    update: (id: string, data: {
      name: string;
      description: string;
      private_access_policy?: CollectionPrivateAccessPolicy;
    }) =>
      request<Collection>(`/collections/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    // entryCount is the server's own count, read moments earlier via `get`.
    // The server refuses a non-empty collection unless it matches what it
    // currently counts, so this is the client proving it knew what it was
    // about to destroy; a stale value is refused rather than trusted.
    remove: (id: string, entryCount?: number) =>
      request<void>(
        `/collections/${id}${typeof entryCount === 'number' ? `?entry_count=${entryCount}` : ''}`,
        { method: 'DELETE' }
      ),
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
