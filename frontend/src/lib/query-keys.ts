export const queryKeys = {
  auth: {
    me: ['auth', 'me'] as const,
    sessions: ['auth', 'sessions'] as const,
  },
  activity: {
    all: ['activity'] as const,
    list: (params?: Record<string, unknown>) =>
      [...queryKeys.activity.all, 'list', params] as const,
  },
  capabilityLog: {
    all: ['capability-log'] as const,
    list: (params?: Record<string, unknown>) =>
      [...queryKeys.capabilityLog.all, 'list', params] as const,
  },
  admin: {
    users: () => ['admin', 'users'] as const,
    invitations: () => ['admin', 'invitations'] as const,
    notificationChannels: () => ['admin', 'notification-channels'] as const,
    unownedEntries: () => ['admin', 'vault-ownership'] as const,
    vaultKey: () => ['admin', 'vault-key'] as const,
  },
  settings: {
    all: ['settings'] as const,
    vaultPolicy: () => ['settings', 'vault-policy'] as const,
    smtp: () => ['settings', 'smtp'] as const,
    sessionDuration: () => ['settings', 'session-duration'] as const,
  },
  apiKeys: {
    all: ['api-keys'] as const,
    list: () => ['api-keys', 'list'] as const,
  },
  ai: {
    config: () => ['ai', 'config'] as const,
  },
  // Reserved for the vault module (src/pages/Vault.tsx and friends).
  vault: {
    all: ['vault'] as const,
    list: () => ['vault', 'list'] as const,
    entry: (id: string) => ['vault', 'entry', id] as const,
    targets: (id: string) => ['vault', 'targets', id] as const,
  },
  // Shared-team-vault collections and their members.
  collections: {
    all: ['collections'] as const,
    list: () => ['collections', 'list'] as const,
    detail: (id: string) => ['collections', 'detail', id] as const,
    members: (id: string) => ['collections', 'members', id] as const,
    // Invitations waiting on the current user (consent-based membership).
    pendingInvites: () => ['collections', 'pending-invites'] as const,
  },
};
