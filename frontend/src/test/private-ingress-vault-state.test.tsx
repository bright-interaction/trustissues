import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { Collection, IngressHealth } from '@/lib/types';
import type { VaultEntry } from '@/lib/vault-types';
import {
  ApiError,
  PRIVATE_INGRESS_REQUIRED_CODE,
  PRIVATE_INGRESS_REQUIRED_MESSAGE,
} from '@/lib/api';

vi.mock('@/components/Layout', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 'u1', email: 'operator@example.com', name: 'Operator', role: 'user' },
    isLoading: false,
    isAdmin: false,
    isVaultOnly: false,
    setupRequired: false,
    login: vi.fn(),
    logout: vi.fn(),
    refreshUser: vi.fn(),
  }),
}));

const listMock = vi.fn();
const unlockMock = vi.fn();

vi.mock('@/lib/vault-types', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/vault-types')>();
  return {
    ...actual,
    vaultApi: {
      ...actual.vaultApi,
      list: () => listMock(),
      unlock: (password: string) => unlockMock(password),
    },
  };
});

const healthMock = vi.fn();
const collectionsListMock = vi.fn();
const collectionGetMock = vi.fn();
const membersMock = vi.fn();
const pendingInvitesMock = vi.fn();
const requestMock = vi.fn();

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return {
    ...actual,
    request: (path: string) => requestMock(path),
    api: {
      ...actual.api,
      system: { health: () => healthMock() },
      collections: {
        ...actual.api.collections,
        list: () => collectionsListMock(),
        get: (id: string) => collectionGetMock(id),
        listMembers: (id: string) => membersMock(id),
        listPendingInvites: () => pendingInvitesMock(),
      },
    },
  };
});

import Vault from '@/pages/Vault';

const PLAINTEXT = 'private-plaintext-that-must-be-sealed';

function entry(value = ''): VaultEntry {
  return {
    id: 'entry-1',
    name: 'Internal production credential',
    url: '',
    alias_url: '',
    username: 'operator',
    value,
    category: 'password',
    notes: '',
    rotation_interval_days: null,
    expires_at: null,
    last_rotated_at: null,
    rotation_status: 'fresh',
    collection_id: 'collection-1',
    created_at: '',
    updated_at: '',
  };
}

function collection(
  private_access_policy: Collection['private_access_policy']
): Collection {
  return {
    id: 'collection-1',
    name: 'Internal',
    description: '',
    private_access_policy,
    role: 'manager',
    member_count: 1,
    entry_count: 1,
    created_at: null,
    updated_at: null,
  };
}

function health(ingress: 'public' | 'private'): IngressHealth {
  return {
    status: 'ok',
    version: 'test',
    ingress,
    base_url: `https://vault-${ingress}.example.test`,
    private_ingress_enabled: true,
  };
}

function renderVault() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Vault />
      </MemoryRouter>
    </QueryClientProvider>
  );
  return queryClient;
}

async function unlockVault(user: ReturnType<typeof userEvent.setup>) {
  const input = await screen.findByPlaceholderText('Enter your password');
  await user.type(input, 'account-password');
  await user.click(screen.getByRole('button', { name: 'Unlock' }));
  await screen.findByText('Vault unlocked');
}

function mutationCacheText(queryClient: QueryClient): string {
  return JSON.stringify(
    queryClient.getMutationCache().getAll().map((mutation) => mutation.state)
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  listMock.mockResolvedValue([entry()]);
  unlockMock.mockResolvedValue([entry(PLAINTEXT)]);
  pendingInvitesMock.mockResolvedValue([]);
  membersMock.mockResolvedValue([]);
  requestMock.mockImplementation((path: string) => {
    if (path === '/settings/vault-policy') {
      return Promise.resolve({ auto_lock_max_minutes: 15 });
    }
    return Promise.reject(new Error(`unexpected request(${path})`));
  });
});

describe('unlocked private-access state is fail-closed', () => {
  it('seals plaintext and the mutation cache if a private page is re-routed to public ingress', async () => {
    const user = userEvent.setup();
    collectionsListMock.mockResolvedValue([collection('sensitive_private')]);
    collectionGetMock.mockResolvedValue(collection('sensitive_private'));
    healthMock.mockResolvedValue(health('private'));
    const queryClient = renderVault();

    await screen.findByText('Private URL');
    await unlockVault(user);
    expect(mutationCacheText(queryClient)).toContain(PLAINTEXT);

    healthMock.mockResolvedValue(health('public'));
    await queryClient.invalidateQueries({ queryKey: ['ingress', 'health'] });

    await screen.findByText('Vault is locked');
    expect(mutationCacheText(queryClient)).not.toContain(PLAINTEXT);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  });

  it('post-verifies unlock even when an already-newer metadata cache keeps the same omitted result', async () => {
    const user = userEvent.setup();
    // Models the documented admission race: metadata observes the promotion
    // first and omits the row, while an unlock transaction admitted just before
    // the promotion finishes afterward with plaintext.
    listMock.mockResolvedValue([]);
    collectionsListMock.mockResolvedValue([collection('sensitive_private')]);
    healthMock.mockResolvedValue(health('private'));
    const queryClient = renderVault();

    await screen.findByText('Private URL');
    const input = screen.getByPlaceholderText('Enter your password');
    await user.type(input, 'account-password');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));

    await waitFor(() => expect(listMock.mock.calls.length).toBeGreaterThanOrEqual(2));
    await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    expect(screen.getByText('Vault is locked')).toBeInTheDocument();
    expect(mutationCacheText(queryClient)).not.toContain(PLAINTEXT);
  });

  it('seals plaintext when another tab promotes its collection to private policy', async () => {
    const user = userEvent.setup();
    collectionsListMock.mockResolvedValue([collection('standard')]);
    collectionGetMock.mockResolvedValue(collection('standard'));
    healthMock.mockResolvedValue(health('public'));
    const queryClient = renderVault();

    await screen.findByText('Public URL');
    await unlockVault(user);
    expect(mutationCacheText(queryClient)).toContain(PLAINTEXT);

    collectionsListMock.mockResolvedValue([collection('sensitive_private')]);
    await queryClient.invalidateQueries({ queryKey: ['collections'] });

    await screen.findByText('Vault is locked');
    expect(mutationCacheText(queryClient)).not.toContain(PLAINTEXT);
  });
});

describe('protected collection read failures are never rendered as emptiness', () => {
  it('shows a private-ingress refusal instead of claiming a known collection has no members', async () => {
    const user = userEvent.setup();
    const protectedCollection = collection('sensitive_private');
    collectionsListMock.mockResolvedValue([protectedCollection]);
    collectionGetMock.mockResolvedValue(protectedCollection);
    membersMock.mockRejectedValue(
      new ApiError(PRIVATE_INGRESS_REQUIRED_MESSAGE, 403, {
        error: 'private ingress required',
        code: PRIVATE_INGRESS_REQUIRED_CODE,
      })
    );
    healthMock.mockResolvedValue(health('public'));
    renderVault();

    await screen.findByText('Public URL');
    await user.click(screen.getByTitle('Your role: manager'));
    await user.click(screen.getByRole('button', { name: 'Manage' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /requires the private TrustIssues URL/i
    );
    expect(screen.queryByText('No members yet.')).not.toBeInTheDocument();
    expect(screen.getByLabelText(/invite a member by email/i)).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Save details' })).toBeDisabled();
  });

  it('treats a fully-private 404 as unavailable, never as an empty member list or deletion success', async () => {
    const user = userEvent.setup();
    const formerlyVisible = collection('sensitive_private');
    collectionsListMock.mockResolvedValue([formerlyVisible]);
    collectionGetMock.mockResolvedValue(formerlyVisible);
    membersMock.mockRejectedValue(new ApiError('collection not found', 404));
    healthMock.mockResolvedValue(health('public'));
    renderVault();

    await screen.findByText('Public URL');
    await user.click(screen.getByTitle('Your role: manager'));
    await user.click(screen.getByRole('button', { name: 'Manage' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /may now be private-only, your access may have changed, or it may have been removed/i
    );
    expect(screen.queryByText('No members yet.')).not.toBeInTheDocument();
    expect(screen.queryByText(/Collection deleted/i)).not.toBeInTheDocument();
  });

  it('reports a failed collection list and disables management instead of silently showing none', async () => {
    collectionsListMock.mockRejectedValue(new ApiError('server unavailable', 503));
    healthMock.mockResolvedValue(health('public'));
    renderVault();

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/Collections could not be loaded/i);
    expect(alert).toHaveTextContent(/Nothing is being reported as empty or deleted/i);
    expect(screen.getByRole('button', { name: 'New collection' })).toBeDisabled();
  });
});
