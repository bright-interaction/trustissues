import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { VaultEntry } from '@/lib/vault-types';

// P1-1/P1-2/P1-3: locking the vault (auto-lock timer, the manual Lock button)
// cleared component state (vaultEntries, revealedSecrets, ...) but left the
// decrypted values and the account password reachable through TanStack
// Query's mutation cache: unlockVaultMutation.data/.variables and
// rotateSecretMutation.data/.variables outlive lockVault entirely unless
// something calls .reset() on them, and nothing did.
//
// This is a RUNTIME property. The old chokepoint test read Vault.tsx as text
// and could not see it: a mutation cache entry is not a `setX(...)` call in
// the source. So this file builds a REAL QueryClient, renders the REAL Vault
// component, drives the REAL unlock/rotate/Lock UI (real useMutation hooks,
// real onSuccess handlers, real lockVault), and asserts against the actual
// mutation-cache OBJECT afterward -- the same object React Query devtools or
// a heap snapshot would show an attacker.
//
// Proof level: this is jsdom + React Testing Library, not a real browser.
// It exercises real React state, real hooks, and the real TanStack Query
// cache object, which is exactly the surface this bug lived in. It does NOT
// exercise actual browser memory (V8 heap layout, GC timing) or a real
// network layer -- vaultApi.unlock/rotate are mocked at the module boundary,
// same as this codebase's existing component tests (see
// credential-access.test.tsx). See the report for what that does and does
// not prove.

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

const unlockMock = vi.fn();
const rotateMock = vi.fn();
const listMock = vi.fn();

vi.mock('@/lib/vault-types', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/vault-types')>();
  return {
    ...actual,
    vaultApi: {
      ...actual.vaultApi,
      list: () => listMock(),
      unlock: (password: string) => unlockMock(password),
      rotate: (id: string, password: string) => rotateMock(id, password),
    },
  };
});

const collectionsListMock = vi.fn();
const pendingInvitesMock = vi.fn();
const requestMock = vi.fn();

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return {
    ...actual,
    request: (path: string) => requestMock(path),
    api: {
      ...actual.api,
      collections: {
        ...actual.api.collections,
        list: () => collectionsListMock(),
        listPendingInvites: () => pendingInvitesMock(),
      },
    },
  };
});

import Vault from '@/pages/Vault';

const DECRYPTED_VALUE = 'S3cr3t-Plaintext-Value-42';
const ACCOUNT_PASSWORD = 'hunter2-the-real-account-password';
const ROTATED_VALUE = 'Rotated-Plaintext-Value-99';

function entry(): VaultEntry {
  return {
    id: 'e1',
    name: 'Prod DB password',
    url: '',
    alias_url: '',
    username: 'admin',
    value: DECRYPTED_VALUE,
    category: '',
    notes: '',
    rotation_interval_days: null,
    expires_at: null,
    last_rotated_at: '',
    rotation_status: 'fresh',
    collection_id: null,
    created_at: '',
    updated_at: '',
  };
}

function renderVault() {
  // Deliberately NOT setting a short gcTime for mutations: the whole point is
  // that a SUCCEEDED mutation's cache entry survives on its own (react-query
  // defaults to a 5-minute gcTime) unless lockVault's .reset() calls remove
  // it. A short gcTime would make this test pass whether or not the fix
  // exists, which is exactly the "passes with and without the fix" trap the
  // brief warns about.
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Vault />
      </MemoryRouter>
    </QueryClientProvider>
  );
  return qc;
}

function mutationSnapshot(qc: QueryClient) {
  return qc.getMutationCache()
    .getAll()
    .map((m) => ({ data: m.state.data, variables: m.state.variables }));
}

async function unlock(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByTestId('page-vault');
  const passwordInput = await screen.findByPlaceholderText('Enter your password');
  await user.type(passwordInput, ACCOUNT_PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Unlock' }));
  await screen.findByText('Prod DB password');
}

beforeEach(() => {
  unlockMock.mockReset().mockResolvedValue([entry()]);
  rotateMock.mockReset().mockResolvedValue({ ...entry(), value: ROTATED_VALUE });
  listMock.mockReset().mockResolvedValue([]);
  collectionsListMock.mockReset().mockResolvedValue([]);
  pendingInvitesMock.mockReset().mockResolvedValue([]);
  requestMock.mockReset().mockImplementation((path: string) => {
    if (path === '/settings/vault-policy') {
      return Promise.resolve({ auto_lock_max_minutes: 15 });
    }
    return Promise.reject(new Error(`unexpected request(${path}) in this test`));
  });
});

afterEach(() => vi.clearAllMocks());

describe('locking the vault clears the real mutation cache, not just component state', () => {
  it('sanity check: unlocking genuinely leaves the decrypted values and the account password in the mutation cache', async () => {
    // This has to be true BEFORE the fix is even considered, or every
    // assertion after a lock in the next test would pass vacuously.
    const user = userEvent.setup();
    const qc = renderVault();
    await unlock(user);

    const serialized = JSON.stringify(mutationSnapshot(qc));
    expect(serialized).toContain(DECRYPTED_VALUE);
    expect(serialized).toContain(ACCOUNT_PASSWORD);
  });

  it('lock drops the decrypted values and the account password from the mutation cache, the DOM, and the re-shown password field', async () => {
    const user = userEvent.setup();
    const qc = renderVault();
    await unlock(user);

    // Also exercise rotate, so a SECOND decrypted value (ROTATED_VALUE) and a
    // second copy of the account password are sitting in the cache too.
    await user.click(screen.getByTitle('Rotate secret'));
    await user.type(await screen.findByPlaceholderText('Enter your password'), ACCOUNT_PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Rotate' }));
    await screen.findByText(ROTATED_VALUE);

    // Confirm the cache is genuinely dirty before locking.
    const before = JSON.stringify(mutationSnapshot(qc));
    expect(before).toContain(DECRYPTED_VALUE);
    expect(before).toContain(ROTATED_VALUE);
    expect(before).toContain(ACCOUNT_PASSWORD);

    await user.click(screen.getByRole('button', { name: 'Lock' }));
    await screen.findByPlaceholderText('Enter your password');

    // The money assertion: the real mutation-cache object, post-lock.
    const after = JSON.stringify(mutationSnapshot(qc));
    expect(after).not.toContain(DECRYPTED_VALUE);
    expect(after).not.toContain(ROTATED_VALUE);
    expect(after).not.toContain(ACCOUNT_PASSWORD);
    for (const m of mutationSnapshot(qc)) {
      expect(m.data, 'a mutation still has cached data after lock').toBeUndefined();
      expect(m.variables, 'a mutation still has cached variables after lock').toBeUndefined();
    }

    // Component state: the re-shown password field must not be pre-filled
    // with the password typed before lock (vaultPassword was cleared).
    const reshown = screen.getByPlaceholderText('Enter your password') as HTMLInputElement;
    expect(reshown.value).toBe('');

    // Nothing plaintext survives in the rendered page either.
    expect(document.body.textContent).not.toContain(DECRYPTED_VALUE);
    expect(document.body.textContent).not.toContain(ROTATED_VALUE);
    expect(document.body.textContent).not.toContain(ACCOUNT_PASSWORD);
  });

  it('a rotate that resolves AFTER lock does not repopulate the locked UI or its own mutation cache entry', async () => {
    const user = userEvent.setup();
    const qc = renderVault();
    await unlock(user);

    // Hang the rotate request so we can lock WHILE it is in flight -- the
    // race the brief calls out explicitly (item 4).
    let releaseRotate: (() => void) | undefined;
    rotateMock.mockImplementation(
      () => new Promise((resolve) => { releaseRotate = () => resolve({ ...entry(), value: ROTATED_VALUE }); })
    );

    await user.click(screen.getByTitle('Rotate secret'));
    await user.type(await screen.findByPlaceholderText('Enter your password'), ACCOUNT_PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Rotate' }));
    await waitFor(() => expect(rotateMock).toHaveBeenCalled());

    // Lock while the rotate above is still unresolved.
    await user.click(screen.getByRole('button', { name: 'Lock' }));
    await screen.findByPlaceholderText('Enter your password');

    // The cache was already cleared at lock time, above -- confirm that
    // directly before letting the stale response land, so the assertions
    // after it cannot pass just because nothing was ever in the cache.
    expect(mutationSnapshot(qc)).toEqual([]);

    // Now let the stale rotate resolve. Its Mutation object is orphaned (no
    // longer reachable via the cache or the component's observer, see
    // lockVault's comment), so this must not cause it to reappear anywhere.
    releaseRotate!();
    await waitFor(() => expect(rotateMock).toHaveBeenCalled());
    // Give the resolved promise's microtask chain a turn to fully settle.
    await new Promise((r) => setTimeout(r, 0));

    // The locked UI must not have been silently refilled by the late response,
    // and the orphaned mutation must not have found its way back into the
    // live cache.
    expect(document.body.textContent).not.toContain(ROTATED_VALUE);
    expect(mutationSnapshot(qc)).toEqual([]);
  });
});
