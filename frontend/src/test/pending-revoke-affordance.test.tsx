import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { VaultEntry, ProviderInfo } from '@/lib/vault-types';

// pending_revoke closes the gap where a rotation minted a replacement but
// could not delete the OLD key at the provider: the server keeps that key's
// coordinates and retries them at the NEXT rotation, but an on-demand entry
// (auto_rotate off) may never rotate again for a human to click, so that
// stranded key would otherwise sit live at the provider forever with nothing
// in the UI saying so. Two surfaces close it: the unlocked RotationManager
// banner (retry the delete, or attest it was handled by hand) and the locked
// table's "Predecessor key live" chip, which is the ONLY signal a locked,
// on-demand entry has.
//
// These three tests each pin the one way the affordance could look like it
// works while lying:
//  (a) the retry endpoint returns HTTP 200 with `revoked: false` on FAILURE
//      -- not an HTTP error. Reading a 200 as success here means telling the
//      operator a live orphaned credential was deleted when it was not.
//  (b) the locked chip must be driven by pending_revoke.outstanding alone.
//      last_rotation_error is about the MOST RECENT rotation attempt and gets
//      overwritten by the next one, so gating on it would hide exactly the
//      on-demand entry this feature exists for.
//  (c) "I deleted it myself" only clears the LOCAL record, never the
//      provider, so it must not be one click: the operator has to type the
//      key id back.

const toastErrorMock = vi.fn();
const toastSuccessMock = vi.fn();
vi.mock('react-hot-toast', () => ({
  default: {
    error: (...args: unknown[]) => toastErrorMock(...args),
    success: (...args: unknown[]) => toastSuccessMock(...args),
  },
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

// Only needed for the locked-table test (Vault.tsx wraps its content in this).
vi.mock('@/components/Layout', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const listProvidersMock = vi.fn();
const getTargetsMock = vi.fn();
const retryMock = vi.fn();
const resolveMock = vi.fn();
const vaultListMock = vi.fn();
const vaultUpdateMock = vi.fn();
const vaultUnlockMock = vi.fn();

vi.mock('@/lib/vault-types', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/vault-types')>();
  return {
    ...actual,
    vaultApi: {
      ...actual.vaultApi,
      listProviders: () => listProvidersMock(),
      getTargets: (id: string) => getTargetsMock(id),
      pendingRevokeRetry: (id: string, password: string) => retryMock(id, password),
      pendingRevokeResolve: (id: string, acknowledgedKeyId: string) => resolveMock(id, acknowledgedKeyId),
      list: () => vaultListMock(),
      update: (id: string, patch: unknown) => vaultUpdateMock(id, patch),
      unlock: (password: string) => vaultUnlockMock(password),
    },
  };
});

// Only needed for the locked-table test: Vault.tsx queries vault-policy,
// collections and pending invites unconditionally on mount (not gated on
// unlock state), same fixture shape as vault-lock-seals-secrets.test.tsx.
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

import RotationManager from '@/components/RotationManager';
import Vault from '@/pages/Vault';

const PREDECESSOR_KEY_ID = 'key_old_123';

function provider(): ProviderInfo {
  return {
    name: 'stripe',
    label: 'Stripe',
    can_auto_rotate: true,
    revokes_predecessor: false,
    predecessor_fate: 'leaves_live',
    predecessor_note: '',
    dashboard_url: 'https://dashboard.stripe.com/apikeys',
    required_meta: {},
  };
}

function entry(over: Partial<VaultEntry> = {}): VaultEntry {
  return {
    id: 'e1',
    name: 'Stripe secret key',
    url: '',
    alias_url: '',
    username: '',
    category: '',
    notes: '',
    rotation_interval_days: null,
    expires_at: null,
    last_rotated_at: '',
    rotation_status: 'fresh',
    collection_id: null,
    created_at: '',
    updated_at: '',
    provider: 'stripe',
    provider_meta: '{}',
    auto_rotate: false,
    pending_revoke: { outstanding: true, predecessor_key_id: PREDECESSOR_KEY_ID },
    ...over,
  };
}

// onPendingRevokeChanged is optional so existing callers are unaffected. It is
// the prop the parent uses to keep its own copy of pending_revoke fresh, and a
// test that cares whether the component forwarded the SERVER's value (rather
// than a hardcoded null) has to observe it.
function renderRotationManager(
  e: VaultEntry,
  onPendingRevokeChanged?: (patch: { pending_revoke: VaultEntry['pending_revoke'] }) => void
) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  render(
    <QueryClientProvider client={qc}>
      <RotationManager entry={e} onPendingRevokeChanged={onPendingRevokeChanged} />
    </QueryClientProvider>
  );
  return qc;
}

beforeEach(() => {
  listProvidersMock.mockReset().mockResolvedValue([provider()]);
  getTargetsMock.mockReset().mockResolvedValue({ targets: [], version: 'v1' });
  retryMock.mockReset();
  resolveMock.mockReset();
  vaultListMock.mockReset().mockResolvedValue([]);
  vaultUpdateMock.mockReset();
  vaultUnlockMock.mockReset();
  toastErrorMock.mockReset();
  toastSuccessMock.mockReset();
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

describe('a 200 that means failure must not read as success', () => {
  it('keeps the banner up and fires an error toast when retry resolves {revoked: false}', async () => {
    const user = userEvent.setup();
    // The contract is explicit that this is the FAILURE case despite the 200.
    retryMock.mockResolvedValue({
      revoked: false,
      detail: 'Stripe still reports this key as active.',
      pending_revoke: { outstanding: true, predecessor_key_id: PREDECESSOR_KEY_ID },
    });
    renderRotationManager(entry());

    await screen.findByText('An older key at this provider is still live.');

    await user.click(screen.getByRole('button', { name: 'Retry the revoke' }));
    await user.type(await screen.findByPlaceholderText('Enter your password'), 'hunter2');
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => expect(retryMock).toHaveBeenCalledWith('e1', 'hunter2'));
    await waitFor(() => expect(toastErrorMock).toHaveBeenCalled());

    // The money assertions: no success toast, and the banner is still there.
    expect(toastSuccessMock).not.toHaveBeenCalled();
    expect(
      screen.getByText('An older key at this provider is still live.')
    ).toBeInTheDocument();
    expect(screen.getByText(PREDECESSOR_KEY_ID)).toBeInTheDocument();
  });

  it('sanity check: a genuine revoke (revoked: true) DOES clear the banner and toast success', async () => {
    // Without this, test 1 above could pass vacuously if the banner simply
    // never clears under any circumstance.
    const user = userEvent.setup();
    retryMock.mockResolvedValue({
      revoked: true,
      detail: 'Deleted at Stripe.',
      pending_revoke: null,
    });
    renderRotationManager(entry());

    await screen.findByText('An older key at this provider is still live.');
    await user.click(screen.getByRole('button', { name: 'Retry the revoke' }));
    await user.type(await screen.findByPlaceholderText('Enter your password'), 'hunter2');
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => expect(toastSuccessMock).toHaveBeenCalled());
    expect(toastErrorMock).not.toHaveBeenCalled();
    expect(
      screen.queryByText('An older key at this provider is still live.')
    ).not.toBeInTheDocument();
  });
});

describe('"I deleted it myself" only clears the local record, and refuses to do so blindly', () => {
  it('the confirm button stays disabled until the exact predecessor key id is typed back', async () => {
    const user = userEvent.setup();
    renderRotationManager(entry());

    await screen.findByText('An older key at this provider is still live.');
    await user.click(screen.getByRole('button', { name: 'I deleted it myself' }));

    const confirmButton = await screen.findByRole('button', { name: 'Confirm, clear the record' });
    expect(confirmButton).toBeDisabled();

    const input = screen.getByPlaceholderText(PREDECESSOR_KEY_ID);
    await user.type(input, 'not-the-right-key');
    expect(confirmButton).toBeDisabled();
    expect(resolveMock).not.toHaveBeenCalled();

    await user.clear(input);
    await user.type(input, PREDECESSOR_KEY_ID);
    expect(confirmButton).not.toBeDisabled();

    await user.click(confirmButton);
    await waitFor(() => expect(resolveMock).toHaveBeenCalledWith('e1', PREDECESSOR_KEY_ID));
  });

  it('keeps the banner up when the server hands back ANOTHER stranded key after the resolve', async () => {
    // An entry can carry a QUEUE of stranded predecessors: rotation N's revoke
    // of K1 failed, rotation N+1 stranded K2 as well. Acknowledging the key the
    // banner is currently showing discharges only that one, and the server
    // PROMOTES the next and returns it.
    //
    // This handler used to call applyPendingRevoke(null) unconditionally against
    // a `void`-typed response, so the banner came down and the operator was told
    // the entry was handled while an older key was still authenticating at the
    // vendor. That is the same false-assurance failure the server side of this
    // feature was fixed for, arriving one layer up.
    const user = userEvent.setup();
    const stillOutstanding = { outstanding: true, predecessor_key_id: 'K-older' };
    resolveMock.mockResolvedValue({ resolved: true, pending_revoke: stillOutstanding });
    const pendingRevokeChangedMock = vi.fn();
    renderRotationManager(entry(), pendingRevokeChangedMock);

    await screen.findByText('An older key at this provider is still live.');
    await user.click(screen.getByRole('button', { name: 'I deleted it myself' }));
    const confirmButton = await screen.findByRole('button', { name: 'Confirm, clear the record' });
    await user.type(screen.getByPlaceholderText(PREDECESSOR_KEY_ID), PREDECESSOR_KEY_ID);
    await user.click(confirmButton);

    await waitFor(() => expect(resolveMock).toHaveBeenCalledWith('e1', PREDECESSOR_KEY_ID));
    // The banner must STAY, because another key is still live.
    expect(
      await screen.findByText('An older key at this provider is still live.')
    ).toBeInTheDocument();
    // And the parent's copy must carry the promoted key, not null.
    expect(pendingRevokeChangedMock).toHaveBeenCalledWith({ pending_revoke: stillOutstanding });
  });

  it('positive control: the banner DOES come down when nothing is left outstanding', async () => {
    // Without this, the test above would pass against a component that simply
    // never clears the banner.
    const user = userEvent.setup();
    resolveMock.mockResolvedValue({ resolved: true, pending_revoke: null });
    renderRotationManager(entry());

    await screen.findByText('An older key at this provider is still live.');
    await user.click(screen.getByRole('button', { name: 'I deleted it myself' }));
    const confirmButton = await screen.findByRole('button', { name: 'Confirm, clear the record' });
    await user.type(screen.getByPlaceholderText(PREDECESSOR_KEY_ID), PREDECESSOR_KEY_ID);
    await user.click(confirmButton);

    await waitFor(() => expect(resolveMock).toHaveBeenCalled());
    await waitFor(() =>
      expect(
        screen.queryByText('An older key at this provider is still live.')
      ).not.toBeInTheDocument()
    );
  });
});

describe('the locked table shows a stranded key independently of last_rotation_error', () => {
  it('renders "Predecessor key live" for an entry with pending_revoke.outstanding and an EMPTY last_rotation_error', async () => {
    // last_rotation_error is deliberately empty here. It is what the server
    // overwrites on every later rotation attempt, so an on-demand entry (never
    // rotated again) can carry NO error text at all while still having a real
    // key stranded live at the provider. If the chip depended on this field,
    // this exact entry -- the one the feature exists for -- would show nothing.
    vaultListMock.mockResolvedValue([
      entry({
        last_rotation_error: '',
        rotation_status: 'overdue',
        pending_revoke: { outstanding: true, predecessor_key_id: PREDECESSOR_KEY_ID },
      }),
    ]);

    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })}>
        <MemoryRouter>
          <Vault />
        </MemoryRouter>
      </QueryClientProvider>
    );

    await screen.findByText('Stripe secret key');
    expect(await screen.findByText('Predecessor key live')).toBeInTheDocument();
    // No rotation-error chip should appear alongside it: this entry has none.
    expect(screen.queryByText('Failed')).not.toBeInTheDocument();
  });

  it('the chip tooltip says "an older key" rather than leaving a blank where the id goes', async () => {
    // The TWIN of the RotationManager fix below. The unlocked panel and this
    // locked chip both interpolate predecessor_key_id, and the first pass at
    // this fixed only the panel -- so the locked table, which is the ONLY
    // signal a locked on-demand entry has, still rendered "Key  could not be
    // deleted" with a hole in the sentence.
    vaultListMock.mockResolvedValue([
      entry({ pending_revoke: { outstanding: true, predecessor_key_id: '' } }),
    ]);

    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })}>
        <MemoryRouter>
          <Vault />
        </MemoryRouter>
      </QueryClientProvider>
    );

    await screen.findByText('Stripe secret key');
    const chip = await screen.findByText('Predecessor key live');
    const tip = chip.closest('span')?.getAttribute('title') ?? '';
    expect(tip).not.toMatch(/Key\s{2,}/);
    expect(tip).toContain('An older key');
  });

  it('sanity check: an entry with no pending_revoke shows no chip at all', async () => {
    vaultListMock.mockResolvedValue([entry({ pending_revoke: null })]);

    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })}>
        <MemoryRouter>
          <Vault />
        </MemoryRouter>
      </QueryClientProvider>
    );

    await screen.findByText('Stripe secret key');
    expect(screen.queryByText('Predecessor key live')).not.toBeInTheDocument();
  });
});

describe('a predecessor id the backend could not characterize', () => {
  // FRONTEND-CONTRACT.md allows predecessor_key_id to be "" while outstanding
  // is still true, and states two consequences. The UI broke both:
  //  (a) it rendered the empty id straight into a <code> element, so the
  //      banner read "The last rotation replaced key  but could not delete
  //      it" with a blank gap where the id belongs.
  //  (b) it still offered "I deleted it myself". The confirmation IS typing
  //      the id back, so at "" the disabled test ('' !== '') is false: the
  //      button was live, and every click was a certain 400 from the server's
  //      own equality check -- a dead end with no way out of the banner.
  const blind = () => entry({ pending_revoke: { outstanding: true, predecessor_key_id: '' } });

  it('still warns and offers retry, but does NOT offer resolve', async () => {
    renderRotationManager(blind());

    await screen.findByText('An older key at this provider is still live.');
    expect(screen.getByRole('button', { name: 'Retry the revoke' })).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'I deleted it myself' })
    ).not.toBeInTheDocument();
  });

  it('renders prose for the unknown id rather than a blank code element', async () => {
    renderRotationManager(blind());

    await screen.findByText('An older key at this provider is still live.');
    expect(document.body.textContent).toContain('could not determine that key');

    const blankCodes = Array.from(document.querySelectorAll('code')).filter(
      (el) => (el.textContent ?? '').trim() === ''
    );
    expect(blankCodes).toHaveLength(0);
  });

  it('positive control: the SAME entry carrying an id does offer resolve', async () => {
    // Without this, the two tests above pass just as well against a component
    // that never renders the resolve button for anybody.
    renderRotationManager(entry());

    await screen.findByText('An older key at this provider is still live.');
    expect(
      screen.getByRole('button', { name: 'I deleted it myself' })
    ).toBeInTheDocument();
  });
});

describe('a provider save must not invent an all-clear the server did not give', () => {
  it('forwards the server\'s pending_revoke instead of hardcoding null', async () => {
    // The server drops the stranded-key markers ONLY when the provider
    // actually changed (reconcileProviderMetaForStorage's `keep` is literally
    // provider == current.Provider). On an unchanged-provider save it keeps
    // them, and says so: Update returns a full entry with pending_revoke
    // always present. The client used to overwrite that with a hardcoded
    // null, on the stated but false premise that "the response to a provider
    // save is not a full VaultEntry" -- so the alarm for a key still live at
    // the provider read as resolved.
    const user = userEvent.setup();
    const stillOutstanding = { outstanding: true, predecessor_key_id: PREDECESSOR_KEY_ID };
    vaultUpdateMock.mockResolvedValue({
      ...entry(),
      provider: 'stripe',
      provider_meta: '{}',
      pending_revoke: stillOutstanding,
    });

    const saved: unknown[] = [];
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    render(
      <QueryClientProvider client={qc}>
        <RotationManager entry={entry()} onProviderSaved={(patch) => saved.push(patch)} />
      </QueryClientProvider>
    );

    await screen.findByText('An older key at this provider is still live.');
    await user.click(await screen.findByRole('button', { name: 'Save provider' }));

    await waitFor(() => expect(vaultUpdateMock).toHaveBeenCalled());
    await waitFor(() => expect(saved).toHaveLength(1));

    expect(saved[0]).toMatchObject({ pending_revoke: stillOutstanding });

    // And the panel itself must still show the alarm.
    expect(
      screen.getByText('An older key at this provider is still live.')
    ).toBeInTheDocument();
  });

  it('positive control: when the server DOES clear it, the banner goes', async () => {
    // Without this the test above passes against a component that simply never
    // updates pending_revoke on save.
    const user = userEvent.setup();
    vaultUpdateMock.mockResolvedValue({
      ...entry(),
      provider: 'sendgrid',
      provider_meta: '{}',
      pending_revoke: null,
    });

    const saved: unknown[] = [];
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
    render(
      <QueryClientProvider client={qc}>
        <RotationManager entry={entry()} onProviderSaved={(patch) => saved.push(patch)} />
      </QueryClientProvider>
    );

    await screen.findByText('An older key at this provider is still live.');
    await user.click(await screen.findByRole('button', { name: 'Save provider' }));

    await waitFor(() => expect(saved).toHaveLength(1));
    expect(saved[0]).toMatchObject({ pending_revoke: null });
    await waitFor(() =>
      expect(
        screen.queryByText('An older key at this provider is still live.')
      ).not.toBeInTheDocument()
    );
  });
});

describe('the stranded-key alarm must survive unlocking', () => {
  // The chip lived ONLY in the locked table, so the single signal an
  // on-demand entry has disappeared the moment the operator unlocked, which is
  // exactly when they are working on their secrets. FRONTEND-CONTRACT.md ties
  // the requirement to "wherever rotation_status is already shown", and the
  // unlocked row shows rotation_status.
  const stranded = () =>
    entry({
      username: 'admin',
      rotation_status: 'fresh',
      last_rotation_error: '',
      pending_revoke: { outstanding: true, predecessor_key_id: PREDECESSOR_KEY_ID },
    });

  async function renderAndUnlock() {
    const user = userEvent.setup();
    vaultListMock.mockResolvedValue([stranded()]);
    vaultUnlockMock.mockResolvedValue([stranded()]);
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })}>
        <MemoryRouter>
          <Vault />
        </MemoryRouter>
      </QueryClientProvider>
    );
    await screen.findByText('Stripe secret key');
    await user.type(await screen.findByPlaceholderText('Enter your password'), 'hunter2');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));
    // The username column exists only in the unlocked view, so this is the
    // discriminator that we really left the locked table.
    await screen.findByText('admin');
  }

  it('still shows "Predecessor key live" after unlocking', async () => {
    await renderAndUnlock();
    expect(screen.getByText('Predecessor key live')).toBeInTheDocument();
  });

  it('shows it even when rotation_status is Fresh and there is no rotation error', async () => {
    // The two are independent: an entry can read Fresh and still carry a live
    // orphaned predecessor. Folding them into one badge would hide exactly the
    // on-demand entry this feature exists for.
    await renderAndUnlock();
    expect(screen.getByText('Fresh')).toBeInTheDocument();
    expect(screen.queryByText('Rotation failed')).not.toBeInTheDocument();
    expect(screen.getByText('Predecessor key live')).toBeInTheDocument();
  });

  it('positive control: an entry with no pending_revoke shows no chip once unlocked', async () => {
    const user = userEvent.setup();
    const clean = entry({ username: 'admin', pending_revoke: null });
    vaultListMock.mockResolvedValue([clean]);
    vaultUnlockMock.mockResolvedValue([clean]);
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })}>
        <MemoryRouter>
          <Vault />
        </MemoryRouter>
      </QueryClientProvider>
    );
    await screen.findByText('Stripe secret key');
    await user.type(await screen.findByPlaceholderText('Enter your password'), 'hunter2');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));
    await screen.findByText('admin');
    expect(screen.queryByText('Predecessor key live')).not.toBeInTheDocument();
  });
});
