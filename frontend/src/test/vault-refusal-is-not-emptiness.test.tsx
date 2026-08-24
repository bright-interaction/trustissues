import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { ApiError, TOTP_ENROLLMENT_REQUIRED_CODE } from '@/lib/api';

// "No secrets stored. Unlock the vault and add your first secret."
//
// That is what a credential vault holding five entries said to its owner when
// the enrolment gate refused the list. Vault.tsx destructured `data` and
// `isLoading` from the query and never `error`, and there was no error branch,
// so a 403 left `vaultList` at its `= []` default and fell straight through to
// the empty state.
//
// It is the most alarming sentence this product can produce. A user who has
// just been told their secrets are gone does not calmly read a banner; the
// difference between "we could not load this" and "there is nothing here" is
// the difference between an inconvenience and believing a vault has lost its
// contents.
//
// This renders the REAL Vault page against a REAL QueryClient with the list
// query rejecting, because the defect is a rendering-branch defect: reading the
// source for the word `error` would be satisfied by any mention of it.

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

vi.mock('@/lib/vault-types', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/vault-types')>();
  return {
    ...actual,
    vaultApi: { ...actual.vaultApi, list: () => listMock() },
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

function renderVault() {
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

const EMPTY_STATE = /No secrets stored/i;

beforeEach(() => {
  collectionsListMock.mockResolvedValue([]);
  pendingInvitesMock.mockResolvedValue([]);
  requestMock.mockResolvedValue({});
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('a refused vault list is never rendered as an empty one', () => {
  it('does not claim the vault is empty when the enrolment gate refuses it', async () => {
    listMock.mockRejectedValue(
      new ApiError('two-factor authentication is required', 403, {
        error: 'two-factor authentication is required',
        code: TOTP_ENROLLMENT_REQUIRED_CODE,
      })
    );

    renderVault();

    // The refusal must be stated, and it must say the secrets still exist.
    await waitFor(() => {
      expect(
        screen.getByText(/not shown because two-factor authentication is required/i)
      ).toBeInTheDocument();
    });
    expect(screen.getByText(/Nothing has been deleted/i)).toBeInTheDocument();

    // And the sentence that caused the alarm must be absent.
    expect(screen.queryByText(EMPTY_STATE)).toBeNull();
  });

  it('offers the way out, since the gate is the one refusal the user can fix', async () => {
    listMock.mockRejectedValue(
      new ApiError('two-factor authentication is required', 403, {
        error: 'two-factor authentication is required',
        code: TOTP_ENROLLMENT_REQUIRED_CODE,
      })
    );

    renderVault();

    const link = await screen.findByRole('link', { name: /set up 2fa/i });
    expect(link).toHaveAttribute('href', '/settings?tab=account');
  });

  it('does not claim the vault is empty on an ordinary failure either', async () => {
    listMock.mockRejectedValue(new ApiError('internal server error', 500));

    renderVault();

    await waitFor(() => {
      expect(
        screen.getByText(/Your secrets could not be loaded/i)
      ).toBeInTheDocument();
    });
    expect(screen.getByText(/Nothing has been deleted/i)).toBeInTheDocument();
    expect(screen.queryByText(EMPTY_STATE)).toBeNull();

    // A 500 is not something the user can fix by enrolling, so it must NOT
    // offer the 2FA route: sending them to a setup page for a server fault
    // would be a false instruction.
    expect(screen.queryByRole('link', { name: /set up 2fa/i })).toBeNull();
  });

  // The positive control. Without it, a component that rendered the refusal
  // text unconditionally -- or failed to render at all -- would satisfy every
  // assertion above.
  it('still shows the empty state when the vault is genuinely empty', async () => {
    listMock.mockResolvedValue([]);

    renderVault();

    await waitFor(() => {
      expect(screen.getByText(EMPTY_STATE)).toBeInTheDocument();
    });
    expect(
      screen.queryByText(/could not be loaded|not shown because/i)
    ).toBeNull();
  });
});
