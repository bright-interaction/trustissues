import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { User } from '@/lib/types';

const mocks = vi.hoisted(() => ({
  redeem: vi.fn(),
  login: vi.fn(),
  currentUser: {
    value: null as User | null,
  },
}));

vi.mock('@/lib/api', () => ({
  api: {
    auth: {
      redeemInvitation: (...args: unknown[]) => mocks.redeem(...args),
    },
  },
}));

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: mocks.currentUser.value,
    isLoading: false,
    isAdmin: false,
    isVaultOnly: mocks.currentUser.value?.role === 'vault_only',
    setupRequired: false,
    login: (...args: unknown[]) => mocks.login(...args),
    logout: vi.fn(),
    refreshUser: vi.fn(),
  }),
}));

import Invite from '@/pages/Invite';
import ClientOnboarding from '@/pages/ClientOnboarding';

const vaultOnlyUser: User = {
  id: 'client-1',
  email: 'client@example.com',
  name: 'Client User',
  role: 'vault_only',
  totp_enabled: false,
  created_at: '2026-08-27T10:00:00Z',
};

function renderInvite() {
  return render(
    <MemoryRouter initialEntries={['/invite?code=INV-SAFE2345']}>
      <Routes>
        <Route path="/invite" element={<Invite />} />
        <Route path="/client-onboarding" element={<ClientOnboarding />} />
        <Route path="/" element={<div>ordinary account home</div>} />
        <Route path="/vault" element={<div>vault</div>} />
      </Routes>
    </MemoryRouter>
  );
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  mocks.redeem.mockReset();
  mocks.login.mockReset();
  mocks.currentUser.value = vaultOnlyUser;
});

afterEach(() => vi.clearAllMocks());

describe('web-first client onboarding', () => {
  it('redeems with a password, signs in, and ignores any response bootstrap key', async () => {
    const responseSecret = 'ti_must_never_be_exposed_or_stored';
    mocks.redeem.mockResolvedValue({
      user: vaultOnlyUser,
      // A stale or malicious server may still append this field. The frontend
      // contract intentionally omits it and the page must never touch it.
      api_key: responseSecret,
      server_url: 'https://untrusted-response.example',
    });
    mocks.login.mockResolvedValue({ user: vaultOnlyUser });
    const user = userEvent.setup();
    renderInvite();

    await user.type(screen.getByLabelText('Choose a password'), 'correct horse battery staple');
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    expect(await screen.findByText('Your account is ready')).toBeInTheDocument();
    expect(mocks.redeem).toHaveBeenCalledWith(
      'INV-SAFE2345',
      'correct horse battery staple'
    );
    expect(mocks.login).toHaveBeenCalledWith(
      'client@example.com',
      'correct horse battery staple'
    );
    expect(screen.queryByText(responseSecret)).toBeNull();
    expect(screen.queryByDisplayValue(responseSecret)).toBeNull();
    expect(screen.queryByText('https://untrusted-response.example')).toBeNull();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('makes collection consent, named-key creation, and manual extension setup explicit', async () => {
    mocks.redeem.mockResolvedValue({ user: vaultOnlyUser });
    mocks.login.mockResolvedValue({ user: vaultOnlyUser });
    const user = userEvent.setup();
    renderInvite();

    await user.type(screen.getByLabelText('Choose a password'), 'correct horse battery staple');
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    expect(await screen.findByText(/Accept the pending client-vault invitation/i)).toBeInTheDocument();
    expect(screen.getByText(/Create a named extension API key/i)).toBeInTheDocument();
    expect(screen.getByText(/Configure the browser extension manually/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open Vault/i })).toHaveAttribute('href', '/vault');
    expect(screen.getByRole('link', { name: /Open API-key settings/i })).toHaveAttribute(
      'href',
      '/settings?tab=apikeys'
    );
    expect(screen.getByLabelText('Public server URL')).toHaveValue(window.location.origin);
  });

  it('keeps the existing direct sign-in path for a non-vault-only invitation', async () => {
    const ordinaryUser = { ...vaultOnlyUser, id: 'user-1', role: 'user' as const };
    mocks.currentUser.value = ordinaryUser;
    mocks.redeem.mockResolvedValue({ user: ordinaryUser });
    mocks.login.mockResolvedValue({ user: ordinaryUser });
    const user = userEvent.setup();
    renderInvite();

    await user.type(screen.getByLabelText('Choose a password'), 'correct horse battery staple');
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    expect(await screen.findByText('ordinary account home')).toBeInTheDocument();
    expect(screen.queryByText('Your account is ready')).toBeNull();
  });
});
