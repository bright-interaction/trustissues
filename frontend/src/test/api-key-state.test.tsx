import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ApiKey } from '@/lib/types';

const listMock = vi.fn();
const deleteMock = vi.fn();

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      apiKeys: {
        ...actual.api.apiKeys,
        list: () => listMock(),
        delete: (id: string) => deleteMock(id),
      },
    },
  };
});

import { ApiKeysTab } from '@/pages/Settings';

function key(overrides: Partial<ApiKey>): ApiKey {
  return {
    id: 'key-live',
    name: 'Laptop live',
    key_prefix: 'abc123',
    revoked_at: null,
    last_used_at: null,
    expires_at: '2999-08-27T10:00:00Z',
    created_at: '2026-08-27T10:00:00Z',
    ...overrides,
  };
}

function renderTab() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <ApiKeysTab />
    </QueryClientProvider>
  );
}

beforeEach(() => {
  deleteMock.mockReset().mockResolvedValue(undefined);
  listMock.mockReset().mockResolvedValue([
    key({}),
    key({
      id: 'key-expired',
      name: 'Old browser',
      key_prefix: 'expired',
      expires_at: '2000-01-02T03:04:05Z',
    }),
    key({
      id: 'key-revoked',
      name: 'Lost laptop',
      key_prefix: 'revoked',
      expires_at: '2999-08-27T10:00:00Z',
      revoked_at: '2026-08-26T09:00:00Z',
    }),
  ]);
});

afterEach(() => vi.clearAllMocks());

describe('API-key lifecycle state', () => {
  it('renders live, expired, and revoked rows with their expiry evidence', async () => {
    renderTab();

    expect(await screen.findByLabelText('Laptop live status')).toHaveTextContent('Live');
    expect(screen.getByLabelText('Old browser status')).toHaveTextContent('Expired');
    expect(screen.getByLabelText('Lost laptop status')).toHaveTextContent('Revoked');

    expect(screen.getByText(/Expires Jan 2, 2000/i)).toHaveAttribute(
      'datetime',
      '2000-01-02T03:04:05Z'
    );
    expect(screen.getByText(/Revoked Aug 26, 2026/i)).toHaveAttribute(
      'datetime',
      '2026-08-26T09:00:00Z'
    );
  });

  it('only offers revocation for a live key and never treats an inactive row as live', async () => {
    const user = userEvent.setup();
    renderTab();

    const revoke = await screen.findByRole('button', { name: 'Revoke Laptop live' });
    expect(screen.queryByRole('button', { name: 'Revoke Old browser' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Revoke Lost laptop' })).toBeNull();

    await user.click(revoke);
    expect(deleteMock).toHaveBeenCalledWith('key-live');
  });
});
