import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createElement } from 'react';
import { analyzeCredentialHealth } from '@/lib/credential-health';
import type { VaultEntry } from '@/lib/vault-types';
import CredentialHealth from '@/components/CredentialHealth';

function entry(id: string, value: string, overrides: Partial<VaultEntry> = {}): VaultEntry {
  return {
    id,
    name: `Entry ${id}`,
    url: 'https://example.com',
    alias_url: '',
    username: 'person@example.com',
    value,
    category: 'login',
    notes: '',
    rotation_interval_days: null,
    expires_at: null,
    last_rotated_at: '2025-12-01T00:00:00Z',
    rotation_status: 'fresh',
    collection_id: null,
    created_at: '2025-12-01T00:00:00Z',
    updated_at: '2025-12-01T00:00:00Z',
    ...overrides,
  };
}

describe('credential health', () => {
  const now = new Date('2026-08-27T00:00:00Z');

  it('finds weak, reused, and old credentials without including their values', () => {
    const report = analyzeCredentialHealth([
      entry('a', 'password123', { last_rotated_at: '2024-01-01T00:00:00Z' }),
      entry('b', 'password123'),
      entry('c', 'R8!md4_Zp2#vL9@qT6'),
    ], now);

    expect(report).toMatchObject({ checked: 3, healthy: 1, weak: 2, reused: 2, old: 1 });
    expect(JSON.stringify(report)).not.toContain('password123');
  });

  it('does not label a long random credential weak', () => {
    const report = analyzeCredentialHealth([entry('strong', 'R8!md4_Zp2#vL9@qT6')], now);
    expect(report.issues).toEqual([]);
    expect(report.healthy).toBe(1);
  });

  it('ignores non-login opaque secrets for password-policy scoring', () => {
    const report = analyzeCredentialHealth([
      entry('ssh', 'short', { category: 'ssh_key', url: '', username: '' }),
    ], now);
    expect(report.checked).toBe(0);
  });

  it('shows entry names and reasons without rendering plaintext values', async () => {
    const user = userEvent.setup();
    render(createElement(CredentialHealth, {
      entries: [entry('a', 'password123', { name: 'Old portal' })],
    }));

    expect(screen.getByText(/need attention/i)).toBeInTheDocument();
    expect(screen.queryByText('password123')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /review/i }));
    expect(screen.getByText('Old portal')).toBeInTheDocument();
    expect(screen.getByText(/common-password list/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('password123');
  });
});
