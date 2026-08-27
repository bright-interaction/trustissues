import { useState } from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const { exportMock } = vi.hoisted(() => ({ exportMock: vi.fn() }));

vi.mock('@/lib/vault-types', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/vault-types')>();
  return {
    ...actual,
    vaultApi: { ...actual.vaultApi, export: exportMock },
  };
});

import VaultExportModal, {
  exportFilename,
} from '@/components/VaultExportModal';

function Harness() {
  const [isOpen, setIsOpen] = useState(true);
  return (
    <>
      <button type="button" onClick={() => setIsOpen(true)}>
        Open export
      </button>
      <VaultExportModal isOpen={isOpen} onClose={() => setIsOpen(false)} />
    </>
  );
}

describe('vault export', () => {
  const downloads: Array<{ href: string; filename: string }> = [];

  beforeEach(() => {
    downloads.length = 0;
    exportMock.mockReset();
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      writable: true,
      value: vi.fn(() => 'blob:trustissues-export'),
    });
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      writable: true,
      value: vi.fn(),
    });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(
      function (this: HTMLAnchorElement) {
        downloads.push({ href: this.href, filename: this.download });
      }
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('prominently warns that the download contains plaintext secrets', () => {
    render(<Harness />);

    expect(
      screen.getByText('The downloaded file contains plaintext secrets.')
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Anyone who can open it can read every exported password/i)
    ).toBeInTheDocument();
  });

  it('shows a wrong-password error and does not download anything', async () => {
    exportMock.mockRejectedValue(new Error('Incorrect password'));
    const user = userEvent.setup();
    render(<Harness />);

    await user.type(screen.getByLabelText('Account password'), 'wrong-password');
    await user.click(screen.getByRole('button', { name: 'Download export' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect password');
    expect(downloads).toEqual([]);
    expect(screen.getByLabelText('Account password')).toHaveValue('');
  });

  it('downloads the returned Blob using the Content-Disposition filename', async () => {
    const blob = new Blob(['{"version":1}'], { type: 'application/json' });
    exportMock.mockResolvedValue({
      blob,
      contentDisposition: 'attachment; filename="team-vault.json"',
    });
    const user = userEvent.setup();
    render(<Harness />);

    await user.type(screen.getByLabelText('Account password'), 'correct-password');
    await user.click(screen.getByRole('button', { name: 'Download export' }));

    await waitFor(() => expect(downloads).toEqual([
      { href: 'blob:trustissues-export', filename: 'team-vault.json' },
    ]));
    expect(exportMock).toHaveBeenCalledWith(
      'correct-password',
      expect.any(AbortSignal)
    );
    expect(URL.createObjectURL).toHaveBeenCalledWith(blob);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:trustissues-export');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('uses a deterministic safe fallback when no filename is supplied', () => {
    expect(exportFilename(null)).toBe('trustissues-vault-export.json');
    expect(exportFilename('attachment')).toBe('trustissues-vault-export.json');
    expect(
      exportFilename("attachment; filename*=UTF-8''Team%20Vault.json")
    ).toBe('Team Vault.json');
    expect(exportFilename('attachment; filename="../vault.json"')).toBe(
      '.._vault.json'
    );
  });

  it('clears the password when closed and after a successful export', async () => {
    const user = userEvent.setup();
    exportMock.mockResolvedValue({
      blob: new Blob(['{}'], { type: 'application/json' }),
      contentDisposition: null,
    });
    render(<Harness />);

    const password = screen.getByLabelText('Account password');
    await user.type(password, 'close-me');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await user.click(screen.getByRole('button', { name: 'Open export' }));
    expect(screen.getByLabelText('Account password')).toHaveValue('');

    await user.type(screen.getByLabelText('Account password'), 'download-me');
    await user.click(screen.getByRole('button', { name: 'Download export' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: 'Open export' }));
    expect(screen.getByLabelText('Account password')).toHaveValue('');
  });
});
