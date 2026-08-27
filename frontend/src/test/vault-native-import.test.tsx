import { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const {
  csvConfirmMock,
  csvPreviewMock,
  nativeConfirmMock,
  nativePreviewMock,
} = vi.hoisted(() => ({
  csvConfirmMock: vi.fn(),
  csvPreviewMock: vi.fn(),
  nativeConfirmMock: vi.fn(),
  nativePreviewMock: vi.fn(),
}));

vi.mock('@/lib/vault-types', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/vault-types')>();
  return {
    ...actual,
    vaultApi: {
      ...actual.vaultApi,
      importConfirm: csvConfirmMock,
      importPreview: csvPreviewMock,
      nativeImportConfirm: nativeConfirmMock,
      nativeImportPreview: nativePreviewMock,
    },
  };
});

import VaultImportModal from '@/components/VaultImportModal';

const nativePreview = {
  format: 'trustissues-vault',
  version: 1,
  entry_count: 3,
  collection_count: 2,
  conflicts: [] as string[],
  auto_rotate_disabled: 1,
};

function Harness({ onComplete = vi.fn() }: { onComplete?: () => void }) {
  const [isOpen, setIsOpen] = useState(true);
  return (
    <>
      <button type="button" onClick={() => setIsOpen(true)}>
        Open import
      </button>
      <VaultImportModal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        onImportComplete={onComplete}
      />
    </>
  );
}

function trustIssuesFile() {
  return new File(
    ['{"format":"trustissues-vault","version":1,"value":"DO_NOT_RENDER_SECRET"}'],
    'trustissues-vault-export.json',
    { type: 'application/json' }
  );
}

async function uploadAndPreview(file = trustIssuesFile()) {
  const user = userEvent.setup();
  await user.upload(screen.getByLabelText('Choose File'), file);
  await user.click(screen.getByRole('button', { name: 'Preview Import' }));
  await screen.findByText(/TrustIssues export version/i);
  return { file, user };
}

describe('TrustIssues native vault import', () => {
  beforeEach(() => {
    csvConfirmMock.mockReset();
    csvPreviewMock.mockReset();
    nativeConfirmMock.mockReset();
    nativePreviewMock.mockReset();
    nativePreviewMock.mockResolvedValue(nativePreview);
  });

  it('previews JSON using counts only and warns about plaintext and disabled rotation', async () => {
    render(<Harness />);
    const file = trustIssuesFile();
    const user = userEvent.setup();

    await user.upload(screen.getByLabelText('Choose File'), file);
    expect(
      screen.getByText('This JSON file contains plaintext vault secrets.')
    ).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Preview Import' }));

    expect(await screen.findByText(/3 entries in 2 collections/i)).toBeInTheDocument();
    expect(screen.getByText('This file contains plaintext vault secrets.')).toBeInTheDocument();
    expect(screen.getByText('Imported auto-rotation will be disabled.')).toBeInTheDocument();
    expect(screen.getByText(/1 entries requested auto-rotation/i)).toBeInTheDocument();
    expect(screen.queryByText('DO_NOT_RENDER_SECRET')).not.toBeInTheDocument();
    expect(nativePreviewMock).toHaveBeenCalledWith(file, expect.any(AbortSignal));
    expect(csvPreviewMock).not.toHaveBeenCalled();
  });

  it('blocks confirmation when preview reports any name conflict', async () => {
    nativePreviewMock.mockResolvedValue({
      ...nativePreview,
      conflicts: ['Existing GitHub entry'],
    });
    render(<Harness />);

    await uploadAndPreview();

    expect(screen.getByRole('alert')).toHaveTextContent('Import blocked by 1 name conflict');
    expect(screen.getByRole('alert')).toHaveTextContent('Existing GitHub entry');
    expect(screen.getByLabelText('Current account password')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Import 3 entries' })).toBeDisabled();
    expect(nativeConfirmMock).not.toHaveBeenCalled();
  });

  it('requires the current password and confirms by uploading the same file again', async () => {
    nativeConfirmMock.mockResolvedValue({
      imported: 3,
      collections_created: 2,
      auto_rotate_disabled: 1,
    });
    const onComplete = vi.fn();
    render(<Harness onComplete={onComplete} />);
    const { file, user } = await uploadAndPreview();
    const confirm = screen.getByRole('button', { name: 'Import 3 entries' });

    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('Current account password'), 'correct horse');
    expect(confirm).toBeEnabled();
    await user.click(confirm);

    await waitFor(() => {
      expect(nativeConfirmMock).toHaveBeenCalledWith(
        file,
        'correct horse',
        expect.any(AbortSignal)
      );
    });
    await waitFor(() => expect(onComplete).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('clears the selected file and password on close and after success', async () => {
    nativeConfirmMock.mockResolvedValue({
      imported: 3,
      collections_created: 2,
      auto_rotate_disabled: 1,
    });
    render(<Harness />);
    let flow = await uploadAndPreview();

    await flow.user.type(screen.getByLabelText('Current account password'), 'close-me');
    await flow.user.click(screen.getByRole('button', { name: 'Close import' }));
    await flow.user.click(screen.getByRole('button', { name: 'Open import' }));
    expect(screen.queryByText(/Selected:/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Current account password')).not.toBeInTheDocument();

    flow = await uploadAndPreview();
    await flow.user.type(screen.getByLabelText('Current account password'), 'success-me');
    await flow.user.click(screen.getByRole('button', { name: 'Import 3 entries' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await flow.user.click(screen.getByRole('button', { name: 'Open import' }));
    expect(screen.queryByText(/Selected:/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Current account password')).not.toBeInTheDocument();
  });

  it('drops the password immediately and aborts confirmation when closed', async () => {
    let requestSignal: AbortSignal | undefined;
    nativeConfirmMock.mockImplementation(
      (_file: File, _password: string, signal: AbortSignal) => {
        requestSignal = signal;
        return new Promise(() => {});
      }
    );
    render(<Harness />);
    const { user } = await uploadAndPreview();

    await user.type(screen.getByLabelText('Current account password'), 'do-not-retain');
    await user.click(screen.getByRole('button', { name: 'Import 3 entries' }));

    expect(screen.getByLabelText('Current account password')).toHaveValue('');
    expect(requestSignal?.aborted).toBe(false);
    await user.click(screen.getByRole('button', { name: 'Close import' }));
    expect(requestSignal?.aborted).toBe(true);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('keeps the existing CSV preview and confirm flow', async () => {
    csvPreviewMock.mockResolvedValue({
      format: 'bitwarden',
      entries: [{
        name: 'Example login',
        url: 'https://example.test',
        username: 'person@example.test',
        value: 'csv-secret',
        category: 'login',
      }],
      conflicts: [],
      total: 1,
      skipped: [],
      source_rows: 1,
    });
    csvConfirmMock.mockResolvedValue({ imported: 1, skipped: [] });
    render(<Harness />);
    const user = userEvent.setup();
    const file = new File(['name,url,username,password'], 'bitwarden.csv', {
      type: 'text/csv',
    });

    await user.upload(screen.getByLabelText('Choose File'), file);
    await user.click(screen.getByRole('button', { name: 'Preview Import' }));

    expect(await screen.findByText('Example login')).toBeInTheDocument();
    expect(screen.queryByLabelText('Current account password')).not.toBeInTheDocument();
    expect(csvPreviewMock).toHaveBeenCalledWith(file, 'auto', expect.any(AbortSignal));
    await user.click(screen.getByRole('button', { name: 'Import 1 entries' }));
    await waitFor(() => expect(csvConfirmMock).toHaveBeenCalledWith([
      expect.objectContaining({ name: 'Example login', value: 'csv-secret' }),
    ]));
    expect(nativeConfirmMock).not.toHaveBeenCalled();
  });
});
