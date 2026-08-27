import { useCallback, useEffect, useRef, useState } from 'react';
import { FileText, Upload, AlertTriangle } from 'lucide-react';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { vaultApi } from '@/lib/vault-types';
import type {
  NativeVaultImportPreview,
  VaultImportPreview,
} from '@/lib/vault-types';

interface VaultImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImportComplete: () => void;
}

const MAX_IMPORT_BYTES = 10 * 1024 * 1024;

function isNativeExport(file: File): boolean {
  return file.name.toLowerCase().endsWith('.json');
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

export default function VaultImportModal({ isOpen, onClose, onImportComplete }: VaultImportModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<VaultImportPreview | null>(null);
  const [nativePreview, setNativePreview] = useState<NativeVaultImportPreview | null>(null);
  const [password, setPassword] = useState('');
  const [nativeError, setNativeError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState<string>('auto');
  const previewAbortRef = useRef<AbortController | null>(null);
  const importAbortRef = useRef<AbortController | null>(null);

  const abortInFlight = useCallback(() => {
    previewAbortRef.current?.abort();
    importAbortRef.current?.abort();
    previewAbortRef.current = null;
    importAbortRef.current = null;
  }, []);

  const reset = useCallback(() => {
    abortInFlight();
    setFile(null);
    setPreview(null);
    setNativePreview(null);
    setPassword('');
    setNativeError(null);
    setIsUploading(false);
    setIsImporting(false);
    setSelectedFormat('auto');
  }, [abortInFlight]);

  useEffect(() => {
    if (!isOpen) reset();
  }, [isOpen, reset]);

  useEffect(() => abortInFlight, [abortInFlight]);

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (selectedFile) {
      const lowerName = selectedFile.name.toLowerCase();
      if (!lowerName.endsWith('.csv') && !lowerName.endsWith('.json')) {
        toast.error('Please select a CSV or JSON file');
        event.currentTarget.value = '';
        return;
      }
      if (selectedFile.size > MAX_IMPORT_BYTES) {
        toast.error('File size must be 10MB or smaller');
        event.currentTarget.value = '';
        return;
      }
      abortInFlight();
      setFile(selectedFile);
      setPreview(null);
      setNativePreview(null);
      setPassword('');
      setNativeError(null);
      setIsUploading(false);
      setIsImporting(false);
    }
  };

  const handlePreview = async () => {
    if (!file) return;

    previewAbortRef.current?.abort();
    const controller = new AbortController();
    previewAbortRef.current = controller;
    setIsUploading(true);
    setNativeError(null);
    try {
      if (isNativeExport(file)) {
        const result = await vaultApi.nativeImportPreview(file, controller.signal);
        if (!controller.signal.aborted) setNativePreview(result);
      } else {
        const result = await vaultApi.importPreview(file, selectedFormat, controller.signal);
        if (!controller.signal.aborted) setPreview(result);
      }
    } catch (error: unknown) {
      if (!isAbortError(error) && !controller.signal.aborted) {
        if (isNativeExport(file)) {
          const message = 'Could not validate this TrustIssues export. Check that it is an unmodified version 1 export and try again.';
          setNativeError(message);
          toast.error(message);
        } else {
          console.error('Import preview error:', error);
          toast.error(error instanceof Error ? error.message : 'Failed to preview import');
        }
      }
    } finally {
      if (previewAbortRef.current === controller) {
        previewAbortRef.current = null;
        setIsUploading(false);
      }
    }
  };

  const handleImport = async () => {
    if (!preview) return;

    setIsImporting(true);
    try {
      const entriesToImport = preview.entries.filter(entry => !entry.skip);
      const result = await vaultApi.importConfirm(entriesToImport);
      const skipped = result.skipped ?? [];
      if (skipped.length > 0) {
        // A partial import used to report plain success: entries with a
        // duplicate title were dropped server-side and the user only found out
        // when they went looking for one. Name them, and keep the message up
        // until dismissed rather than letting it flash past.
        toast.error(
          `Imported ${result.imported}, skipped ${skipped.length}: ` +
            skipped
              .slice(0, 5)
              .map((s) => `"${s.name}" (${s.reason})`)
              .join('; ') +
            (skipped.length > 5 ? `, and ${skipped.length - 5} more` : ''),
          { duration: 15000 }
        );
      } else {
        toast.success(`Successfully imported ${result.imported} entries`);
      }
      onImportComplete();
      reset();
    } catch (error: unknown) {
      console.error('Import error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to import entries');
    } finally {
      setIsImporting(false);
    }
  };

  const handleNativeImport = async () => {
    if (!file || !nativePreview || nativePreview.conflicts.length > 0 || password.length === 0) {
      return;
    }

    importAbortRef.current?.abort();
    const controller = new AbortController();
    importAbortRef.current = controller;
    const passwordForRequest = password;
    setPassword('');
    setNativeError(null);
    setIsImporting(true);

    try {
      const result = await vaultApi.nativeImportConfirm(
        file,
        passwordForRequest,
        controller.signal
      );
      if (controller.signal.aborted) return;

      toast.success(
        `Successfully imported ${result.imported} entries and created ${result.collections_created} collections`
      );
      reset();
      onImportComplete();
      onClose();
    } catch (error: unknown) {
      if (!isAbortError(error) && !controller.signal.aborted) {
        const message = 'Import failed. Your vault was not changed. Check your password and file, then try again.';
        setNativeError(message);
        toast.error(message);
      }
    } finally {
      if (importAbortRef.current === controller) {
        importAbortRef.current = null;
        setIsImporting(false);
      }
    }
  };

  const handleBack = () => {
    setPreview(null);
    setNativePreview(null);
    setPassword('');
    setNativeError(null);
  };

  const toggleSkipEntry = (index: number) => {
    if (!preview) return;

    const newEntries = [...preview.entries];
    newEntries[index].skip = !newEntries[index].skip;
    setPreview({
      ...preview,
      entries: newEntries,
    });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black bg-opacity-50"
        onClick={handleClose}
      />

      {/* Modal */}
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="vault-import-title"
        className="relative z-10 w-full max-w-4xl bg-white rounded-xl shadow-xl mx-4"
      >
        <div className="flex items-center justify-between p-6 border-b border-slate-200">
          <h2 id="vault-import-title" className="text-xl font-semibold text-slate-900">
            Import Password Manager Data
          </h2>
          <button
            type="button"
            aria-label="Close import"
            onClick={handleClose}
            className="text-slate-400 hover:text-slate-600"
          >
            ×
          </button>
        </div>

        <div className="p-6 max-h-[80vh] overflow-y-auto">
          {/* Step 1: File Upload */}
          {!preview && !nativePreview && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Select a CSV or TrustIssues JSON file to import
                </label>
                <div className="border-2 border-dashed border-slate-300 rounded-lg p-6 text-center hover:border-slate-400 transition-colors">
                  <FileText className="mx-auto h-12 w-12 text-slate-400" />
                  <div className="mt-4">
                    <label className="inline-flex items-center px-4 py-2 bg-white border border-slate-300 rounded-md shadow-sm text-sm font-medium text-slate-700 hover:bg-slate-50 cursor-pointer">
                      <Upload className="h-4 w-4 mr-2" />
                      Choose File
                      <input
                        type="file"
                        className="sr-only"
                        accept=".csv,.json,text/csv,application/json"
                        onChange={handleFileSelect}
                      />
                    </label>
                  </div>
                  {file && (
                    <p className="mt-2 text-sm text-slate-500">
                      Selected: {file.name}
                    </p>
                  )}
                  <p className="mt-4 text-sm text-slate-500">
                    Supports TrustIssues JSON exports and 1Password, Bitwarden, or LastPass CSV exports
                  </p>
                </div>
              </div>

              {file && isNativeExport(file) && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <div className="flex items-start">
                    <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    <div className="ml-3">
                      <p className="text-sm font-medium text-red-800">
                        This JSON file contains plaintext vault secrets.
                      </p>
                      <p className="text-sm text-red-700 mt-1">
                        Keep it private and remove every plaintext copy after you verify the import.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {(!file || !isNativeExport(file)) && <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Format (auto-detection is recommended)
                </label>
                <select
                  value={selectedFormat}
                  onChange={(e) => setSelectedFormat(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 rounded-md text-sm focus:outline-none focus:border-slate-400"
                >
                  <option value="auto">Auto-detect format</option>
                  <option value="1password">1Password</option>
                  <option value="bitwarden">Bitwarden</option>
                  <option value="lastpass">LastPass</option>
                </select>
              </div>}

              {nativeError && (
                <div role="alert" className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-800">
                  {nativeError}
                </div>
              )}

              {file && (
                <div className="flex justify-end">
                  <button
                    onClick={handlePreview}
                    disabled={isUploading}
                    className={clsx(
                      "px-4 py-2 bg-slate-900 text-white rounded-md text-sm font-medium",
                      "hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed"
                    )}
                  >
                    {isUploading ? 'Analyzing...' : 'Preview Import'}
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Step 2: Preview */}
          {preview && (
            <div className="space-y-4">
              {/* Format and count */}
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <p className="text-sm text-blue-800">
                  Detected format: <strong>{preview.format}</strong>
                  • {preview.total} entries ready for import
                </p>
              </div>

              {/* Rows the parser dropped.
                  Shown BEFORE conflicts because a conflict is a choice the
                  operator gets to make, while a dropped row is data that will
                  not arrive at all. The count on its own could never reveal
                  this: `total` is computed after the drops, so an export of
                  500 with 120 secure notes looked exactly like a clean export
                  of 380. */}
              {(preview.skipped?.length ?? 0) > 0 && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <div className="flex items-start">
                    <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    <div className="ml-3 min-w-0">
                      <p className="text-sm font-medium text-red-800">
                        {preview.skipped.length} of {preview.source_rows} rows in this file cannot be
                        imported
                      </p>
                      <p className="text-sm text-red-600 mt-1">
                        These will NOT be added. A Bitwarden secure note keeps its content in
                        the notes field, so check them in your export before deleting it.
                      </p>
                      <ul className="mt-2 space-y-1 text-sm text-red-700 max-h-32 overflow-y-auto">
                        {preview.skipped.slice(0, 20).map((s, i) => (
                          <li key={i} className="truncate">
                            <span className="font-medium">{s.name}</span>: {s.reason}
                          </li>
                        ))}
                      </ul>
                      {preview.skipped.length > 20 && (
                        <p className="text-sm text-red-600 mt-1">
                          and {preview.skipped.length - 20} more
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Warnings */}
              {preview.conflicts.length > 0 && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                  <div className="flex items-start">
                    <AlertTriangle className="h-5 w-5 text-yellow-500 mt-0.5" />
                    <div className="ml-3">
                      <p className="text-sm font-medium text-yellow-800">
                        {preview.conflicts.length} entr{preview.conflicts.length !== 1 ? 'ies' : 'y'} will be skipped due to name conflicts
                      </p>
                      <p className="text-sm text-yellow-600 mt-1">
                        You can manually check entries below to override this behavior
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Entries table */}
              <div>
                <p className="text-sm font-medium text-slate-700 mb-2">
                  Entries to import ({preview.entries.filter(e => !e.skip).length})
                </p>
                <div className="border border-slate-200 rounded-lg overflow-hidden">
                  <table className="min-w-full divide-y divide-slate-200">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-4 py-2 text-left text-xs font-medium text-slate-500">Name</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-slate-500">Username</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-slate-500">URL</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-slate-500">Category</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-slate-500">Skip?</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-slate-200">
                      {preview.entries.map((entry, index) => (
                        <tr
                          key={index}
                          className={clsx(
                            "hover:bg-slate-50",
                            entry.skip && "opacity-50"
                          )}
                        >
                          <td className="px-4 py-2 text-sm font-medium text-slate-900">
                            {entry.name}
                          </td>
                          <td className="px-4 py-2 text-sm text-slate-500">
                            {entry.username || '-'}
                          </td>
                          <td className="px-4 py-2 text-sm text-slate-500">
                            {entry.url || '-'}
                          </td>
                          <td className="px-4 py-2 text-sm text-slate-500">
                            {entry.category || '-'}
                          </td>
                          <td className="px-4 py-2 text-sm">
                            <label className="flex items-center cursor-pointer">
                              <input
                                type="checkbox"
                                checked={entry.skip || false}
                                onChange={() => toggleSkipEntry(index)}
                                className="rounded border-slate-300 text-slate-900"
                              />
                              <span className="ml-2 text-xs text-slate-600">
                                {entry.skip ? 'Skipped' : 'Import'}
                              </span>
                            </label>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Actions */}
              <div className="flex justify-between">
                <button
                  onClick={handleBack}
                  className="px-4 py-2 border border-slate-300 rounded-md text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  Back
                </button>
                <button
                  onClick={handleImport}
                  disabled={isImporting || preview.entries.filter(e => !e.skip).length === 0}
                  className={clsx(
                    "px-4 py-2 bg-slate-900 text-white rounded-md text-sm font-medium",
                    "hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed"
                  )}
                >
                  {isImporting ? 'Importing...' : `Import ${preview.entries.filter(e => !e.skip).length} entries`}
                </button>
              </div>
            </div>
          )}

          {/* TrustIssues-native files are deliberately not rendered as a row
              table: preview responses contain counts and conflict names only,
              so plaintext values never get copied into React state or the DOM. */}
          {nativePreview && (
            <div className="space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <p className="text-sm text-blue-800">
                  TrustIssues export version <strong>{nativePreview.version}</strong>
                  {' • '}{nativePreview.entry_count} entries in {nativePreview.collection_count}{' '}
                  {nativePreview.collection_count === 1 ? 'collection' : 'collections'}
                </p>
              </div>

              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-start">
                  <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-red-800">
                      This file contains plaintext vault secrets.
                    </p>
                    <p className="text-sm text-red-700 mt-1">
                      Anyone who can open it can read them. Keep it private and remove every plaintext copy after you verify the import.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
                <div className="flex items-start">
                  <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 shrink-0" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-amber-900">
                      Imported auto-rotation will be disabled.
                    </p>
                    <p className="text-sm text-amber-800 mt-1">
                      {nativePreview.auto_rotate_disabled > 0
                        ? `${nativePreview.auto_rotate_disabled} entries requested auto-rotation. Review their provider settings and delivery targets before enabling it again.`
                        : 'Review provider settings and delivery targets before enabling auto-rotation on imported entries.'}
                    </p>
                  </div>
                </div>
              </div>

              {nativePreview.conflicts.length > 0 && (
                <div role="alert" className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <div className="flex items-start">
                    <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    <div className="ml-3 min-w-0">
                      <p className="text-sm font-medium text-red-800">
                        Import blocked by {nativePreview.conflicts.length} name{' '}
                        {nativePreview.conflicts.length === 1 ? 'conflict' : 'conflicts'}
                      </p>
                      <p className="text-sm text-red-700 mt-1">
                        Nothing will be imported. Rename the existing or exported entries, then preview the file again.
                      </p>
                      <ul className="mt-2 max-h-32 space-y-1 overflow-y-auto text-sm text-red-800">
                        {nativePreview.conflicts.slice(0, 20).map((conflict, index) => (
                          <li key={`${conflict}-${index}`} className="truncate">{conflict}</li>
                        ))}
                      </ul>
                      {nativePreview.conflicts.length > 20 && (
                        <p className="text-sm text-red-700 mt-1">
                          and {nativePreview.conflicts.length - 20} more
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}

              <div>
                <label htmlFor="native-import-password" className="block text-sm font-medium text-slate-700 mb-2">
                  Current account password
                </label>
                <input
                  id="native-import-password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={nativePreview.conflicts.length > 0 || isImporting}
                  className="w-full px-3 py-2 border border-slate-300 rounded-md text-sm focus:outline-none focus:border-slate-400 disabled:bg-slate-100"
                />
                <p className="mt-1 text-xs text-slate-500">
                  Reauthentication is required before the server validates and encrypts every imported secret for this account.
                </p>
              </div>

              {nativeError && (
                <div role="alert" className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-800">
                  {nativeError}
                </div>
              )}

              <div className="flex justify-between">
                <button
                  type="button"
                  onClick={handleBack}
                  disabled={isImporting}
                  className="px-4 py-2 border border-slate-300 rounded-md text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Back
                </button>
                <button
                  type="button"
                  onClick={handleNativeImport}
                  disabled={
                    isImporting ||
                    nativePreview.conflicts.length > 0 ||
                    password.length === 0
                  }
                  className={clsx(
                    'px-4 py-2 bg-slate-900 text-white rounded-md text-sm font-medium',
                    'hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed'
                  )}
                >
                  {isImporting ? 'Importing...' : `Import ${nativePreview.entry_count} entries`}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
