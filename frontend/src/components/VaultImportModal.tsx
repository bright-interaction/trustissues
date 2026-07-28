import { useState } from 'react';
import { FileText, Upload, AlertTriangle } from 'lucide-react';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { vaultApi } from '@/lib/vault-types';
import type { VaultImportPreview } from '@/lib/vault-types';

interface VaultImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImportComplete: () => void;
}

export default function VaultImportModal({ isOpen, onClose, onImportComplete }: VaultImportModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<VaultImportPreview | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState<string>('auto');

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (selectedFile) {
      if (!selectedFile.name.toLowerCase().endsWith('.csv')) {
        toast.error('Please select a CSV file');
        return;
      }
      if (selectedFile.size > 10 * 1024 * 1024) { // 10MB limit
        toast.error('File size must be less than 10MB');
        return;
      }
      setFile(selectedFile);
      setPreview(null);
    }
  };

  const handlePreview = async () => {
    if (!file) return;

    setIsUploading(true);
    try {
      const result = await vaultApi.importPreview(file, selectedFormat);
      setPreview(result);
    } catch (error: unknown) {
      console.error('Import preview error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to preview import');
    } finally {
      setIsUploading(false);
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

  const reset = () => {
    setFile(null);
    setPreview(null);
    setSelectedFormat('auto');
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
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative z-10 w-full max-w-4xl bg-white rounded-xl shadow-xl mx-4">
        <div className="flex items-center justify-between p-6 border-b border-slate-200">
          <h2 className="text-xl font-semibold text-slate-900">
            Import Password Manager Data
          </h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600"
          >
            ×
          </button>
        </div>

        <div className="p-6 max-h-[80vh] overflow-y-auto">
          {/* Step 1: File Upload */}
          {!preview && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Select CSV file to import
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
                        accept=".csv"
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
                    Supports 1Password, Bitwarden, and LastPass CSV exports
                  </p>
                </div>
              </div>

              <div>
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
              </div>

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
                  onClick={() => setPreview(null)}
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
        </div>
      </div>
    </div>
  );
}
