import { useEffect, useState } from 'react';
import {
  Plus,
  Trash2,
  Loader2,
  Key,
  Eye,
  EyeOff,
  Lock,
  Unlock,
  RotateCw,
  Clock,
  Copy,
  Check,
  Download,
  Pencil,
  X,
  Save,
  AlertCircle,
  Zap,
  ServerCog,
  Ban,
  ScrollText,
  ShieldCheck,
} from 'lucide-react';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from '@/lib/query-keys';
import { request } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import Layout from '@/components/Layout';
import VaultImportModal from '@/components/VaultImportModal';
import RotationManager from '@/components/RotationManager';
import {
  vaultApi,
  serviceIdentitiesApi,
  serviceIdentityKeys,
} from '@/lib/vault-types';
import type { VaultEntry, ServiceIdentity, ServiceIdentityWithKey } from '@/lib/vault-types';

function copyToClipboard(text: string) {
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).catch(() => {});
  }
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
  } catch {
    // ignore
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    copyToClipboard(text);
    setCopied(true);
    toast.success('Copied to clipboard');
    setTimeout(() => setCopied(false), 2500);
  }

  return (
    <button
      onClick={handleCopy}
      className={clsx(
        'rounded p-1 transition-all',
        copied ? 'text-emerald-500' : 'text-slate-400 hover:text-slate-600'
      )}
      title="Copy"
    >
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

function timeAgo(dateStr: string): string {
  if (!dateStr) return 'never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

function identityStatus(s: ServiceIdentity): { label: string; cls: string } {
  if (s.revoked_at) return { label: 'Revoked', cls: 'bg-rose-100 text-rose-700' };
  if (s.expires_at && new Date(s.expires_at).getTime() < Date.now())
    return { label: 'Expired', cls: 'bg-amber-100 text-amber-700' };
  return { label: 'Active', cls: 'bg-emerald-100 text-emerald-700' };
}

// Audit trail for a single identity. Separate component so the query
// only fires when the modal is open (no conditional hooks).
function IdentityAuditModal({ identity, onClose }: { identity: ServiceIdentity; onClose: () => void }) {
  const { data: entries = [], isLoading } = useQuery({
    queryKey: serviceIdentityKeys.audit(identity.id),
    queryFn: () => serviceIdentitiesApi.audit(identity.id),
  });
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4" onClick={onClose}>
      <div className="max-h-[80vh] w-full max-w-2xl overflow-hidden rounded-xl bg-white shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3">
          <div className="flex items-center gap-2">
            <ScrollText className="h-4 w-4 text-slate-500" />
            <h3 className="text-sm font-semibold text-slate-900">Audit trail: {identity.name}</h3>
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:text-slate-600">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[64vh] overflow-y-auto p-5">
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-slate-400">
              <Loader2 className="h-5 w-5 animate-spin" />
            </div>
          ) : entries.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-400">No secret-fetch activity recorded yet.</p>
          ) : (
            <ul className="space-y-2">
              {entries.map((e) => (
                <li key={e.id} className="rounded-lg border border-slate-200 px-3 py-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span
                      className={clsx(
                        'rounded px-1.5 py-0.5 font-medium',
                        e.error ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-700'
                      )}
                    >
                      {e.event}
                    </span>
                    <span className="text-slate-400">{timeAgo(e.occurred_at)}</span>
                  </div>
                  {e.secret_names?.length > 0 && (
                    <p className="mt-1 text-slate-600">
                      Secrets: <span className="font-mono text-[11px]">{e.secret_names.join(', ')}</span>
                    </p>
                  )}
                  {e.error && <p className="mt-1 text-rose-600">{e.error}</p>}
                  {e.remote_ip && <p className="mt-0.5 text-slate-400">from {e.remote_ip}</p>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

// Admin-only management surface for service identities: machine
// credentials that fetch a scoped subset of vault secrets at boot.
// The mint endpoint returns the plaintext key exactly once.
function ServiceIdentitiesCard() {
  const { isAdmin } = useAuth();
  const queryClient = useQueryClient();
  const [showMint, setShowMint] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', allowed_secrets: [] as string[], expires_in_days: '' });
  const [customSecret, setCustomSecret] = useState('');
  const [mintedKey, setMintedKey] = useState<ServiceIdentityWithKey | null>(null);
  const [keyCopied, setKeyCopied] = useState(false);
  const [auditFor, setAuditFor] = useState<ServiceIdentity | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const { data: identities = [], isLoading } = useQuery<ServiceIdentity[]>({
    queryKey: serviceIdentityKeys.list(),
    queryFn: serviceIdentitiesApi.list,
    enabled: isAdmin,
  });

  const { data: vaultList = [] } = useQuery<VaultEntry[]>({
    queryKey: queryKeys.vault.list(),
    queryFn: vaultApi.list,
    enabled: isAdmin && showMint,
  });

  const createMutation = useMutation({
    mutationFn: serviceIdentitiesApi.create,
    onSuccess: (data) => {
      setMintedKey(data);
      setShowMint(false);
      setForm({ name: '', description: '', allowed_secrets: [], expires_in_days: '' });
      setCustomSecret('');
      queryClient.invalidateQueries({ queryKey: serviceIdentityKeys.all });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const revokeMutation = useMutation({
    mutationFn: serviceIdentitiesApi.revoke,
    onSuccess: () => {
      toast.success('Identity revoked');
      queryClient.invalidateQueries({ queryKey: serviceIdentityKeys.all });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: serviceIdentitiesApi.delete,
    onSuccess: () => {
      toast.success('Identity deleted');
      setConfirmDelete(null);
      queryClient.invalidateQueries({ queryKey: serviceIdentityKeys.all });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (!isAdmin) return null;

  function toggleSecret(name: string) {
    setForm((f) => ({
      ...f,
      allowed_secrets: f.allowed_secrets.includes(name)
        ? f.allowed_secrets.filter((n) => n !== name)
        : [...f.allowed_secrets, name],
    }));
  }

  function addCustomSecret() {
    const name = customSecret.trim();
    if (!name) return;
    if (!form.allowed_secrets.includes(name)) {
      setForm((f) => ({ ...f, allowed_secrets: [...f.allowed_secrets, name] }));
    }
    setCustomSecret('');
  }

  function submitMint() {
    if (!form.name.trim()) {
      toast.error('Name is required');
      return;
    }
    if (form.allowed_secrets.length === 0) {
      toast.error('Select at least one allowed secret');
      return;
    }
    createMutation.mutate({
      name: form.name.trim(),
      description: form.description.trim(),
      allowed_secrets: form.allowed_secrets,
      expires_in_days: form.expires_in_days ? Number(form.expires_in_days) : undefined,
    });
  }

  function copyKey() {
    if (!mintedKey) return;
    copyToClipboard(mintedKey.key);
    setKeyCopied(true);
    toast.success('Key copied. Store it now, it will not be shown again.');
    setTimeout(() => setKeyCopied(false), 2500);
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
      <div className="flex items-start justify-between gap-3 border-b border-slate-100 p-5">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-slate-900">
            <ShieldCheck className="h-5 w-5 text-white" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-900">Service identities</h2>
            <p className="mt-1 max-w-2xl text-xs leading-relaxed text-slate-600">
              Machine credentials that fetch a scoped subset of vault secrets at boot. A service presents its key to{' '}
              <code className="rounded bg-slate-100 px-1 font-mono text-[11px] text-slate-700">/api/service-identities/me/secrets</code>{' '}
              and receives only the secrets you allow. Keys start with{' '}
              <code className="rounded bg-slate-100 px-1 font-mono text-[11px] text-slate-700">sk_</code> and are shown once.
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowMint((v) => !v)}
          className="inline-flex flex-shrink-0 items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-700"
        >
          <Plus className="h-3.5 w-3.5" /> Mint identity
        </button>
      </div>

      {showMint && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submitMint();
          }}
          className="space-y-3 border-b border-slate-100 bg-slate-50 p-5"
        >
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Name</label>
              <input
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="ci-deployer"
                className="w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-900 focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Expires in (days, optional)</label>
              <input
                type="number"
                min="1"
                value={form.expires_in_days}
                onChange={(e) => setForm((f) => ({ ...f, expires_in_days: e.target.value }))}
                placeholder="never"
                className="w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-900 focus:outline-none"
              />
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700">Description (optional)</label>
            <input
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              placeholder="What boots with this identity"
              className="w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-900 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700">
              Allowed secrets <span className="text-slate-400">({form.allowed_secrets.length} selected)</span>
            </label>
            {vaultList.length > 0 && (
              <div className="mb-2 flex flex-wrap gap-1.5">
                {vaultList.map((v) => (
                  <button
                    key={v.id}
                    type="button"
                    onClick={() => toggleSecret(v.name)}
                    className={clsx(
                      'rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors',
                      form.allowed_secrets.includes(v.name)
                        ? 'border-slate-900 bg-slate-900 text-white'
                        : 'border-slate-300 bg-white text-slate-600 hover:border-slate-400'
                    )}
                  >
                    {v.name}
                  </button>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <input
                value={customSecret}
                onChange={(e) => setCustomSecret(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addCustomSecret();
                  }
                }}
                placeholder="Add a secret name not yet in the vault"
                className="flex-1 rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-900 focus:outline-none"
              />
              <button
                type="button"
                onClick={addCustomSecret}
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-600 hover:border-slate-400"
              >
                Add
              </button>
            </div>
            {form.allowed_secrets.some((n) => !vaultList.find((v) => v.name === n)) && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {form.allowed_secrets
                  .filter((n) => !vaultList.find((v) => v.name === n))
                  .map((n) => (
                    <span
                      key={n}
                      className="inline-flex items-center gap-1 rounded-full border border-slate-900 bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-white"
                    >
                      {n}
                      <button type="button" onClick={() => toggleSecret(n)} className="hover:text-slate-300">
                        <X className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
              </div>
            )}
          </div>
          <div className="flex items-center gap-2 pt-1">
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-700 disabled:opacity-50"
            >
              {createMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Key className="h-3.5 w-3.5" />}
              Mint and reveal key
            </button>
            <button
              type="button"
              onClick={() => setShowMint(false)}
              className="rounded-lg px-3 py-1.5 text-xs font-medium text-slate-500 hover:text-slate-700"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="p-5">
        {isLoading ? (
          <div className="flex items-center justify-center py-8 text-slate-400">
            <Loader2 className="h-5 w-5 animate-spin" />
          </div>
        ) : identities.length === 0 ? (
          <p className="py-6 text-center text-sm text-slate-400">
            No service identities yet. Mint one to let a service fetch its secrets at boot.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-[11px] uppercase tracking-wide text-slate-400">
                  <th className="pb-2 pr-3 font-medium">Name</th>
                  <th className="pb-2 pr-3 font-medium">Key</th>
                  <th className="pb-2 pr-3 font-medium">Secrets</th>
                  <th className="pb-2 pr-3 font-medium">Last used</th>
                  <th className="pb-2 pr-3 font-medium">Expires</th>
                  <th className="pb-2 pr-3 font-medium">Status</th>
                  <th className="pb-2 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {identities.map((s) => {
                  const st = identityStatus(s);
                  return (
                    <tr key={s.id} className="text-slate-700">
                      <td className="py-2.5 pr-3">
                        <div className="font-medium text-slate-900">{s.name}</div>
                        {s.description && <div className="text-xs text-slate-400">{s.description}</div>}
                      </td>
                      <td className="py-2.5 pr-3">
                        <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">
                          sk_{s.key_prefix}…
                        </code>
                      </td>
                      <td className="py-2.5 pr-3" title={s.allowed_secrets.join(', ')}>
                        {s.allowed_secrets.length}
                      </td>
                      <td className="py-2.5 pr-3 text-xs text-slate-500">{s.last_used_at ? timeAgo(s.last_used_at) : 'never'}</td>
                      <td className="py-2.5 pr-3 text-xs text-slate-500">
                        {s.expires_at ? new Date(s.expires_at).toLocaleDateString() : 'never'}
                      </td>
                      <td className="py-2.5 pr-3">
                        <span className={clsx('rounded-full px-2 py-0.5 text-[11px] font-medium', st.cls)}>{st.label}</span>
                      </td>
                      <td className="py-2.5">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => setAuditFor(s)}
                            title="Audit trail"
                            className="rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
                          >
                            <ScrollText className="h-4 w-4" />
                          </button>
                          {!s.revoked_at && (
                            <button
                              onClick={() => revokeMutation.mutate(s.id)}
                              disabled={revokeMutation.isPending}
                              title="Revoke (key stops working immediately)"
                              className="rounded p-1.5 text-slate-400 hover:bg-amber-50 hover:text-amber-600 disabled:opacity-50"
                            >
                              <Ban className="h-4 w-4" />
                            </button>
                          )}
                          {confirmDelete === s.id ? (
                            <span className="flex items-center gap-1">
                              <button
                                onClick={() => deleteMutation.mutate(s.id)}
                                disabled={deleteMutation.isPending}
                                className="rounded bg-rose-600 px-2 py-1 text-[11px] font-medium text-white hover:bg-rose-700 disabled:opacity-50"
                              >
                                Confirm
                              </button>
                              <button
                                onClick={() => setConfirmDelete(null)}
                                className="rounded px-1.5 py-1 text-[11px] text-slate-500 hover:text-slate-700"
                              >
                                Cancel
                              </button>
                            </span>
                          ) : (
                            <button
                              onClick={() => setConfirmDelete(s.id)}
                              title="Delete permanently"
                              className="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-600"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {mintedKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4">
          <div className="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl">
            <div className="mb-3 flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-100">
                <Key className="h-4.5 w-4.5 text-emerald-600" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-900">Identity minted: {mintedKey.name}</h3>
                <p className="text-xs text-slate-500">Copy this key now. It is not stored and cannot be shown again.</p>
              </div>
            </div>
            <div className="mb-3 flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-900 px-3 py-2.5">
              <code className="flex-1 break-all font-mono text-[11px] text-emerald-300">{mintedKey.key}</code>
              <button
                onClick={copyKey}
                className={clsx(
                  'flex flex-shrink-0 items-center gap-1.5 rounded px-2 py-1 text-[11px] font-medium transition-colors',
                  keyCopied ? 'bg-emerald-500/20 text-emerald-300' : 'bg-white/10 text-slate-200 hover:bg-white/20'
                )}
              >
                {keyCopied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                {keyCopied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div className="mb-4 flex items-start gap-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
              <span>
                Allowed secrets: <span className="font-mono">{mintedKey.allowed_secrets.join(', ')}</span>
              </span>
            </div>
            <div className="flex justify-end">
              <button
                onClick={() => {
                  setMintedKey(null);
                  setKeyCopied(false);
                }}
                className="rounded-lg bg-slate-900 px-4 py-1.5 text-xs font-medium text-white hover:bg-slate-700"
              >
                I've stored it
              </button>
            </div>
          </div>
        </div>
      )}

      {auditFor && <IdentityAuditModal identity={auditFor} onClose={() => setAuditFor(null)} />}
    </div>
  );
}

export default function Vault() {
  const queryClient = useQueryClient();

  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  // Team vault policy drives the auto-lock timer below.
  const { data: vaultPolicy } = useQuery({
    queryKey: queryKeys.settings.vaultPolicy(),
    queryFn: () => request<{ auto_lock_minutes: number }>('/settings/vault-policy'),
  });
  const [vaultPassword, setVaultPassword] = useState('');
  const [vaultEntries, setVaultEntries] = useState<VaultEntry[]>([]);
  const [showAddSecret, setShowAddSecret] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [newSecret, setNewSecret] = useState({ name: '', value: '', url: '', alias_url: '', username: '', category: '', notes: '', rotation_interval_days: '', expires_at: '' });
  const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set());
  const [rotatedValue, setRotatedValue] = useState<{ id: string; value: string } | null>(null);
  const [editingEntryId, setEditingEntryId] = useState<string | null>(null);
  const [rotatingEntryId, setRotatingEntryId] = useState<string | null>(null);
  const [rotationPanelId, setRotationPanelId] = useState<string | null>(null);
  const [rotatePassword, setRotatePassword] = useState('');
  const [editForm, setEditForm] = useState({ name: '', value: '', url: '', alias_url: '', username: '', category: '', notes: '', rotation_interval_days: '', expires_at: '' });

  const { data: vaultList = [], isLoading: vaultLoading } = useQuery<VaultEntry[]>({
    queryKey: queryKeys.vault.list(),
    queryFn: vaultApi.list,
  });

  // Auto-lock: drop the decrypted entries after the policy's
  // auto_lock_minutes (GET /api/settings/vault-policy). The values only live
  // in memory, so re-locking is just clearing state.
  useEffect(() => {
    if (!vaultUnlocked) return;
    const minutes = vaultPolicy?.auto_lock_minutes ?? 15;
    const timer = setTimeout(() => {
      setVaultUnlocked(false);
      setVaultEntries([]);
      setRevealedSecrets(new Set());
      setRotatedValue(null);
      toast('Vault locked automatically', { icon: '🔒' });
    }, minutes * 60_000);
    return () => clearTimeout(timer);
  }, [vaultUnlocked, vaultPolicy?.auto_lock_minutes]);

  const unlockVaultMutation = useMutation({
    mutationFn: (password: string) => vaultApi.unlock(password),
    onSuccess: (data: VaultEntry[]) => {
      setVaultUnlocked(true);
      setVaultEntries(data);
      setVaultPassword('');
      toast.success('Vault unlocked');
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const createSecretMutation = useMutation({
    mutationFn: vaultApi.create,
    onSuccess: () => {
      toast.success('Secret added to vault');
      setNewSecret({ name: '', value: '', url: '', alias_url: '', username: '', category: '', notes: '', rotation_interval_days: '', expires_at: '' });
      setShowAddSecret(false);
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
      setVaultUnlocked(false);
      setVaultEntries([]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteSecretMutation = useMutation({
    mutationFn: vaultApi.delete,
    onSuccess: () => {
      toast.success('Secret deleted');
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
      setVaultUnlocked(false);
      setVaultEntries([]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const rotateSecretMutation = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) => vaultApi.rotate(id, password),
    onSuccess: (data) => {
      setRotatedValue({ id: data.id, value: data.value ?? '' });
      toast.success('Secret rotated');
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const updateSecretMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof vaultApi.update>[1] }) =>
      vaultApi.update(id, data),
    onSuccess: () => {
      toast.success('Secret updated');
      setEditingEntryId(null);
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
      setVaultUnlocked(false);
      setVaultEntries([]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  function startEditing(entry: VaultEntry) {
    setEditingEntryId(entry.id);
    setEditForm({
      name: entry.name,
      value: entry.value || '',
      url: entry.url || '',
      alias_url: entry.alias_url || '',
      username: entry.username || '',
      category: entry.category || '',
      notes: entry.notes || '',
      rotation_interval_days: entry.rotation_interval_days?.toString() || '',
      expires_at: entry.expires_at ? entry.expires_at.split('T')[0] : '',
    });
  }

  function submitEdit(entryId: string) {
    const data: Parameters<typeof vaultApi.update>[1] = {};
    if (editForm.name) data.name = editForm.name;
    if (editForm.value) data.value = editForm.value;
    data.url = editForm.url;
    data.alias_url = editForm.alias_url;
    data.username = editForm.username;
    data.category = editForm.category;
    data.notes = editForm.notes;
    data.rotation_interval_days = editForm.rotation_interval_days ? Number(editForm.rotation_interval_days) : null;
    data.expires_at = editForm.expires_at || null;
    updateSecretMutation.mutate({ id: entryId, data });
  }

  return (
    <Layout>
      <div className="mb-6">
        <h1 data-testid="page-vault" className="text-xl font-semibold text-slate-900">Vault</h1>
        <p className="text-sm text-slate-500">
          Encrypted secret storage with rotation tracking
        </p>
      </div>

      <div className="space-y-6">
        {/* Service identities: machine credentials that fetch a scoped set
            of vault secrets at boot. Admin-only; renders null otherwise. */}
        <ServiceIdentitiesCard />

        {/* Unlock / Lock bar */}
        {!vaultUnlocked ? (
          <div className="rounded-xl border border-slate-200 bg-white p-6">
            <div className="mx-auto max-w-sm text-center">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100">
                <Lock className="h-6 w-6 text-slate-500" />
              </div>
              <h3 className="mb-1 text-sm font-semibold text-slate-900">
                Vault is locked
              </h3>
              <p className="mb-4 text-xs text-slate-500">
                Enter your password to unlock and view encrypted secrets.
              </p>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  unlockVaultMutation.mutate(vaultPassword);
                }}
                className="flex gap-2"
              >
                <input
                  type="password"
                  value={vaultPassword}
                  onChange={(e) => setVaultPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                />
                <button
                  type="submit"
                  disabled={unlockVaultMutation.isPending}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-4 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
                >
                  {unlockVaultMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Unlock className="h-3.5 w-3.5" />
                  )}
                  Unlock
                </button>
              </form>
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-between rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-2.5">
            <div className="flex items-center gap-2">
              <Unlock className="h-4 w-4 text-emerald-600" />
              <span className="text-sm font-medium text-emerald-800">
                Vault unlocked
              </span>
            </div>
            <button
              onClick={() => {
                setVaultUnlocked(false);
                setVaultEntries([]);
                setRotatedValue(null);
              }}
              className="flex items-center gap-1.5 rounded-lg border border-emerald-300 bg-white px-3 py-1 text-xs font-medium text-emerald-700 hover:bg-emerald-50"
            >
              <Lock className="h-3 w-3" />
              Lock
            </button>
          </div>
        )}

        {/* Rotated value banner */}
        {rotatedValue && (
          <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
            <div className="mb-2 flex items-center gap-2">
              <RotateCw className="h-4 w-4 text-blue-600" />
              <h3 className="text-sm font-semibold text-blue-900">
                New Secret Value
              </h3>
            </div>
            <p className="mb-3 text-xs text-blue-700">
              Copy this value now. It will not be shown again after you dismiss
              this banner.
            </p>
            <div className="flex items-center gap-2 rounded-lg bg-white p-3 font-mono text-xs">
              <code className="flex-1 break-all text-slate-900">
                {rotatedValue.value}
              </code>
              <CopyButton text={rotatedValue.value} />
            </div>
            <button
              onClick={() => setRotatedValue(null)}
              className="mt-3 text-xs font-medium text-blue-700 hover:text-blue-900"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Add secret form */}
        {vaultUnlocked && (
          <div className="rounded-xl border border-slate-200 bg-white p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 text-slate-500" />
                <h3 className="text-sm font-semibold text-slate-900">
                  Secrets
                </h3>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowAddSecret(!showAddSecret)}
                  className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Add secret
                </button>
                <button
                  onClick={() => setShowImportModal(true)}
                  className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  <Download className="h-3.5 w-3.5" />
                  Import CSV
                </button>
              </div>
            </div>

            {showAddSecret && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  createSecretMutation.mutate({
                    name: newSecret.name,
                    value: newSecret.value,
                    url: newSecret.url || undefined,
                    alias_url: newSecret.alias_url || undefined,
                    username: newSecret.username || undefined,
                    category: newSecret.category || undefined,
                    notes: newSecret.notes || undefined,
                    rotation_interval_days: newSecret.rotation_interval_days ? Number(newSecret.rotation_interval_days) : undefined,
                    expires_at: newSecret.expires_at || undefined,
                  });
                }}
                className="mb-4 space-y-3 rounded-lg border border-slate-100 bg-slate-50 p-4"
              >
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-slate-600">
                      Name *
                    </label>
                    <input
                      type="text"
                      value={newSecret.name}
                      onChange={(e) => setNewSecret({ ...newSecret, name: e.target.value })}
                      placeholder="e.g. DB_PASSWORD"
                      required
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs font-medium text-slate-600">
                      Category
                    </label>
                    <select
                      value={newSecret.category}
                      onChange={(e) => setNewSecret({ ...newSecret, category: e.target.value })}
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                    >
                      <option value="">None</option>
                      <option value="login">Login</option>
                      <option value="password">Password</option>
                      <option value="api_key">API Key</option>
                      <option value="database">Database</option>
                      <option value="certificate">Certificate</option>
                      <option value="other">Other</option>
                    </select>
                  </div>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-slate-600">
                      URL
                    </label>
                    <input
                      type="text"
                      value={newSecret.url}
                      onChange={(e) => setNewSecret({ ...newSecret, url: e.target.value })}
                      placeholder="e.g. https://github.com"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs font-medium text-slate-600">
                      Alias URL
                    </label>
                    <input
                      type="text"
                      value={newSecret.alias_url}
                      onChange={(e) => setNewSecret({ ...newSecret, alias_url: e.target.value })}
                      placeholder="e.g. https://dev.github.com"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                    />
                  </div>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-600">
                    Username
                  </label>
                  <input
                    type="text"
                    value={newSecret.username}
                    onChange={(e) => setNewSecret({ ...newSecret, username: e.target.value })}
                    placeholder="e.g. admin@example.com"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-600">
                    Value *
                  </label>
                  <input
                    type="text"
                    value={newSecret.value}
                    onChange={(e) => setNewSecret({ ...newSecret, value: e.target.value })}
                    placeholder="Secret value"
                    required
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-mono outline-none focus:border-slate-400"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-600">
                    Notes
                  </label>
                  <input
                    type="text"
                    value={newSecret.notes}
                    onChange={(e) => setNewSecret({ ...newSecret, notes: e.target.value })}
                    placeholder="Optional description"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-slate-600">
                      Rotation interval (days)
                    </label>
                    <input
                      type="number"
                      value={newSecret.rotation_interval_days}
                      onChange={(e) => setNewSecret({ ...newSecret, rotation_interval_days: e.target.value })}
                      placeholder="e.g. 90"
                      min="1"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs font-medium text-slate-600">
                      Expiry date
                    </label>
                    <input
                      type="date"
                      value={newSecret.expires_at}
                      onChange={(e) => setNewSecret({ ...newSecret, expires_at: e.target.value })}
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    type="submit"
                    disabled={createSecretMutation.isPending}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
                  >
                    {createSecretMutation.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Plus className="h-3.5 w-3.5" />
                    )}
                    Add secret
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowAddSecret(false)}
                    className="rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}

            {/* Secrets list (unlocked with values) */}
            {vaultEntries.length === 0 ? (
              <p className="py-4 text-center text-sm text-slate-500">
                No secrets in the vault yet. Add one to get started.
              </p>
            ) : (
              <div className="space-y-2">
                {vaultEntries.map((entry) => (
                  <div
                    key={entry.id}
                    className="rounded-lg border border-slate-100 bg-slate-50 p-3"
                  >
                    {editingEntryId === entry.id ? (
                      /* Edit form */
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          submitEdit(entry.id);
                        }}
                        className="space-y-3"
                      >
                        <div className="grid gap-3 sm:grid-cols-2">
                          <div>
                            <label className="mb-1 block text-xs font-medium text-slate-600">Name</label>
                            <input
                              type="text"
                              value={editForm.name}
                              onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                              required
                              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                            />
                          </div>
                          <div>
                            <label className="mb-1 block text-xs font-medium text-slate-600">Category</label>
                            <select
                              value={editForm.category}
                              onChange={(e) => setEditForm({ ...editForm, category: e.target.value })}
                              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                            >
                              <option value="">None</option>
                              <option value="login">Login</option>
                              <option value="password">Password</option>
                              <option value="api_key">API Key</option>
                              <option value="database">Database</option>
                              <option value="certificate">Certificate</option>
                              <option value="other">Other</option>
                            </select>
                          </div>
                        </div>
                        <div className="grid gap-3 sm:grid-cols-2">
                          <div>
                            <label className="mb-1 block text-xs font-medium text-slate-600">URL</label>
                            <input
                              type="text"
                              value={editForm.url}
                              onChange={(e) => setEditForm({ ...editForm, url: e.target.value })}
                              placeholder="https://example.com"
                              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                            />
                          </div>
                          <div>
                            <label className="mb-1 block text-xs font-medium text-slate-600">Alias URL</label>
                            <input
                              type="text"
                              value={editForm.alias_url}
                              onChange={(e) => setEditForm({ ...editForm, alias_url: e.target.value })}
                              placeholder="https://dev.example.com"
                              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                            />
                          </div>
                        </div>
                        <div>
                          <label className="mb-1 block text-xs font-medium text-slate-600">Username</label>
                          <input
                            type="text"
                            value={editForm.username}
                            onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
                            placeholder="admin@example.com"
                            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                          />
                        </div>
                        <div>
                          <label className="mb-1 block text-xs font-medium text-slate-600">
                            Value <span className="font-normal text-slate-400">(leave blank to keep current)</span>
                          </label>
                          <input
                            type="text"
                            value={editForm.value}
                            onChange={(e) => setEditForm({ ...editForm, value: e.target.value })}
                            placeholder="Enter new value to change"
                            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-mono outline-none focus:border-slate-400"
                          />
                        </div>
                        <div>
                          <label className="mb-1 block text-xs font-medium text-slate-600">Notes</label>
                          <input
                            type="text"
                            value={editForm.notes}
                            onChange={(e) => setEditForm({ ...editForm, notes: e.target.value })}
                            placeholder="Optional description"
                            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                          />
                        </div>
                        <div className="grid gap-3 sm:grid-cols-2">
                          <div>
                            <label className="mb-1 block text-xs font-medium text-slate-600">Rotation interval (days)</label>
                            <input
                              type="number"
                              value={editForm.rotation_interval_days}
                              onChange={(e) => setEditForm({ ...editForm, rotation_interval_days: e.target.value })}
                              placeholder="e.g. 90"
                              min="1"
                              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                            />
                          </div>
                          <div>
                            <label className="mb-1 block text-xs font-medium text-slate-600">Expiry date</label>
                            <input
                              type="date"
                              value={editForm.expires_at}
                              onChange={(e) => setEditForm({ ...editForm, expires_at: e.target.value })}
                              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                            />
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <button
                            type="submit"
                            disabled={updateSecretMutation.isPending}
                            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
                          >
                            {updateSecretMutation.isPending ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <Save className="h-3.5 w-3.5" />
                            )}
                            Save
                          </button>
                          <button
                            type="button"
                            onClick={() => setEditingEntryId(null)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50"
                          >
                            <X className="h-3.5 w-3.5" />
                            Cancel
                          </button>
                        </div>
                      </form>
                    ) : (
                      /* Display view */
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-slate-900">
                              {entry.name}
                            </span>
                            {entry.category && (
                              <span className="rounded-full bg-slate-200 px-2 py-0.5 text-xs text-slate-600">
                                {entry.category}
                              </span>
                            )}
                            <span
                              className={clsx(
                                'rounded-full px-2 py-0.5 text-xs font-medium',
                                entry.rotation_status === 'fresh' && 'bg-emerald-100 text-emerald-700',
                                entry.rotation_status === 'due_soon' && 'bg-amber-100 text-amber-700',
                                entry.rotation_status === 'overdue' && 'bg-red-100 text-red-700',
                                entry.rotation_status === 'expired' && 'bg-red-100 text-red-700'
                              )}
                            >
                              {entry.rotation_status === 'fresh' && 'Fresh'}
                              {entry.rotation_status === 'due_soon' && 'Due Soon'}
                              {entry.rotation_status === 'overdue' && 'Overdue'}
                              {entry.rotation_status === 'expired' && 'Expired'}
                            </span>
                            {entry.provider && entry.provider !== 'manual' && (
                              <span
                                className="rounded-full bg-indigo-50 px-2 py-0.5 text-xs font-medium text-indigo-700"
                                title={`Rotation provider: ${entry.provider}`}
                              >
                                {entry.provider}
                              </span>
                            )}
                            {entry.auto_rotate && (
                              <span
                                className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700"
                                title={
                                  entry.rotation_interval_days
                                    ? `Auto-rotates every ${entry.rotation_interval_days} days`
                                    : 'Auto-rotation enabled'
                                }
                              >
                                <Zap className="h-3 w-3" />
                                Auto
                              </span>
                            )}
                            {entry.last_rotation_error && (
                              <span
                                className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700"
                                title={entry.last_rotation_error}
                              >
                                <AlertCircle className="h-3 w-3" />
                                Rotation error
                              </span>
                            )}
                          </div>
                          {(entry.url || entry.alias_url || entry.username) && (
                            <div className="mt-0.5 flex items-center gap-3 text-xs text-slate-500">
                              {entry.url && <span>{entry.url}</span>}
                              {entry.alias_url && <span className="text-slate-400">| {entry.alias_url}</span>}
                              {entry.username && <span className="font-mono">{entry.username}</span>}
                            </div>
                          )}
                          {entry.notes && (
                            <p className="mt-0.5 text-xs text-slate-500">
                              {entry.notes}
                            </p>
                          )}
                          <div className="mt-2 flex items-center gap-2">
                            <div className="flex-1 rounded bg-white px-2 py-1 font-mono text-xs text-slate-700">
                              {revealedSecrets.has(entry.id) ? entry.value : '••••••••••••'}
                            </div>
                            <button
                              onClick={() => {
                                const next = new Set(revealedSecrets);
                                if (next.has(entry.id)) next.delete(entry.id);
                                else next.add(entry.id);
                                setRevealedSecrets(next);
                              }}
                              className="rounded p-1 text-slate-400 hover:text-slate-600"
                              title={revealedSecrets.has(entry.id) ? 'Hide' : 'Reveal'}
                            >
                              {revealedSecrets.has(entry.id) ? (
                                <EyeOff className="h-3.5 w-3.5" />
                              ) : (
                                <Eye className="h-3.5 w-3.5" />
                              )}
                            </button>
                            {entry.value && <CopyButton text={entry.value} />}
                          </div>
                          <div className="mt-1.5 flex items-center gap-3 text-xs text-slate-400">
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              Rotated {timeAgo(entry.last_rotated_at)}
                            </span>
                            {entry.rotation_interval_days && (
                              <span>Every {entry.rotation_interval_days}d</span>
                            )}
                            {entry.expires_at && (
                              <span>Expires {new Date(entry.expires_at).toLocaleDateString()}</span>
                            )}
                          </div>
                        </div>
                        <div className="ml-2 flex items-center gap-1">
                          <button
                            onClick={() => startEditing(entry)}
                            className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-white hover:text-slate-600"
                            title="Edit entry"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => {
                              setRotatingEntryId(rotatingEntryId === entry.id ? null : entry.id);
                              setRotatePassword('');
                            }}
                            disabled={rotateSecretMutation.isPending}
                            className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-white hover:text-slate-600"
                            title="Rotate secret"
                          >
                            <RotateCw className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setRotationPanelId(rotationPanelId === entry.id ? null : entry.id)}
                            className={clsx(
                              'rounded-lg p-1.5 transition-colors hover:bg-white',
                              rotationPanelId === entry.id ? 'text-slate-700' : 'text-slate-400 hover:text-slate-600'
                            )}
                            title="Manage rotation delivery"
                          >
                            <ServerCog className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => {
                              if (window.confirm(`Delete secret "${entry.name}"? This cannot be undone.`)) {
                                deleteSecretMutation.mutate(entry.id);
                              }
                            }}
                            disabled={deleteSecretMutation.isPending}
                            className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-white hover:text-red-500"
                            title="Delete secret"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </div>
                    )}
                    {rotatingEntryId === entry.id && (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          if (rotatePassword) {
                            rotateSecretMutation.mutate({ id: entry.id, password: rotatePassword });
                            setRotatingEntryId(null);
                            setRotatePassword('');
                          }
                        }}
                        className="mt-2 flex items-center gap-2"
                      >
                        <input
                          type="password"
                          value={rotatePassword}
                          onChange={(e) => setRotatePassword(e.target.value)}
                          placeholder="Enter your password"
                          autoFocus
                          className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                        />
                        <button
                          type="submit"
                          disabled={!rotatePassword || rotateSecretMutation.isPending}
                          className="rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
                        >
                          Rotate
                        </button>
                        <button
                          type="button"
                          onClick={() => { setRotatingEntryId(null); setRotatePassword(''); }}
                          className="rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50"
                        >
                          Cancel
                        </button>
                      </form>
                    )}
                    {rotationPanelId === entry.id && <RotationManager entry={entry} />}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Metadata-only list when locked */}
        {!vaultUnlocked && (
          <div className="rounded-xl border border-slate-200 bg-white p-4">
            <div className="mb-3 flex items-center gap-2">
              <Key className="h-4 w-4 text-slate-500" />
              <h3 className="text-sm font-semibold text-slate-900">
                Stored Secrets
              </h3>
            </div>
            {vaultLoading ? (
              <div className="flex items-center justify-center py-6">
                <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
              </div>
            ) : vaultList.length === 0 ? (
              <p className="py-4 text-center text-sm text-slate-500">
                No secrets stored. Unlock the vault and add your first secret.
              </p>
            ) : (
              <div className="overflow-hidden rounded-lg border border-slate-100">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 bg-slate-50">
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Name</th>
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Category</th>
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Status</th>
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Last rotated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vaultList.map((entry) => (
                      <tr key={entry.id} className="border-b border-slate-50 last:border-0">
                        <td className="px-3 py-2 text-sm font-medium text-slate-900">{entry.name}</td>
                        <td className="px-3 py-2 text-xs text-slate-500">{entry.category || '-'}</td>
                        <td className="px-3 py-2">
                          <span
                            className={clsx(
                              'rounded-full px-2 py-0.5 text-xs font-medium',
                              entry.rotation_status === 'fresh' && 'bg-emerald-100 text-emerald-700',
                              entry.rotation_status === 'due_soon' && 'bg-amber-100 text-amber-700',
                              entry.rotation_status === 'overdue' && 'bg-red-100 text-red-700',
                              entry.rotation_status === 'expired' && 'bg-red-100 text-red-700'
                            )}
                          >
                            {entry.rotation_status === 'fresh' && 'Fresh'}
                            {entry.rotation_status === 'due_soon' && 'Due Soon'}
                            {entry.rotation_status === 'overdue' && 'Overdue'}
                            {entry.rotation_status === 'expired' && 'Expired'}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-xs text-slate-500">{timeAgo(entry.last_rotated_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Import Modal */}
      <VaultImportModal
        isOpen={showImportModal}
        onClose={() => setShowImportModal(false)}
        onImportComplete={() => {
          setVaultUnlocked(false);
          setVaultEntries([]);
          queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
        }}
      />
    </Layout>
  );
}
