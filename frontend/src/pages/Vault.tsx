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
  Folder,
  FolderPlus,
  Users,
  UserPlus,
  LogOut,
  Database,
} from 'lucide-react';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from '@/lib/query-keys';
import { api, request, ApiError } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import Layout from '@/components/Layout';
import VaultImportModal from '@/components/VaultImportModal';
import RotationManager from '@/components/RotationManager';
import {
  vaultApi,
  serviceIdentitiesApi,
  serviceIdentityKeys,
} from '@/lib/vault-types';
import type { VaultEntry, ServiceIdentity, ServiceIdentityWithKey, CustomField } from '@/lib/vault-types';
import type {
  Collection,
  CollectionMember,
  CollectionRole,
  PendingInvite,
} from '@/lib/types';

// Seconds after which a copied secret is cleared from the clipboard, matching
// the behaviour of dedicated password managers so a secret does not linger.
const CLIPBOARD_CLEAR_SECONDS = 20;

// Same helper the other pages use: prefer the server's error text (ApiError
// carries the parsed body), fall back to a neutral message.
function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return 'Something went wrong';
}

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

  // Auto-clear: only wipe if the clipboard still holds the value we wrote, so we
  // never clobber something the user copied elsewhere in the meantime.
  if (navigator.clipboard?.writeText && navigator.clipboard?.readText) {
    window.setTimeout(() => {
      navigator.clipboard
        .readText()
        .then((current) => {
          if (current === text) {
            navigator.clipboard.writeText('').catch(() => {});
          }
        })
        .catch(() => {});
    }, CLIPBOARD_CLEAR_SECONDS * 1000);
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

// Labels a "database" entry gets pre-filled with, so DB credentials use the
// same custom-fields mechanism as everything else but arrive structured.
const DB_PRESET_LABELS = ['Host', 'Port', 'Database', 'SSL mode'];

// Drop rows with no label and trim what remains, so blank editor rows never
// reach the API. The value is kept as typed (may be intentionally empty).
function cleanCustomFields(fields: CustomField[]): CustomField[] {
  return fields
    .filter((f) => f.label.trim() !== '')
    .map((f) => ({ label: f.label.trim(), value: f.value, secret: f.secret }));
}

// Editable list of custom fields used inside both the add and edit forms. Each
// row is a label + value + a "secret" masking flag. Secret values render as a
// password input with a per-row show/hide toggle. The "Add database fields"
// button only shows for the database category and never duplicates a label.
function CustomFieldsEditor({
  fields,
  onChange,
  category,
}: {
  fields: CustomField[];
  onChange: (fields: CustomField[]) => void;
  category: string;
}) {
  const [shown, setShown] = useState<Set<number>>(new Set());

  function toggleShown(index: number) {
    setShown((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  function updateField(index: number, patch: Partial<CustomField>) {
    onChange(fields.map((f, i) => (i === index ? { ...f, ...patch } : f)));
  }

  function addField() {
    onChange([...fields, { label: '', value: '', secret: false }]);
  }

  function removeField(index: number) {
    onChange(fields.filter((_, i) => i !== index));
    // Reindex the local show/hide set so later rows keep their visibility.
    setShown((prev) => {
      const next = new Set<number>();
      prev.forEach((i) => {
        if (i < index) next.add(i);
        else if (i > index) next.add(i - 1);
      });
      return next;
    });
  }

  function addDatabaseFields() {
    const existing = new Set(fields.map((f) => f.label.trim().toLowerCase()));
    const additions = DB_PRESET_LABELS.filter(
      (label) => !existing.has(label.toLowerCase())
    ).map((label) => ({ label, value: '', secret: false }));
    if (additions.length > 0) onChange([...fields, ...additions]);
  }

  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <label className="block text-xs font-medium text-slate-600">Custom fields</label>
        {category === 'database' && (
          <button
            type="button"
            onClick={addDatabaseFields}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-2.5 py-1 text-xs font-medium text-slate-600 hover:bg-slate-50"
          >
            <Database className="h-3 w-3" />
            Add database fields
          </button>
        )}
      </div>
      {fields.length > 0 && (
        <div className="space-y-2">
          {fields.map((field, index) => {
            const visible = !field.secret || shown.has(index);
            return (
              <div key={index} className="flex items-center gap-2">
                <input
                  type="text"
                  value={field.label}
                  onChange={(e) => updateField(index, { label: e.target.value })}
                  placeholder="Label"
                  className="w-1/3 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                />
                <div className="relative flex-1">
                  <input
                    type={field.secret && !visible ? 'password' : 'text'}
                    value={field.value}
                    onChange={(e) => updateField(index, { value: e.target.value })}
                    placeholder="Value"
                    className={clsx(
                      'w-full rounded-lg border border-slate-200 bg-white py-1.5 pl-3 text-sm outline-none focus:border-slate-400',
                      field.secret ? 'pr-9 font-mono' : 'pr-3'
                    )}
                  />
                  {field.secret && (
                    <button
                      type="button"
                      onClick={() => toggleShown(index)}
                      className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:text-slate-600"
                      title={visible ? 'Hide value' : 'Show value'}
                    >
                      {visible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => updateField(index, { secret: !field.secret })}
                  className={clsx(
                    'rounded-lg border p-1.5 transition-colors',
                    field.secret
                      ? 'border-slate-900 bg-slate-900 text-white'
                      : 'border-slate-200 text-slate-400 hover:text-slate-600'
                  )}
                  title={field.secret ? 'Value is hidden (click to show as a plain field)' : 'Hide this value'}
                >
                  {field.secret ? <Lock className="h-3.5 w-3.5" /> : <Unlock className="h-3.5 w-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => removeField(index)}
                  className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-white hover:text-red-500"
                  title="Remove field"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      )}
      <button
        type="button"
        onClick={addField}
        className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50"
      >
        <Plus className="h-3.5 w-3.5" />
        Add field
      </button>
    </div>
  );
}

// Read-only render of an unlocked entry's custom fields. Secret values stay
// masked behind a per-row show/hide toggle; every value gets a CopyButton with
// the same auto-clear behaviour as the main secret value.
function CustomFieldsDisplay({ fields }: { fields: CustomField[] }) {
  const [shown, setShown] = useState<Set<number>>(new Set());
  if (fields.length === 0) return null;

  function toggleShown(index: number) {
    setShown((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  return (
    <div className="mt-2 space-y-1.5">
      {fields.map((field, index) => {
        const visible = !field.secret || shown.has(index);
        return (
          <div key={index} className="flex items-center gap-2 text-xs">
            <span
              className="w-1/4 min-w-[72px] flex-shrink-0 truncate font-medium text-slate-500"
              title={field.label}
            >
              {field.label}
            </span>
            <div className="flex-1 break-all rounded bg-white px-2 py-1 font-mono text-slate-700">
              {visible ? field.value : '••••••••••••'}
            </div>
            {field.secret && (
              <button
                onClick={() => toggleShown(index)}
                className="rounded p-1 text-slate-400 hover:text-slate-600"
                title={visible ? 'Hide' : 'Reveal'}
              >
                {visible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </button>
            )}
            <CopyButton text={field.value} />
          </div>
        );
      })}
    </div>
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

const COLLECTION_ROLES: CollectionRole[] = ['viewer', 'editor', 'manager'];

// Invitations waiting on the current user. Collection membership is consent
// based: being added grants nothing until the invitee accepts, so without this
// card an invited user would never see the collection at all. Renders null when
// there is nothing pending, so it never nags.
function PendingInvitesCard() {
  const queryClient = useQueryClient();

  const { data: invites = [] } = useQuery<PendingInvite[]>({
    queryKey: queryKeys.collections.pendingInvites(),
    queryFn: api.collections.listPendingInvites,
  });

  // Accepting adds a collection and its entries to the vault; declining keeps
  // them out. Both change every list on this page, so refresh all three.
  function refreshAfterAnswer() {
    queryClient.invalidateQueries({ queryKey: queryKeys.collections.pendingInvites() });
    queryClient.invalidateQueries({ queryKey: queryKeys.collections.all });
    queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
  }

  const acceptMutation = useMutation({
    mutationFn: (collectionId: string) => api.collections.acceptInvite(collectionId),
    onSuccess: () => {
      toast.success('Invitation accepted');
      refreshAfterAnswer();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const declineMutation = useMutation({
    mutationFn: (collectionId: string) => api.collections.declineInvite(collectionId),
    onSuccess: () => {
      toast.success('Invitation declined');
      refreshAfterAnswer();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (invites.length === 0) return null;

  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg bg-amber-100">
          <UserPlus className="h-4 w-4 text-amber-700" />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-amber-900">
            {invites.length === 1
              ? 'Collection invitation'
              : `${invites.length} collection invitations`}
          </h3>
          <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-amber-800">
            Someone shared a collection with you. Its entries will not appear in your vault or
            autofill until you accept.
          </p>
          <ul className="mt-3 space-y-2">
            {invites.map((invite) => {
              const accepting =
                acceptMutation.isPending && acceptMutation.variables === invite.collection_id;
              const declining =
                declineMutation.isPending && declineMutation.variables === invite.collection_id;
              const busy = accepting || declining;
              return (
                <li
                  key={invite.collection_id}
                  className="flex flex-col gap-2 rounded-lg border border-amber-200 bg-white px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Folder className="h-3.5 w-3.5 flex-shrink-0 text-slate-400" />
                      <span className="truncate text-sm font-medium text-slate-900">
                        {invite.name}
                      </span>
                      <span
                        className="flex-shrink-0 rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-600"
                        title={`You are being offered the ${invite.role} role`}
                      >
                        {invite.role}
                      </span>
                    </div>
                    {invite.description && (
                      <p className="mt-0.5 truncate text-xs text-slate-500">{invite.description}</p>
                    )}
                    <p className="mt-0.5 text-xs text-slate-400">
                      Invited by {invite.invited_by_email || 'a manager of this collection'}
                      {invite.invited_at ? ` · ${timeAgo(invite.invited_at)}` : ''}
                    </p>
                  </div>
                  <div className="flex flex-shrink-0 items-center gap-2">
                    <button
                      onClick={() => acceptMutation.mutate(invite.collection_id)}
                      disabled={busy}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800 disabled:opacity-50"
                    >
                      {accepting ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Check className="h-3.5 w-3.5" />
                      )}
                      Accept
                    </button>
                    <button
                      onClick={() => declineMutation.mutate(invite.collection_id)}
                      disabled={busy}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-rose-50 hover:text-rose-600 disabled:opacity-50"
                    >
                      {declining ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <X className="h-3.5 w-3.5" />
                      )}
                      Decline
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </div>
  );
}

// Manager-only surface for a single collection: rename/delete the collection
// and manage its members. The members query only fires while this modal is
// mounted, so no conditional hooks. Server-side guards (409 last-manager, 404
// unknown email) surface through the mutation error toasts.
function CollectionManageModal({
  collection,
  onClose,
  onDeleted,
}: {
  collection: Collection;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const queryClient = useQueryClient();
  const [addForm, setAddForm] = useState<{ email: string; role: CollectionRole }>({
    email: '',
    role: 'viewer',
  });
  const [details, setDetails] = useState({
    name: collection.name,
    description: collection.description,
  });
  const [confirmDelete, setConfirmDelete] = useState(false);

  const { data: members = [], isLoading } = useQuery<CollectionMember[]>({
    queryKey: queryKeys.collections.members(collection.id),
    queryFn: () => api.collections.listMembers(collection.id),
  });

  function invalidateMembers() {
    queryClient.invalidateQueries({ queryKey: queryKeys.collections.members(collection.id) });
    queryClient.invalidateQueries({ queryKey: queryKeys.collections.all });
  }

  // One endpoint covers both "invite this address" and "change this member's
  // role". `existing` is a UI-only flag so the toast tells the truth: an invite
  // gets the server's neutral wording (it never confirms whether the address
  // has an account), a role change gets a plain confirmation.
  const addMemberMutation = useMutation({
    mutationFn: ({ email, role }: { email: string; role: CollectionRole; existing?: boolean }) =>
      api.collections.addMember(collection.id, { email, role }),
    onSuccess: (result, variables) => {
      if (variables.existing) {
        toast.success('Role updated');
      } else {
        toast.success(result?.detail || 'Invitation sent if that address has an account');
        setAddForm({ email: '', role: 'viewer' });
      }
      invalidateMembers();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) => api.collections.removeMember(collection.id, userId),
    onSuccess: () => {
      toast.success('Member removed');
      invalidateMembers();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const updateCollectionMutation = useMutation({
    mutationFn: (data: { name: string; description: string }) =>
      api.collections.update(collection.id, data),
    onSuccess: () => {
      toast.success('Collection updated');
      queryClient.invalidateQueries({ queryKey: queryKeys.collections.all });
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const deleteCollectionMutation = useMutation({
    mutationFn: () => api.collections.remove(collection.id),
    onSuccess: () => {
      toast.success('Collection deleted');
      queryClient.invalidateQueries({ queryKey: queryKeys.collections.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
      onDeleted();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4"
      onClick={onClose}
    >
      <div
        className="max-h-[85vh] w-full max-w-2xl overflow-hidden rounded-xl bg-white shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3">
          <div className="flex items-center gap-2">
            <Users className="h-4 w-4 text-slate-500" />
            <h3 className="text-sm font-semibold text-slate-900">
              Manage collection: {collection.name}
            </h3>
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:text-slate-600">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[74vh] space-y-5 overflow-y-auto p-5">
          {/* Collection details: rename + description + delete */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              updateCollectionMutation.mutate({
                name: details.name.trim(),
                description: details.description.trim(),
              });
            }}
            className="space-y-3 rounded-lg border border-slate-100 bg-slate-50 p-4"
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-600">Name</label>
                <input
                  value={details.name}
                  onChange={(e) => setDetails((d) => ({ ...d, name: e.target.value }))}
                  required
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-600">Description</label>
                <input
                  value={details.description}
                  onChange={(e) => setDetails((d) => ({ ...d, description: e.target.value }))}
                  placeholder="Optional"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                />
              </div>
            </div>
            <div className="flex items-center justify-between">
              <button
                type="submit"
                disabled={updateCollectionMutation.isPending || !details.name.trim()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800 disabled:opacity-50"
              >
                {updateCollectionMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Save className="h-3.5 w-3.5" />
                )}
                Save details
              </button>
              {confirmDelete ? (
                <span className="flex items-center gap-2">
                  <span className="text-xs text-slate-500">Delete and all its entries?</span>
                  <button
                    type="button"
                    onClick={() => deleteCollectionMutation.mutate()}
                    disabled={deleteCollectionMutation.isPending}
                    className="rounded-lg bg-rose-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-rose-700 disabled:opacity-50"
                  >
                    Confirm delete
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmDelete(false)}
                    className="rounded-lg px-2 py-1 text-xs font-medium text-slate-500 hover:text-slate-700"
                  >
                    Cancel
                  </button>
                </span>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirmDelete(true)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-rose-50 hover:text-rose-600"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Delete collection
                </button>
              )}
            </div>
          </form>

          {/* Members list */}
          <div>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
              Members
            </h4>
            {isLoading ? (
              <div className="flex items-center justify-center py-6 text-slate-400">
                <Loader2 className="h-5 w-5 animate-spin" />
              </div>
            ) : members.length === 0 ? (
              <p className="py-4 text-center text-sm text-slate-400">No members yet.</p>
            ) : (
              <ul className="divide-y divide-slate-100 rounded-lg border border-slate-100">
                {members.map((m) => (
                  <li
                    key={m.user_id || m.email}
                    className="flex items-center justify-between gap-3 px-3 py-2.5"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="truncate text-sm font-medium text-slate-900">
                          {m.name || m.email}
                        </p>
                        {m.pending && (
                          <span
                            className="inline-flex flex-shrink-0 items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-700"
                            title="Invited but has not accepted yet. No access to this collection until they do."
                          >
                            <Clock className="h-3 w-3" />
                            Pending
                          </span>
                        )}
                      </div>
                      <p className="truncate text-xs text-slate-400">{m.email}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <select
                        value={m.role}
                        onChange={(e) =>
                          addMemberMutation.mutate({
                            email: m.email,
                            role: e.target.value as CollectionRole,
                            existing: true,
                          })
                        }
                        disabled={addMemberMutation.isPending}
                        className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs outline-none focus:border-slate-400 disabled:opacity-50"
                      >
                        {COLLECTION_ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                      <button
                        onClick={() => removeMemberMutation.mutate(m.user_id)}
                        disabled={removeMemberMutation.isPending}
                        title="Remove member"
                        className="rounded-lg p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-600 disabled:opacity-50"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Add member */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (addForm.email.trim()) {
                addMemberMutation.mutate({
                  email: addForm.email.trim(),
                  role: addForm.role,
                });
              }
            }}
            className="space-y-2 rounded-lg border border-slate-100 bg-slate-50 p-4"
          >
            <label className="block text-xs font-medium text-slate-600">
              Invite a member by email
            </label>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                type="email"
                value={addForm.email}
                onChange={(e) => setAddForm((f) => ({ ...f, email: e.target.value }))}
                placeholder="teammate@example.com"
                className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
              />
              <select
                value={addForm.role}
                onChange={(e) => setAddForm((f) => ({ ...f, role: e.target.value as CollectionRole }))}
                className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm outline-none focus:border-slate-400"
              >
                {COLLECTION_ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                disabled={addMemberMutation.isPending || !addForm.email.trim()}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
              >
                {addMemberMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Plus className="h-3.5 w-3.5" />
                )}
                Invite
              </button>
            </div>
            <p className="text-xs text-slate-400">
              They show up as Pending and get no access until they accept the invitation. We do not
              report back whether the address has a Trustissues account.
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}

export default function Vault() {
  const queryClient = useQueryClient();

  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  // Team vault policy drives the auto-lock timer below.
  const { data: vaultPolicy } = useQuery({
    queryKey: queryKeys.settings.vaultPolicy(),
    queryFn: () => request<{ auto_lock_max_minutes: number }>('/settings/vault-policy'),
  });
  const [vaultPassword, setVaultPassword] = useState('');
  const [vaultEntries, setVaultEntries] = useState<VaultEntry[]>([]);
  const [showAddSecret, setShowAddSecret] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [newSecret, setNewSecret] = useState({ name: '', value: '', url: '', alias_url: '', username: '', category: '', notes: '', rotation_interval_days: '', expires_at: '', collection_id: '' });
  const [newCustomFields, setNewCustomFields] = useState<CustomField[]>([]);
  const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set());
  const [rotatedValue, setRotatedValue] = useState<{ id: string; value: string } | null>(null);
  const [editingEntryId, setEditingEntryId] = useState<string | null>(null);
  const [rotatingEntryId, setRotatingEntryId] = useState<string | null>(null);
  const [rotationPanelId, setRotationPanelId] = useState<string | null>(null);
  const [rotatePassword, setRotatePassword] = useState('');
  const [editForm, setEditForm] = useState({ name: '', value: '', url: '', alias_url: '', username: '', category: '', notes: '', rotation_interval_days: '', expires_at: '', collection_id: '', destination_patterns: '' });
  const [editCustomFields, setEditCustomFields] = useState<CustomField[]>([]);

  // Collection filter: 'all' | 'personal' | a collection id.
  const [collectionFilter, setCollectionFilter] = useState<string>('all');
  const [showNewCollection, setShowNewCollection] = useState(false);
  const [newCollection, setNewCollection] = useState({ name: '', description: '' });
  const [manageCollectionId, setManageCollectionId] = useState<string | null>(null);
  // Id of the collection whose "Leave" button is waiting on confirmation.
  const [confirmLeaveId, setConfirmLeaveId] = useState<string | null>(null);

  const { data: vaultList = [], isLoading: vaultLoading } = useQuery<VaultEntry[]>({
    queryKey: queryKeys.vault.list(),
    queryFn: vaultApi.list,
  });

  const { data: collections = [] } = useQuery<Collection[]>({
    queryKey: queryKeys.collections.list(),
    queryFn: api.collections.list,
  });

  // Auto-lock: drop the decrypted entries after the policy's
  // auto_lock_max_minutes (GET /api/settings/vault-policy). The values only live
  // in memory, so re-locking is just clearing state.
  useEffect(() => {
    if (!vaultUnlocked) return;
    const minutes = vaultPolicy?.auto_lock_max_minutes ?? 15;
    const timer = setTimeout(() => {
      setVaultUnlocked(false);
      setVaultEntries([]);
      setRevealedSecrets(new Set());
      setRotatedValue(null);
      toast('Vault locked automatically', { icon: '🔒' });
    }, minutes * 60_000);
    return () => clearTimeout(timer);
  }, [vaultUnlocked, vaultPolicy?.auto_lock_max_minutes]);

  // Drop a half-finished "Leave" confirmation when the filter moves elsewhere,
  // so the confirm never reappears attached to a different collection.
  useEffect(() => {
    setConfirmLeaveId((id) => (id && id !== collectionFilter ? null : id));
  }, [collectionFilter]);

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
      setNewSecret({ name: '', value: '', url: '', alias_url: '', username: '', category: '', notes: '', rotation_interval_days: '', expires_at: '', collection_id: '' });
      setNewCustomFields([]);
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
      // A 200 does not mean the rotation was clean.
      //
      // The server returns 200 for a rotation that committed but could not be
      // delivered (rotation_targets unreadable) or whose predecessor could not be
      // revoked, and records the reason in last_rotation_error. Toasting an
      // unconditional success, and then coercing that field to '' below, erased the
      // ONE record the server had written: the row rendered green, no "Rotation error"
      // pill appeared, and the operator was told a rotation worked while every
      // consumer still held a revoked key.
      if (data.last_rotation_error) {
        toast.error(`Rotated, but not complete: ${data.last_rotation_error}`);
      } else {
        toast.success('Secret rotated');
      }
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
      // Rotate was the only mutation that did not refresh the unlocked list.
      // vaultEntries holds the decrypted values from unlock, and invalidating
      // the query only refetches the LOCKED list, so the row kept revealing and
      // copying the PREVIOUS secret: the one that was just revoked upstream.
      // Copy it into a deploy and it fails to authenticate, with the UI insisting
      // the rotation succeeded. The rotation status shown alongside it was stale
      // for the same reason.
      setVaultEntries((entries) =>
        entries.map((e) =>
          e.id === data.id
            ? {
                ...e,
                value: data.value ?? e.value,
                last_rotated_at: data.last_rotated_at ?? e.last_rotated_at,
                rotation_status: data.rotation_status ?? e.rotation_status,
                // NOT `?? ''`: an absent field must keep whatever the row already
                // had rather than being blanked, and a present one must survive.
                last_rotation_error:
                  data.last_rotation_error ?? e.last_rotation_error ?? '',
              }
            : e
        )
      );
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

  const createCollectionMutation = useMutation({
    mutationFn: (data: { name: string; description: string }) => api.collections.create(data),
    onSuccess: () => {
      toast.success('Collection created');
      setShowNewCollection(false);
      setNewCollection({ name: '', description: '' });
      queryClient.invalidateQueries({ queryKey: queryKeys.collections.all });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  // Moving an entry is a dedicated endpoint, not part of the entry update. We
  // patch the in-memory unlocked list so the badge updates without re-locking.
  const moveToCollectionMutation = useMutation({
    mutationFn: ({ id, collectionId }: { id: string; collectionId: string | null }) =>
      vaultApi.moveToCollection(id, collectionId),
    onSuccess: (_data, variables) => {
      toast.success(variables.collectionId ? 'Moved to collection' : 'Moved to personal');
      setVaultEntries((prev) =>
        prev.map((e) => (e.id === variables.id ? { ...e, collection_id: variables.collectionId } : e))
      );
      setEditForm((f) => ({ ...f, collection_id: variables.collectionId ?? '' }));
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.collections.all });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  // Leaving drops your own membership. It is the same endpoint that declines an
  // invitation, so nobody is stuck in a collection someone else created. The
  // server refuses (409) when you are the last manager; that message is shown
  // as-is rather than second-guessed here.
  const leaveCollectionMutation = useMutation({
    mutationFn: (collectionId: string) => api.collections.declineInvite(collectionId),
    onSuccess: (_data, collectionId) => {
      toast.success('You left the collection');
      setConfirmLeaveId(null);
      setCollectionFilter('all');
      // Drop the collection's entries from the decrypted in-memory list so the
      // view matches the new access without forcing a re-unlock.
      setVaultEntries((prev) => prev.filter((e) => e.collection_id !== collectionId));
      queryClient.invalidateQueries({ queryKey: queryKeys.collections.all });
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  // Collections the user can write into (add or move entries).
  const writableCollections = collections.filter(
    (c) => c.role === 'editor' || c.role === 'manager'
  );

  const collectionById = (id: string | null): Collection | undefined =>
    id ? collections.find((c) => c.id === id) : undefined;

  // Name for a collection badge; falls back to a generic label when the entry
  // points at a collection not in our list (no crash, read-only treatment).
  const collectionName = (id: string | null): string => collectionById(id)?.name ?? 'Shared';

  // Whether the current user may edit/move/delete this entry. Personal entries
  // are always the owner's. Collection entries need editor/manager; an unknown
  // collection is treated as read-only.
  function canEditEntry(entry: VaultEntry): boolean {
    if (!entry.collection_id) return true;
    const c = collectionById(entry.collection_id);
    if (!c) return false;
    return c.role === 'editor' || c.role === 'manager';
  }

  function matchesFilter(entry: VaultEntry): boolean {
    if (collectionFilter === 'all') return true;
    if (collectionFilter === 'personal') return !entry.collection_id;
    return entry.collection_id === collectionFilter;
  }

  // The collection currently selected in the filter, if the user manages it,
  // drives the contextual Manage button.
  const selectedFilterCollection =
    collectionFilter !== 'all' && collectionFilter !== 'personal'
      ? collectionById(collectionFilter)
      : undefined;
  const manageCollection = manageCollectionId ? collectionById(manageCollectionId) : undefined;

  const filteredEntries = vaultEntries.filter(matchesFilter);
  const filteredVaultList = vaultList.filter(matchesFilter);

  function startEditing(entry: VaultEntry) {
    setEditingEntryId(entry.id);
    setEditForm({
      name: entry.name,
      // Deliberately NOT pre-filled with entry.value. The field's own label says
      // "(leave blank to keep current)", and submitEdit only sends `value` when
      // it is non-empty, so pre-filling made every metadata edit re-submit the
      // secret. The backend treats a value write as a rotation and stamps
      // last_rotated_at = now, so renaming an entry or fixing a typo in its
      // notes silently reset the rotation clock and de-scheduled an overdue
      // auto-rotation. Blank means "keep it", which is what the label promises.
      value: '',
      url: entry.url || '',
      alias_url: entry.alias_url || '',
      username: entry.username || '',
      category: entry.category || '',
      notes: entry.notes || '',
      rotation_interval_days: entry.rotation_interval_days?.toString() || '',
      expires_at: entry.expires_at ? entry.expires_at.split('T')[0] : '',
      collection_id: entry.collection_id ?? '',
      // One host per line. Empty means no agent token can be minted for this
      // secret at all, which is the safe default rather than a wide one.
      destination_patterns: (entry.destination_patterns ?? []).join('\n'),
    });
    setEditCustomFields((entry.custom_fields ?? []).map((f) => ({ ...f })));
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
    // The interval has TWO editors: this field and the rotation panel, which renders
    // outside the edit/display ternary and so can be used while the edit form is open.
    // The panel's save has to write back into this form (see onScheduleSaved), or the
    // stale seeded value below lands as NULL: the row becomes auto_rotate=1 with
    // rotation_interval_days NULL, ListVaultEntriesNeedingRotation requires
    // `rotation_interval_days > 0`, and the sweep then skips the entry forever while
    // the UI still shows a schedule. Silently disabling the automation the operator
    // just switched on.
    data.rotation_interval_days = editForm.rotation_interval_days
      ? Number(editForm.rotation_interval_days)
      : null;
    data.expires_at = editForm.expires_at || null;
    // Always send the array: it replaces the whole set, so removing every row
    // clears the entry's custom fields.
    data.custom_fields = cleanCustomFields(editCustomFields);
    // Always send it: the textarea holds the full list, so an emptied box means
    // "clear the ceiling" (which disables minting) rather than "leave it alone".
    data.destination_patterns = editForm.destination_patterns
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
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
        {/* Collection invitations waiting on this user. Membership is consent
            based, so nothing is shared until one of these is accepted. Renders
            null when there is nothing pending. */}
        <PendingInvitesCard />

        {/* Service identities: machine credentials that fetch a scoped set
            of vault secrets at boot. Admin-only; renders null otherwise. */}
        <ServiceIdentitiesCard />

        {/* Collection filter: All / Personal / each shared collection. Filters
            the entries shown below and hosts the create + manage affordances. */}
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Folder className="h-4 w-4 text-slate-500" />
              <h3 className="text-sm font-semibold text-slate-900">Collections</h3>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {selectedFilterCollection?.role === 'manager' && (
                <button
                  onClick={() => setManageCollectionId(selectedFilterCollection.id)}
                  className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  <Users className="h-3.5 w-3.5" />
                  Manage
                </button>
              )}
              {/* Leave: available on any collection you are a member of, at any
                  role, so nobody is stuck in someone else's collection. */}
              {selectedFilterCollection &&
                (confirmLeaveId === selectedFilterCollection.id ? (
                  <span className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">
                      Leave {selectedFilterCollection.name}? Its entries disappear from your vault.
                    </span>
                    <button
                      onClick={() => leaveCollectionMutation.mutate(selectedFilterCollection.id)}
                      disabled={leaveCollectionMutation.isPending}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-rose-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-rose-700 disabled:opacity-50"
                    >
                      {leaveCollectionMutation.isPending && (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      )}
                      Confirm leave
                    </button>
                    <button
                      onClick={() => setConfirmLeaveId(null)}
                      className="rounded-lg px-2 py-1 text-xs font-medium text-slate-500 hover:text-slate-700"
                    >
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button
                    onClick={() => setConfirmLeaveId(selectedFilterCollection.id)}
                    title="Give up your own access to this collection"
                    className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-rose-50 hover:text-rose-600"
                  >
                    <LogOut className="h-3.5 w-3.5" />
                    Leave
                  </button>
                ))}
              <button
                onClick={() => setShowNewCollection(true)}
                className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
              >
                <FolderPlus className="h-3.5 w-3.5" />
                New collection
              </button>
            </div>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {[
              { key: 'all', label: 'All' },
              { key: 'personal', label: 'Personal' },
            ].map((f) => (
              <button
                key={f.key}
                onClick={() => setCollectionFilter(f.key)}
                className={clsx(
                  'rounded-full border px-3 py-1 text-xs font-medium transition-colors',
                  collectionFilter === f.key
                    ? 'border-slate-900 bg-slate-900 text-white'
                    : 'border-slate-300 bg-white text-slate-600 hover:border-slate-400'
                )}
              >
                {f.label}
              </button>
            ))}
            {collections.map((c) => {
              const active = collectionFilter === c.id;
              return (
                <button
                  key={c.id}
                  onClick={() => setCollectionFilter(c.id)}
                  title={`Your role: ${c.role}`}
                  className={clsx(
                    'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors',
                    active
                      ? 'border-slate-900 bg-slate-900 text-white'
                      : 'border-slate-300 bg-white text-slate-600 hover:border-slate-400'
                  )}
                >
                  {c.name}
                  {typeof c.entry_count === 'number' && (
                    <span
                      className={clsx(
                        'rounded-full px-1.5 py-0.5 text-[10px] leading-none',
                        active ? 'bg-white/20 text-white' : 'bg-slate-100 text-slate-500'
                      )}
                    >
                      {c.entry_count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

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
                    collection_id: newSecret.collection_id || undefined,
                    custom_fields: cleanCustomFields(newCustomFields),
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
                      Collection
                    </label>
                    <select
                      value={newSecret.collection_id}
                      onChange={(e) => setNewSecret({ ...newSecret, collection_id: e.target.value })}
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                    >
                      <option value="">Personal</option>
                      {writableCollections.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name}
                        </option>
                      ))}
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
                <CustomFieldsEditor
                  fields={newCustomFields}
                  onChange={setNewCustomFields}
                  category={newSecret.category}
                />
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
            {filteredEntries.length === 0 ? (
              <p className="py-4 text-center text-sm text-slate-500">
                {vaultEntries.length === 0
                  ? 'No secrets in the vault yet. Add one to get started.'
                  : 'No secrets in this view. Try a different collection filter.'}
              </p>
            ) : (
              <div className="space-y-2">
                {filteredEntries.map((entry) => (
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
                        <div>
                          <label className="mb-1 block text-xs font-medium text-slate-600">
                            Collection{' '}
                            <span className="font-normal text-slate-400">(moves the entry when changed)</span>
                          </label>
                          <select
                            value={editForm.collection_id}
                            onChange={(e) => {
                              const next = e.target.value || null;
                              setEditForm((f) => ({ ...f, collection_id: next ?? '' }));
                              moveToCollectionMutation.mutate({ id: entry.id, collectionId: next });
                            }}
                            disabled={moveToCollectionMutation.isPending}
                            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:border-slate-400 disabled:opacity-50"
                          >
                            <option value="">Personal</option>
                            {writableCollections.map((c) => (
                              <option key={c.id} value={c.id}>
                                {c.name}
                              </option>
                            ))}
                            {/* Keep the current collection selectable even if it
                                is not in the writable set (avoids a blank select). */}
                            {editForm.collection_id &&
                              !writableCollections.some((c) => c.id === editForm.collection_id) && (
                                <option value={editForm.collection_id}>
                                  {collectionName(editForm.collection_id)}
                                </option>
                              )}
                          </select>
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
                        {/*
                          The capability ceiling. Without a writer for this the
                          MCP "use a secret you never see" feature could not be
                          used at all for any secret created in the product:
                          minting always failed with no way to fix it from the UI.
                        */}
                        <div>
                          <label className="mb-1 block text-xs font-medium text-slate-600">
                            Agent access{' '}
                            <span className="font-normal text-slate-400">
                              (hosts an AI agent may send this secret to, one per line)
                            </span>
                          </label>
                          <textarea
                            rows={3}
                            value={editForm.destination_patterns}
                            onChange={(e) =>
                              setEditForm({ ...editForm, destination_patterns: e.target.value })
                            }
                            placeholder={'api.example.com/*\napi.example.com/v1/chat/*'}
                            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 font-mono text-xs outline-none focus:border-slate-400"
                          />
                          <p className="mt-1 text-xs text-slate-500">
                            Leave empty to block agent access entirely. Name the exact
                            host and narrow with a path glob; host wildcards like{' '}
                            <code className="font-mono">*.example.com</code> are rejected
                            because anyone can register a sibling subdomain.
                          </p>
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
                        <CustomFieldsEditor
                          fields={editCustomFields}
                          onChange={setEditCustomFields}
                          category={editForm.category}
                        />
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
                            {entry.collection_id && (
                              <span
                                className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600"
                                title="Shared collection"
                              >
                                <Folder className="h-3 w-3" />
                                {collectionName(entry.collection_id)}
                              </span>
                            )}
                            <span
                              className={clsx(
                                'rounded-full px-2 py-0.5 text-xs font-medium',
                                entry.rotation_status === 'fresh' && 'bg-emerald-100 text-emerald-700',
                                entry.rotation_status === 'due_soon' && 'bg-amber-100 text-amber-700',
                                entry.rotation_status === 'overdue' && 'bg-red-100 text-red-700',
                                entry.rotation_status === 'expired' && 'bg-red-100 text-red-700',
                                entry.rotation_status === 'error' && 'bg-red-100 text-red-700'
                              )}
                              title={
                                entry.rotation_status === 'error'
                                  ? entry.last_rotation_error || 'The last rotation failed'
                                  : undefined
                              }
                            >
                              {entry.rotation_status === 'fresh' && 'Fresh'}
                              {entry.rotation_status === 'due_soon' && 'Due Soon'}
                              {entry.rotation_status === 'overdue' && 'Overdue'}
                              {entry.rotation_status === 'expired' && 'Expired'}
                              {entry.rotation_status === 'error' && 'Rotation failed'}
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
                          {entry.custom_fields && entry.custom_fields.length > 0 && (
                            <CustomFieldsDisplay fields={entry.custom_fields} />
                          )}
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
                        {canEditEntry(entry) ? (
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
                        ) : (
                          <span
                            className="ml-2 inline-flex flex-shrink-0 items-center gap-1 self-start rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-500"
                            title="You have viewer access to this collection"
                          >
                            <Lock className="h-3 w-3" />
                            View only
                          </span>
                        )}
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
                    {rotationPanelId === entry.id && (
                      <RotationManager
                        entry={entry}
                        onScheduleSaved={(patch) => {
                          setVaultEntries((prev) =>
                            prev.map((e) => (e.id === entry.id ? { ...e, ...patch } : e))
                          );
                          // Keep the edit form in sync. It holds its own copy of the
                          // interval, seeded when it opened, and saving it writes that
                          // copy back. Without this the panel's new schedule is
                          // overwritten with NULL and the sweep stops seeing the entry.
                          if (editingEntryId === entry.id) {
                            setEditForm((f) => ({
                              ...f,
                              rotation_interval_days:
                                patch.rotation_interval_days?.toString() ?? '',
                            }));
                          }
                        }}
                      />
                    )}
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
            ) : filteredVaultList.length === 0 ? (
              <p className="py-4 text-center text-sm text-slate-500">
                {vaultList.length === 0
                  ? 'No secrets stored. Unlock the vault and add your first secret.'
                  : 'No secrets in this view. Try a different collection filter.'}
              </p>
            ) : (
              <div className="overflow-hidden rounded-lg border border-slate-100">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 bg-slate-50">
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Name</th>
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Category</th>
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Collection</th>
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Status</th>
                      <th className="px-3 py-2 text-xs font-medium text-slate-500">Last rotated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredVaultList.map((entry) => (
                      <tr key={entry.id} className="border-b border-slate-50 last:border-0">
                        <td className="px-3 py-2 text-sm font-medium text-slate-900">{entry.name}</td>
                        <td className="px-3 py-2 text-xs text-slate-500">{entry.category || '-'}</td>
                        <td className="px-3 py-2 text-xs text-slate-500">
                          {entry.collection_id ? collectionName(entry.collection_id) : 'Personal'}
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap items-center gap-1.5">
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
                            {/*
                              This locked table is what a user sees WITHOUT
                              unlocking, and it used to show only rotation_status.
                              A rotation that failed outright leaves the status
                              looking merely "overdue", so the failure was
                              invisible unless you unlocked and opened the
                              rotation panel. The reason is already API-visible
                              and structural (never a raw upstream error), so it
                              is safe to show here.
                            */}
                            {entry.last_rotation_error && (
                              <span
                                className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700"
                                title={entry.last_rotation_error}
                              >
                                <AlertCircle className="h-3 w-3" />
                                Failed
                              </span>
                            )}
                          </div>
                          {entry.last_rotation_error && (
                            <p className="mt-1 max-w-xs text-xs leading-snug text-red-600">
                              {entry.last_rotation_error}
                            </p>
                          )}
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

      {/* New collection modal */}
      {showNewCollection && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4"
          onClick={() => setShowNewCollection(false)}
        >
          <div
            className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-900">
                <FolderPlus className="h-4 w-4 text-white" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-900">New collection</h3>
                <p className="text-xs text-slate-500">You become its manager.</p>
              </div>
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (newCollection.name.trim()) {
                  createCollectionMutation.mutate({
                    name: newCollection.name.trim(),
                    description: newCollection.description.trim(),
                  });
                }
              }}
              className="space-y-3"
            >
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-600">Name</label>
                <input
                  value={newCollection.name}
                  onChange={(e) => setNewCollection((c) => ({ ...c, name: e.target.value }))}
                  placeholder="e.g. Payments team"
                  required
                  autoFocus
                  className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-600">
                  Description (optional)
                </label>
                <input
                  value={newCollection.description}
                  onChange={(e) => setNewCollection((c) => ({ ...c, description: e.target.value }))}
                  placeholder="What this collection holds"
                  className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-sm outline-none focus:border-slate-400"
                />
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setShowNewCollection(false)}
                  className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-500 hover:text-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createCollectionMutation.isPending || !newCollection.name.trim()}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-4 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
                >
                  {createCollectionMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <FolderPlus className="h-3.5 w-3.5" />
                  )}
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Manage collection modal (managers only; the button that opens it is
          gated on role === 'manager'). */}
      {manageCollection && (
        <CollectionManageModal
          collection={manageCollection}
          onClose={() => setManageCollectionId(null)}
          onDeleted={() => {
            setManageCollectionId(null);
            setCollectionFilter('all');
          }}
        />
      )}
    </Layout>
  );
}
