import { useState } from 'react';
import {
  Loader2,
  Plus,
  Trash2,
  Save,
  Zap,
  ShieldCheck,
  AlertCircle,
  Webhook,
  Bell,
  GitBranch,
  KeyRound,
  Info,
  ExternalLink,
} from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { queryKeys } from '@/lib/query-keys';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { vaultApi, providerKeys } from '@/lib/vault-types';
import type { VaultEntry, RotationTarget, ProviderInfo } from '@/lib/vault-types';

// Parses provider_meta (a JSON-encoded object) into a flat string map for the
// form. Anything that is not a JSON object of strings is treated as empty
// rather than thrown: a corrupt or pre-feature "{}" column must not crash the
// panel, it should just look like a provider with nothing filled in yet.
function parseProviderMeta(raw?: string): Record<string, string> {
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof v === 'string') out[k] = v;
      }
      return out;
    }
  } catch {
    // Not JSON. Treat as empty rather than surfacing a parse error for a
    // column the operator never touched directly.
  }
  return {};
}

// Renders ProviderInfo.predecessor_fate honestly. "unknown" is NOT the same
// claim as "leaves_live": one is a verified vendor behavior, the other is an
// open question, and collapsing them would be exactly the false confidence
// this field exists to remove. See ProviderInfo's doc comment.
function fateClasses(fate: ProviderInfo['predecessor_fate']): string {
  if (fate === 'revokes') return 'border-emerald-200 bg-emerald-50 text-emerald-700';
  if (fate === 'not_applicable') return 'border-slate-200 bg-slate-50 text-slate-600';
  return 'border-amber-200 bg-amber-50 text-amber-700'; // leaves_live, unknown
}

function FateIcon({ fate }: { fate: ProviderInfo['predecessor_fate'] }) {
  const cls = 'mt-0.5 h-3.5 w-3.5 shrink-0';
  if (fate === 'revokes') return <ShieldCheck className={cls} />;
  if (fate === 'not_applicable') return <Info className={cls} />;
  return <AlertCircle className={cls} />;
}

function fateHeadline(p: ProviderInfo): string {
  switch (p.predecessor_fate) {
    case 'revokes':
      return 'Rotating destroys the key it replaces.';
    case 'leaves_live':
      return 'Rotating does NOT destroy the key it replaces: both keys keep working.';
    case 'not_applicable':
      return p.can_auto_rotate
        ? 'No vendor key to revoke: this is a locally generated secret.'
        : 'This provider does not auto-rotate, so no key is ever replaced here.';
    case 'unknown':
    default:
      return 'Not verified whether rotating destroys the key it replaces.';
  }
}

const TARGET_TYPES: { value: RotationTarget['type']; label: string; icon: typeof Webhook; hint: string }[] = [
  { value: 'webhook', label: 'Webhook', icon: Webhook, hint: 'POST the new value to a signed webhook' },
  { value: 'forgejo_secret', label: 'Forgejo secret', icon: GitBranch, hint: 'Update a repository actions secret on a Forgejo instance' },
  { value: 'notify', label: 'Notify only', icon: Bell, hint: 'Send a notification, no delivery' },
];

const INTERVALS = [0, 30, 45, 60, 90, 180, 365];

function blankTarget(type: RotationTarget['type']): RotationTarget {
  return { type };
}

function targetIcon(type: RotationTarget['type']) {
  return (TARGET_TYPES.find((t) => t.value === type) || TARGET_TYPES[0]).icon;
}

export default function RotationManager({
  entry,
  onScheduleSaved,
  onProviderSaved,
}: {
  entry: VaultEntry;
  // Patches the caller's in-memory copy after a schedule save. The unlocked
  // entries live in useState, not in react-query, so invalidateQueries does not
  // reach them: without this the parent keeps the OLD interval, and the next
  // metadata edit submits that stale value. Since an explicit null now genuinely
  // clears the field, that stale save silently wiped the interval the user had
  // just set while leaving auto_rotate on, i.e. auto-rotation enabled with no
  // schedule.
  onScheduleSaved?: (patch: { rotation_interval_days: number | null; auto_rotate: boolean }) => void;
  // Same reason as onScheduleSaved: patches the caller's in-memory entry after
  // a provider save so the badge and this panel agree without a full reload.
  onProviderSaved?: (patch: { provider: string; provider_meta: string }) => void;
}) {
  const queryClient = useQueryClient();
  const [targets, setTargets] = useState<RotationTarget[] | null>(null);
  const [addType, setAddType] = useState<RotationTarget['type']>('webhook');
  const [interval, setIntervalDays] = useState<number>(entry.rotation_interval_days ?? 0);
  const [autoRotate, setAutoRotate] = useState<boolean>(!!entry.auto_rotate);
  const [providerName, setProviderName] = useState<string>(entry.provider ?? '');
  const [providerMeta, setProviderMeta] = useState<Record<string, string>>(() =>
    parseProviderMeta(entry.provider_meta)
  );

  const targetsQuery = useQuery({
    queryKey: queryKeys.vault.targets(entry.id),
    queryFn: () => vaultApi.getTargets(entry.id),
  });

  // A "notify" target fans out to the configured notification channels, so with
  // none enabled it delivers nothing at all. Warn about that where the target is
  // configured rather than letting it look like it works.
  //
  // GET /admin/notification-channels is AdminOnly, so only run it for an admin;
  // a non-admin gets the same warning without the count and is pointed at an
  // admin. `enabled: isAdmin` keeps a non-admin from firing a request that would
  // 403 on every render of this panel.
  const { isAdmin } = useAuth();
  const channelsQuery = useQuery({
    queryKey: queryKeys.admin.notificationChannels(),
    queryFn: () => api.admin.listNotificationChannels(),
    enabled: isAdmin,
    staleTime: 60_000,
  });
  const channelsLoading = isAdmin && channelsQuery.isLoading;
  const enabledChannelCount = isAdmin
    ? (channelsQuery.data ?? []).filter((c) => c.enabled).length
    : 0;

  // Seed local editable state once the server targets arrive.
  const serverTargets = targetsQuery.data?.targets;
  const targetsVersion = targetsQuery.data?.version;
  if (targets === null && serverTargets) {
    setTargets(serverTargets.map((t) => ({ ...t })));
  }
  const working = targets ?? [];

  const saveTargets = useMutation({
    // An empty `working` here is a deliberate clear, not an accident: Save is
    // disabled unless the targets query settled successfully, so the user is
    // looking at the real list and has removed every row from it.
    mutationFn: () =>
      vaultApi.updateTargets(entry.id, working, {
        clear: working.length === 0,
        // Pins the view being edited; the server 409s if it moved.
        version: targetsVersion,
      }),
    onSuccess: () => {
      toast.success('Rotation targets saved');
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.targets(entry.id) });
    },
    onError: (e: Error) => toast.error(e.message || 'Failed to save targets'),
  });

  const saveSchedule = useMutation({
    mutationFn: () => vaultApi.updateSchedule(entry.id, { rotation_interval_days: interval, auto_rotate: autoRotate }),
    onSuccess: () => {
      toast.success('Rotation schedule saved');
      onScheduleSaved?.({
        rotation_interval_days: interval > 0 ? interval : null,
        auto_rotate: autoRotate,
      });
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
    },
    onError: (e: Error) => toast.error(e.message || 'Failed to save schedule'),
  });

  // The provider catalog: names, required_meta fields and predecessor_fate,
  // all driven from the API rather than a second hardcoded list in this file.
  // Static enough per instance to cache for a few minutes.
  const providersQuery = useQuery({
    queryKey: providerKeys.list(),
    queryFn: vaultApi.listProviders,
    staleTime: 5 * 60_000,
  });
  const providers = providersQuery.data ?? [];
  const selectedProvider = providers.find((p) => p.name === providerName);
  const requiredKeys = selectedProvider ? Object.keys(selectedProvider.required_meta) : [];
  const missingRequired = requiredKeys.filter((k) => !providerMeta[k]?.trim());

  // Switching to the provider already stored on the entry restores what is
  // actually saved for it; switching to any other provider starts blank,
  // because a Twilio account_sid left over in the meta object after picking
  // Auth0 is not a value that means anything to Auth0's adapter.
  function handleProviderChange(name: string) {
    setProviderName(name);
    setProviderMeta(name === (entry.provider ?? '') ? parseProviderMeta(entry.provider_meta) : {});
  }

  const saveProvider = useMutation({
    mutationFn: () =>
      vaultApi.update(entry.id, {
        provider: providerName,
        provider_meta: JSON.stringify(providerMeta),
      }),
    onSuccess: (updated) => {
      toast.success(providerName ? `Rotation provider set to ${selectedProvider?.label ?? providerName}` : 'Rotation provider cleared');
      onProviderSaved?.({
        provider: updated.provider ?? providerName,
        provider_meta: updated.provider_meta ?? JSON.stringify(providerMeta),
      });
      queryClient.invalidateQueries({ queryKey: queryKeys.vault.all });
    },
    onError: (e: Error) => toast.error(e.message || 'Failed to save provider'),
  });

  function patch(i: number, fields: Partial<RotationTarget>) {
    setTargets(working.map((t, idx) => (idx === i ? { ...t, ...fields } : t)));
  }
  function remove(i: number) {
    setTargets(working.filter((_, idx) => idx !== i));
  }
  function add() {
    setTargets([...working, blankTarget(addType)]);
  }

  const hasError = !!entry.last_rotation_error;

  return (
    <div className="mt-3 space-y-4 rounded-lg border border-slate-200 bg-slate-50 p-4">
      {/* Verification status */}
      <div
        className={clsx(
          'flex items-start gap-2 rounded-lg border p-3 text-xs',
          hasError ? 'border-red-200 bg-red-50 text-red-700' : 'border-emerald-200 bg-emerald-50 text-emerald-700'
        )}
      >
        {hasError ? <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" /> : <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />}
        <div>
          <div className="font-medium">
            {hasError ? 'Last rotation did not fully verify' : 'Rotation healthy'}
          </div>
          <div className="mt-0.5 text-slate-600">
            {hasError
              ? entry.last_rotation_error
              : entry.last_rotated_at
                ? `Last rotated ${new Date(entry.last_rotated_at).toLocaleString()}.`
                : 'Not rotated yet.'}
          </div>
        </div>
      </div>

      {/* Rotation provider: what mints the replacement value. Comes first because
          the schedule and targets below only matter once something can actually
          produce a new secret. */}
      <div className="rounded-lg border border-slate-200 bg-white p-3">
        <h4 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-slate-800">
          <KeyRound className="h-4 w-4 text-slate-500" />
          Rotation provider
        </h4>

        {providersQuery.isError ? (
          <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
            <p className="font-medium">Could not load the provider catalog.</p>
            <button
              type="button"
              onClick={() => providersQuery.refetch()}
              className="mt-1 rounded-lg border border-red-300 bg-white px-2 py-1 font-medium text-red-700 hover:bg-red-100"
            >
              Retry
            </button>
          </div>
        ) : (
          <>
            <select
              value={providerName}
              onChange={(e) => handleProviderChange(e.target.value)}
              disabled={providersQuery.isLoading}
              className="w-full rounded-lg border border-slate-200 px-2 py-1.5 text-sm outline-none focus:border-slate-400 disabled:opacity-50"
            >
              <option value="">No provider (manual)</option>
              {[...providers]
                .sort((a, b) => a.label.localeCompare(b.label))
                .map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.label}
                    {p.can_auto_rotate ? '' : ' (reminder only, no auto-rotate)'}
                  </option>
                ))}
            </select>

            {selectedProvider && requiredKeys.length > 0 && (
              <div className="mt-3 grid grid-cols-2 gap-2">
                {requiredKeys.map((key) => (
                  <Field
                    key={key}
                    label={selectedProvider.required_meta[key]}
                    value={providerMeta[key]}
                    onChange={(v) => setProviderMeta((m) => ({ ...m, [key]: v }))}
                    placeholder={key}
                  />
                ))}
              </div>
            )}

            {selectedProvider && (
              <div
                className={clsx(
                  'mt-3 flex items-start gap-2 rounded-lg border p-2.5 text-xs',
                  fateClasses(selectedProvider.predecessor_fate)
                )}
              >
                <FateIcon fate={selectedProvider.predecessor_fate} />
                <div>
                  <div className="font-medium">{fateHeadline(selectedProvider)}</div>
                  {selectedProvider.predecessor_note && (
                    <p className="mt-0.5 text-slate-600">{selectedProvider.predecessor_note}</p>
                  )}
                </div>
              </div>
            )}

            {selectedProvider?.dashboard_url && (
              <a
                href={selectedProvider.dashboard_url}
                target="_blank"
                rel="noreferrer"
                className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-slate-700"
              >
                <ExternalLink className="h-3 w-3" />
                Open {selectedProvider.label} dashboard
              </a>
            )}

            <div className="mt-3 flex items-center justify-between">
              {missingRequired.length > 0 ? (
                <p className="text-xs text-amber-600">
                  Fill in {missingRequired.map((k) => selectedProvider!.required_meta[k]).join(', ')} to save.
                </p>
              ) : (
                <span />
              )}
              <button
                type="button"
                onClick={() => saveProvider.mutate()}
                disabled={saveProvider.isPending || providersQuery.isLoading || missingRequired.length > 0}
                className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
              >
                {saveProvider.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                Save provider
              </button>
            </div>
          </>
        )}
      </div>

      {/* Auto-rotation schedule */}
      <div className="rounded-lg border border-slate-200 bg-white p-3">
        <div className="flex items-center justify-between">
          <label className="flex cursor-pointer items-center gap-2 text-sm font-medium text-slate-800">
            <button
              type="button"
              role="switch"
              aria-checked={autoRotate}
              onClick={() => setAutoRotate((v) => !v)}
              className={clsx(
                'relative inline-flex h-5 w-9 items-center rounded-full transition-colors',
                autoRotate ? 'bg-emerald-500' : 'bg-slate-300'
              )}
            >
              <span className={clsx('inline-block h-4 w-4 transform rounded-full bg-white transition-transform', autoRotate ? 'translate-x-4' : 'translate-x-0.5')} />
            </button>
            <Zap className="h-4 w-4 text-emerald-600" />
            Auto-rotate on schedule
          </label>
          <div className="flex items-center gap-2">
            <select
              value={interval}
              onChange={(e) => setIntervalDays(Number(e.target.value))}
              className="rounded-lg border border-slate-200 px-2 py-1 text-sm outline-none focus:border-slate-400"
            >
              {INTERVALS.map((d) => (
                <option key={d} value={d}>{d === 0 ? 'No interval' : `Every ${d} days`}</option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => saveSchedule.mutate()}
              disabled={saveSchedule.isPending}
              className="rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {saveSchedule.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
            </button>
          </div>
        </div>
        {autoRotate && interval === 0 && (
          <p className="mt-2 text-xs text-amber-600">Pick an interval so auto-rotation actually fires.</p>
        )}
      </div>

      {/* Delivery targets */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <h4 className="text-sm font-semibold text-slate-800">Delivery targets</h4>
          <div className="flex items-center gap-2">
            <select
              value={addType}
              onChange={(e) => setAddType(e.target.value as RotationTarget['type'])}
              className="rounded-lg border border-slate-200 px-2 py-1 text-xs outline-none focus:border-slate-400"
            >
              {TARGET_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            <button
              type="button"
              onClick={add}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              <Plus className="h-3.5 w-3.5" /> Add
            </button>
          </div>
        </div>

        {targetsQuery.isLoading ? (
          <div className="flex items-center justify-center py-4">
            <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
          </div>
        ) : targetsQuery.isError ? (
          /* A failed load used to fall through to the empty state below, which
             reads as "this entry has no targets". Saving from that view sent an
             empty array and Save is a full replace, so the real targets (webhook
             HMAC secrets included, which exist nowhere else) were deleted with a
             success toast. Failure has to look like failure. */
          <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-4 text-center text-xs text-red-700">
            <p className="font-medium">Could not load the delivery targets.</p>
            <p className="mt-1">
              Nothing has been changed. Saving is disabled until they load, so an existing target cannot be overwritten by accident.
            </p>
            <button
              type="button"
              onClick={() => targetsQuery.refetch()}
              className="mt-2 rounded-lg border border-red-300 bg-white px-3 py-1 font-medium text-red-700 hover:bg-red-100"
            >
              Retry
            </button>
          </div>
        ) : working.length === 0 ? (
          <p className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-4 text-center text-xs text-slate-500">
            No delivery targets. A rotation with no targets only updates the stored value, it will not reach any consumer.
          </p>
        ) : (
          <div className="space-y-2">
            {working.map((t, i) => {
              const Icon = targetIcon(t.type);
              return (
                <div key={i} className="rounded-lg border border-slate-200 bg-white p-3">
                  <div className="mb-2 flex items-center justify-between">
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-700">
                      <Icon className="h-3.5 w-3.5 text-slate-500" />
                      {(TARGET_TYPES.find((x) => x.value === t.type) || TARGET_TYPES[0]).label}
                    </span>
                    <button type="button" onClick={() => remove(i)} className="rounded p-1 text-slate-400 hover:text-red-500" title="Remove target">
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  {/*
                    TARGET_TYPES carried a `hint` for every type that was never
                    rendered anywhere, so "Notify only: send a notification, no
                    delivery" was invisible and the option read as if it
                    delivered something.
                  */}
                  <p className="mb-2 text-xs text-slate-500">
                    {(TARGET_TYPES.find((x) => x.value === t.type) || TARGET_TYPES[0]).hint}
                  </p>
                  {t.type === 'notify' && !channelsLoading && enabledChannelCount === 0 && (
                    <p className="mb-2 flex items-start gap-1.5 rounded-md bg-amber-50 px-2 py-1.5 text-xs text-amber-700">
                      <AlertCircle className="mt-0.5 h-3 w-3 shrink-0" />
                      <span>
                        This delivers nothing right now: no notification channel is
                        enabled.{' '}
                        {isAdmin ? (
                          <a href="/settings?tab=channels" className="font-medium underline">
                            Add one in Settings, Alerts
                          </a>
                        ) : (
                          'Ask an admin to add one in Settings, Alerts.'
                        )}
                      </span>
                    </p>
                  )}
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Label" value={t.label} onChange={(v) => patch(i, { label: v })} placeholder="e.g. deploy hook" />
                    {t.type === 'webhook' && (
                      <>
                        <Field label="Webhook URL" value={t.webhook_url} onChange={(v) => patch(i, { webhook_url: v })} placeholder="https://..." />
                        <Field label="HMAC secret (optional)" value={t.webhook_secret} onChange={(v) => patch(i, { webhook_secret: v })} placeholder="signing secret" />
                      </>
                    )}
                    {t.type === 'forgejo_secret' && (
                      <>
                        <Field label="Instance URL" value={t.instance} onChange={(v) => patch(i, { instance: v })} placeholder="https://git.example.com" />
                        <Field label="Repo (owner/name)" value={t.repo} onChange={(v) => patch(i, { repo: v })} placeholder="acme/api" />
                        <Field label="Secret name" value={t.secret_name} onChange={(v) => patch(i, { secret_name: v })} placeholder="DEPLOY_KEY" />
                        <Field label="Auth token (vault entry name)" value={t.auth_token} onChange={(v) => patch(i, { auth_token: v })} placeholder="forgejo API token entry" />
                      </>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <div className="mt-3 flex items-center justify-between">
          <p className="text-xs text-slate-500">
            Targets receive the new value right after a rotation succeeds.
          </p>
          <button
            type="button"
            onClick={() => saveTargets.mutate()}
            /* Never savable from an unsettled or failed load: that is the state
               that made an accidental full-replace-with-empty possible. */
            disabled={saveTargets.isPending || targetsQuery.isLoading || targetsQuery.isError}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
          >
            {saveTargets.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save targets
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, onChange, placeholder }: { label: string; value?: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <label className="block">
      <span className="mb-0.5 block text-xs font-medium text-slate-500">{label}</span>
      <input
        type="text"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg border border-slate-200 px-2 py-1 font-mono text-xs outline-none focus:border-slate-400"
      />
    </label>
  );
}
