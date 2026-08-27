import clsx from 'clsx';
import { Lock, ShieldCheck } from 'lucide-react';
import type { CollectionPrivateAccessPolicy } from '@/lib/types';

export interface CollectionPrivateAccessOption {
  value: CollectionPrivateAccessPolicy;
  label: string;
  shortLabel: string;
  description: string;
}

export const COLLECTION_PRIVATE_ACCESS_OPTIONS: readonly CollectionPrivateAccessOption[] = [
  {
    value: 'standard',
    label: 'Standard access',
    shortLabel: 'Standard',
    description:
      'Normal authenticated HTTPS access. Use this for client collections that must work without your internal private network.',
  },
  {
    value: 'sensitive_private',
    label: 'Private for secret actions',
    shortLabel: 'Private actions',
    description:
      'Metadata stays visible normally; revealing, changing, exporting, or rotating secrets requires the private URL.',
  },
  {
    value: 'fully_private',
    label: 'Private for all access',
    shortLabel: 'Private only',
    description:
      'The collection and its entries are hidden on the normal URL. Every operation requires the private URL.',
  },
] as const;

export function normalizeCollectionPrivateAccessPolicy(
  policy: CollectionPrivateAccessPolicy | undefined
): CollectionPrivateAccessPolicy {
  return policy ?? 'standard';
}

export function collectionPrivateAccessOption(
  policy: CollectionPrivateAccessPolicy | undefined
): CollectionPrivateAccessOption {
  const normalized = normalizeCollectionPrivateAccessPolicy(policy);
  return (
    COLLECTION_PRIVATE_ACCESS_OPTIONS.find((option) => option.value === normalized) ??
    COLLECTION_PRIVATE_ACCESS_OPTIONS[0]
  );
}

export function CollectionAccessBadge({
  policy,
  inverted = false,
}: {
  policy: CollectionPrivateAccessPolicy | undefined;
  inverted?: boolean;
}) {
  const option = collectionPrivateAccessOption(policy);
  if (option.value === 'standard') return null;

  const Icon = option.value === 'fully_private' ? Lock : ShieldCheck;
  return (
    <span
      title={option.description}
      aria-label={`${option.shortLabel}: ${option.description}`}
      className={clsx(
        'inline-flex items-center gap-1 rounded-full px-1.5 py-0.5 text-[10px] font-semibold leading-none',
        inverted
          ? 'bg-white/20 text-white'
          : option.value === 'fully_private'
            ? 'bg-indigo-100 text-indigo-700'
            : 'bg-sky-100 text-sky-700'
      )}
    >
      <Icon className="h-2.5 w-2.5" aria-hidden="true" />
      {option.shortLabel}
    </span>
  );
}

export default function CollectionPrivateAccessPolicyField({
  value,
  onChange,
  disabled = false,
  canSelectProtected = true,
  name = 'private_access_policy',
}: {
  value: CollectionPrivateAccessPolicy | undefined;
  onChange: (policy: CollectionPrivateAccessPolicy) => void;
  disabled?: boolean;
  // Creating, promoting, or downgrading a protected collection is admitted
  // only by private ingress. Callers pass false until /health proves this page
  // is on that listener, avoiding a form that invites a guaranteed 403.
  canSelectProtected?: boolean;
  name?: string;
}) {
  const normalized = normalizeCollectionPrivateAccessPolicy(value);
  const protectedPolicy = normalized !== 'standard';

  return (
    <fieldset disabled={disabled} className="space-y-2">
      <legend className="text-xs font-medium text-slate-600">Private access</legend>
      <div className="grid gap-2">
        {COLLECTION_PRIVATE_ACCESS_OPTIONS.map((option) => {
          const selected = normalized === option.value;
          const optionDisabled =
            disabled || (!canSelectProtected && option.value !== 'standard');
          return (
            <label
              key={option.value}
              className={clsx(
                'flex cursor-pointer gap-2.5 rounded-lg border bg-white p-3 transition-colors',
                selected
                  ? 'border-slate-700 ring-1 ring-slate-700'
                  : 'border-slate-200 hover:border-slate-300',
                optionDisabled && 'cursor-not-allowed opacity-60'
              )}
            >
              <input
                type="radio"
                name={name}
                value={option.value}
                checked={selected}
                disabled={optionDisabled}
                onChange={() => onChange(option.value)}
                className="mt-0.5 h-3.5 w-3.5 border-slate-300 text-slate-900 focus:ring-slate-500"
              />
              <span className="min-w-0">
                <span className="block text-xs font-semibold text-slate-800">{option.label}</span>
                <span className="mt-0.5 block text-xs leading-4 text-slate-500">
                  {option.description}
                </span>
              </span>
            </label>
          );
        })}
      </div>
      <div
        role="note"
        className={clsx(
          'rounded-lg border px-3 py-2 text-xs leading-4',
          protectedPolicy
            ? 'border-amber-200 bg-amber-50 text-amber-800'
            : 'border-slate-200 bg-slate-50 text-slate-600'
        )}
      >
        {!canSelectProtected ? (
          <>
            Protected policy changes are available only on the private
            TrustIssues URL. Connect to your team network and open that address;
            ask your administrator for it if needed. Standard client collections
            remain available here.
          </>
        ) : protectedPolicy ? (
          <>
            Configure and test the private URL first. Protected policies must be saved from and
            later used through that URL; a fully private collection may disappear from the normal
            URL.
          </>
        ) : (
          <>Client-facing collections normally stay on standard access.</>
        )}{' '}
        Private-network access is an extra gate. It does not replace sign-in, MFA, collection
        roles, or audit logging.
      </div>
    </fieldset>
  );
}
