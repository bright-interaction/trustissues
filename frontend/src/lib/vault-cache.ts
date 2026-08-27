import type { CustomField, VaultEntry } from './vault-types';

/**
 * Merge an ordinary custom-field response into an already revealed array.
 *
 * Withheld fields are position-bound by the backend. Matching by label alone
 * would borrow a secret from the wrong duplicate/reordered row, so a mismatch
 * stays withheld and blank rather than guessing.
 */
export function mergeUnlockedCustomFields(
  revealed: CustomField[] | null | undefined,
  incoming: CustomField[] | null | undefined
): CustomField[] | null | undefined {
  if (incoming === undefined) return revealed;
  if (incoming === null) return null;
  return incoming.map((field, index) => {
    if (!field.withheld) return field;
    // Mirror the backend's only valid preservation marker. Anything broader
    // remains visibly withheld instead of becoming a client-side overwrite
    // primitive.
    if (!field.secret || field.value !== '') return field;
    const prior = revealed?.[index];
    if (
      !prior ||
      prior.withheld ||
      prior.label !== field.label ||
      prior.secret !== field.secret
    ) {
      return field;
    }
    const { withheld: _withheld, ...visibleField } = field;
    return { ...visibleField, value: prior.value };
  });
}

function parseObject(raw: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(raw || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/** Retain only the provider keys the server explicitly says it withheld. */
export function mergeUnlockedProviderMeta(
  revealedRaw: string | undefined,
  incomingRaw: string | undefined,
  withheldKeys: string[] | undefined
): string | undefined {
  if (incomingRaw === undefined) return revealedRaw;
  if (!withheldKeys?.length) return incomingRaw;

  const revealed = parseObject(revealedRaw ?? '{}');
  const incoming = parseObject(incomingRaw);
  if (!revealed || !incoming) return revealedRaw;

  // Null-prototype output prevents a hostile/legacy "__proto__" key from
  // invoking an object setter while values are copied.
  const merged: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(incoming)) merged[key] = value;
  for (const key of withheldKeys) {
    if (Object.prototype.hasOwnProperty.call(revealed, key)) merged[key] = revealed[key];
  }
  return JSON.stringify(merged);
}

/** Merge a metadata/write echo without resealing values already unlocked. */
export function mergeUnlockedVaultEntry(
  revealed: VaultEntry,
  incoming: Partial<VaultEntry>
): VaultEntry {
  // Provider credentials belong to one adapter relationship. A response that
  // explicitly moves the entry to another provider must never satisfy that
  // provider's withheld marker from the previous provider's cache, even when
  // both happen to use the same metadata key. This can occur on a cross-tab
  // provider change racing a rotate response. Callers that just submitted the
  // new provider rebase `revealed` to that submitted pair before calling us.
  const sameProvider =
    incoming.provider === undefined || incoming.provider === revealed.provider;
  return {
    ...revealed,
    ...incoming,
    provider_meta: mergeUnlockedProviderMeta(
      sameProvider ? revealed.provider_meta : undefined,
      incoming.provider_meta,
      incoming.provider_meta_withheld
    ),
    custom_fields: mergeUnlockedCustomFields(
      revealed.custom_fields,
      incoming.custom_fields
    ),
  };
}
