import type { VaultEntry } from './vault-types';

export type CredentialIssueKind = 'weak' | 'reused' | 'old';

export interface CredentialHealthIssue {
  entryId: string;
  entryName: string;
  kinds: CredentialIssueKind[];
  reasons: string[];
}

export interface CredentialHealthReport {
  checked: number;
  healthy: number;
  weak: number;
  reused: number;
  old: number;
  issues: CredentialHealthIssue[];
}

const COMMON = new Set([
  'password', 'password1', 'password123', 'admin', 'admin123', 'letmein',
  'welcome', 'welcome1', 'qwerty', 'qwerty123', '12345678', '123456789',
  'iloveyou', 'monkey', 'dragon', 'football', 'trustno1',
]);

const DAY_MS = 24 * 60 * 60 * 1000;
const OLD_AFTER_DAYS = 365;

function credentialLike(entry: VaultEntry): boolean {
  return Boolean(entry.value) && (
    entry.category === 'login' ||
    entry.category === 'password' ||
    Boolean(entry.username) ||
    Boolean(entry.url)
  );
}

function weakReasons(entry: VaultEntry): string[] {
  const value = entry.value ?? '';
  const lower = value.toLowerCase();
  const reasons: string[] = [];
  if (value.length < 14) reasons.push('fewer than 14 characters');
  if (COMMON.has(lower)) reasons.push('appears in the built-in common-password list');
  if (/^(.{1,4})\1{2,}$/.test(value)) reasons.push('is a repeated pattern');
  if (/(?:012345|123456|234567|345678|456789|abcdef|qwerty|asdfgh)/i.test(value)) {
    reasons.push('contains an easy sequence');
  }

  const classes = [/[a-z]/.test(value), /[A-Z]/.test(value), /\d/.test(value), /[^A-Za-z0-9]/.test(value)]
    .filter(Boolean).length;
  if (classes < 2 && value.length < 20) reasons.push('uses one character class');

  const username = entry.username.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (username.length >= 4 && lower.replace(/[^a-z0-9]/g, '').includes(username)) {
    reasons.push('contains the username');
  }
  return Array.from(new Set(reasons));
}

function credentialAgeDays(entry: VaultEntry, now: Date): number | null {
  const raw = entry.last_rotated_at || entry.updated_at || entry.created_at;
  if (!raw) return null;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return null;
  return Math.floor((now.getTime() - date.getTime()) / DAY_MS);
}

// Runs only over the already-unlocked in-memory entries. It never hashes,
// persists, logs, or sends a password anywhere. Exact-value comparison is what
// makes reuse detection authoritative without creating a second credential
// database in localStorage or on the server.
export function analyzeCredentialHealth(
  allEntries: VaultEntry[],
  now = new Date(),
): CredentialHealthReport {
  const entries = allEntries.filter(credentialLike);
  const valueOwners = new Map<string, string[]>();
  for (const entry of entries) {
    const value = entry.value ?? '';
    const owners = valueOwners.get(value) ?? [];
    owners.push(entry.id);
    valueOwners.set(value, owners);
  }

  const issues: CredentialHealthIssue[] = [];
  let weak = 0;
  let reused = 0;
  let old = 0;

  for (const entry of entries) {
    const kinds: CredentialIssueKind[] = [];
    const reasons = weakReasons(entry);
    if (reasons.length > 0) {
      kinds.push('weak');
      weak++;
    }
    if ((valueOwners.get(entry.value ?? '')?.length ?? 0) > 1) {
      kinds.push('reused');
      reasons.push('is reused by another vault entry');
      reused++;
    }
    const age = credentialAgeDays(entry, now);
    if (age !== null && age > OLD_AFTER_DAYS) {
      kinds.push('old');
      reasons.push(`has not been changed for ${age} days`);
      old++;
    }
    if (kinds.length > 0) {
      issues.push({ entryId: entry.id, entryName: entry.name, kinds, reasons });
    }
  }

  return {
    checked: entries.length,
    healthy: entries.length - issues.length,
    weak,
    reused,
    old,
    issues,
  };
}
