import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Re-locking the vault must clear EVERY piece of secret-bearing state that
// lives in this component, through exactly one chokepoint.
//
// There were six places that re-locked and each cleared a different subset:
//
//   auto-lock timer      vaultUnlocked, vaultEntries, revealedSecrets, rotatedValue
//   create / delete / update / import    vaultUnlocked, vaultEntries only
//   the explicit Lock button             all but revealedSecrets
//
// Two secrets stayed on screen as a result. The blue "New Secret Value" banner
// renders rotatedValue in cleartext and is a SIBLING of the lock bar, outside
// the vaultUnlocked ternary, so a freshly rotated secret remained visible on a
// page displaying "Vault is locked". And revealedSecrets is a set of entry ids
// whose plaintext renders, so a secret revealed before locking re-appeared in
// cleartext on the next unlock without anyone asking for it.
//
// 2026-08-15 (P1-1/P1-2/P1-3): this file used to also assert that lockVault
// "clears all four pieces of secret-bearing state" -- a hardcoded count. That
// assertion could never have caught P1-1/2/3, and it was green the entire
// time the bug was live: the actual leak was in TanStack Query's mutation
// cache (unlockVaultMutation.data / rotateSecretMutation.data, and their
// `.variables`, which is the ACCOUNT PASSWORD), none of which is a
// `setX(...)` call in this component's source. Reading source text cannot see
// a runtime cache. And "four" pins a count: every secret-bearing useState
// added since (vaultPassword, rotatePassword, editForm, newSecret, ...) was
// invisible to it by construction, so it could never have grown to match the
// surface it was meant to police.
//
// The proof that lock actually clears secret state now lives in
// vault-lock-seals-secrets.test.tsx, which builds a real QueryClient, runs
// the real mutations so the cache genuinely holds decrypted values and the
// plaintext password, drives the real Lock button, and asserts against the
// live mutation-cache object. That is a RUNTIME property; nothing that reads
// this file as text can substitute for it.
//
// What stays here is the one property source inspection genuinely can prove:
// that this component has exactly ONE re-lock chokepoint, and that every
// useState/useMutation it declares is EITHER swept by that chokepoint OR
// explicitly, visibly triaged as not secret-bearing. The second half replaces
// the old count with enumeration: a new piece of state nobody triages fails
// by NAME below, with no human required to remember to bump a number.
const vaultSrc = readFileSync(
  resolve(__dirname, '../pages/Vault.tsx'),
  'utf8'
);

// The default-exported component is the LAST top-level declaration in the
// file (checked below via the useCallback-count sanity test's sibling), so
// slicing to EOF is exactly this component's own body: no other component's
// hooks can appear in it.
const componentStart = vaultSrc.indexOf('export default function Vault()');
if (componentStart === -1) {
  throw new Error(
    'export default function Vault() not found; did the component get renamed?'
  );
}
const vaultComponentSrc = vaultSrc.slice(componentStart);

const lockVaultStart = vaultComponentSrc.indexOf(
  'const lockVault = useCallback(() => {'
);
if (lockVaultStart === -1) {
  throw new Error('lockVault no longer exists; the chokepoint is gone');
}
// lockVault is asserted to be the only useCallback in this file below, so the
// first `}, []);` after its start is unambiguously its own close.
const lockVaultEnd = vaultComponentSrc.indexOf('}, []);', lockVaultStart);
if (lockVaultEnd === -1) {
  throw new Error(
    "lockVault's closing `}, []);` was not found -- did its shape change?"
  );
}
const lockVaultBody = vaultComponentSrc.slice(lockVaultStart, lockVaultEnd);

describe('vault re-lock has exactly one chokepoint', () => {
  it('lockVault is the only useCallback in Vault.tsx', () => {
    // If a second one appears, the `}, []);` search above can no longer be
    // trusted to find the right boundary, so this has to fail loudly instead
    // of letting the rest of this file silently check the wrong span.
    const count = (vaultSrc.match(/useCallback\(/g) || []).length;
    expect(
      count,
      'a second useCallback appeared in Vault.tsx; the lockVault-body extraction above assumes there is only one and must be updated before it can be trusted'
    ).toBe(1);
  });

  it('nothing sets vaultUnlocked(false) except inside lockVault itself', () => {
    const before = vaultComponentSrc.slice(0, lockVaultStart);
    const after = vaultComponentSrc.slice(lockVaultEnd);
    const offenders: string[] = [];
    for (const [label, text] of [
      ['before lockVault', before],
      ['after lockVault', after],
    ] as const) {
      text.split('\n').forEach((line, i) => {
        if (line.includes('setVaultUnlocked(false)')) {
          offenders.push(`${label}, line ${i + 1}: ${line.trim()}`);
        }
      });
    }
    expect(
      offenders,
      'a re-lock bypasses lockVault, so it clears only some of the secret state:\n' +
        offenders.join('\n')
    ).toEqual([]);
  });

  it('every re-lock site actually calls it', () => {
    // Six sites were found by the audit; fewer would mean one was removed or
    // reverted to raw setState calls without this file noticing.
    const calls = (vaultSrc.match(/lockVault\(\);/g) || []).length;
    expect(
      calls,
      'expected the six re-lock sites (auto-lock, create, delete, update, Lock button, import)'
    ).toBeGreaterThanOrEqual(6);
  });
});

// ---------------------------------------------------------------------------
// Enumerate, don't count: every piece of state this component owns is either
// swept by lockVault or named here as deliberately left alone, with a reason.
// Adding a new useState/useMutation to the Vault component and forgetting to
// triage it fails one of the two tests below BY NAME, not by a count quietly
// going from 14 to 15.
// ---------------------------------------------------------------------------

// Non-secret component state. None of these ever hold a decrypted vault value
// or the account password, so lockVault deliberately leaves them alone.
const ALLOWED_UNSEALED_STATE = new Set([
  'setShowImportModal', // an open/closed flag; VaultImportModal owns and
  // clears its OWN file/preview/format state on submit (see its `reset()`)
  'setCollectionFilter', // a view filter: which collection tab is selected
  'setShowNewCollection', // open/closed flag for the new-collection modal
  'setNewCollection', // collection name + description, not a vault secret
  'setManageCollectionId', // which collection's manage modal is open
  'setConfirmLeaveId', // which collection has a pending "Leave" confirmation
]);

// Non-secret mutations. None of these carry a decrypted vault value or the
// account password in `.data`/`.variables`, so their cache entries are inert.
const ALLOWED_UNSEALED_MUTATIONS = new Set([
  'deleteSecretMutation', // variables is just an entry id
  'createCollectionMutation', // name + description only
  'moveToCollectionMutation', // entry id + destination collection id
  'leaveCollectionMutation', // a collection id
]);

function setterNamesIn(src: string): string[] {
  const re = /const \[\s*\w+\s*,\s*(set[A-Z]\w*)\s*\]\s*=\s*useState/g;
  return [...src.matchAll(re)].map((m) => m[1]);
}

function mutationNamesIn(src: string): string[] {
  const re = /const (\w+Mutation)\s*=\s*useMutation/g;
  return [...src.matchAll(re)].map((m) => m[1]);
}

describe('every piece of Vault state is triaged: sealed by lockVault, or explicitly allowed to survive a lock', () => {
  it('finds a non-trivial number of useState/useMutation declarations (sanity check on the extraction itself)', () => {
    // If this component gets rewritten so the regexes above stop matching
    // anything, the two tests below would vacuously pass with empty lists.
    // Pin a floor so that failure mode is loud instead of silent.
    expect(setterNamesIn(vaultComponentSrc).length).toBeGreaterThanOrEqual(14);
    expect(mutationNamesIn(vaultComponentSrc).length).toBeGreaterThanOrEqual(8);
  });

  it('every useState setter is sealed by lockVault or explicitly allow-listed as non-secret', () => {
    const setters = setterNamesIn(vaultComponentSrc);
    const untriaged = setters.filter(
      (name) =>
        !lockVaultBody.includes(`${name}(`) && !ALLOWED_UNSEALED_STATE.has(name)
    );
    expect(
      untriaged,
      'new state was added to Vault() that lockVault does not clear, and this test ' +
        'does not know it is safe. Either call it inside lockVault, or add it to ' +
        'ALLOWED_UNSEALED_STATE above with a comment proving it never holds a ' +
        'decrypted value or the account password:\n' +
        untriaged.join('\n')
    ).toEqual([]);
  });

  it('every useMutation is reset by lockVault or explicitly allow-listed as non-secret', () => {
    const mutations = mutationNamesIn(vaultComponentSrc);
    const untriaged = mutations.filter(
      (name) =>
        !lockVaultBody.includes(`${name}.reset()`) &&
        !ALLOWED_UNSEALED_MUTATIONS.has(name)
    );
    expect(
      untriaged,
      "a new mutation was added to Vault() whose cache lockVault does not reset, and " +
        "this test does not know it is safe. TanStack Query keeps a succeeded " +
        "mutation's .data AND .variables for a 5-minute gcTime by default, so an " +
        "unreset mutation is exactly how P1-1/2/3 happened: either call " +
        "`<name>.reset()` inside lockVault, or add it to ALLOWED_UNSEALED_MUTATIONS " +
        "above with a comment proving its data/variables never carry a decrypted " +
        "value or the account password:\n" +
        untriaged.join('\n')
    ).toEqual([]);
  });

  it('every allow-listed name is still real (catches a stale entry after a rename)', () => {
    const known = new Set([
      ...setterNamesIn(vaultComponentSrc),
      ...mutationNamesIn(vaultComponentSrc),
    ]);
    const stale = [
      ...ALLOWED_UNSEALED_STATE,
      ...ALLOWED_UNSEALED_MUTATIONS,
    ].filter((n) => !known.has(n));
    expect(
      stale,
      'allow-listed a name that no longer exists in Vault.tsx; remove the stale entry'
    ).toEqual([]);
  });
});
