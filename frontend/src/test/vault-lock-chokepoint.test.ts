import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Re-locking the vault must clear EVERY piece of secret-bearing state.
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
// This guard is STRUCTURAL, and that is a deliberate compromise worth naming.
// The property is "there is exactly one chokepoint", which is a statement about
// the source rather than about one behaviour, and the alternative (rendering a
// 2,600-line page component with its whole query/router/toast environment) would
// test one path while the bug is precisely about the paths nobody thought of.
// The estate uses this same shape for its transaction-scope rule.
//
// The known limit: this cannot see whether lockVault's BODY is still correct, so
// the body is asserted separately below.
const vaultSrc = readFileSync(
  resolve(__dirname, '../pages/Vault.tsx'),
  'utf8'
);

describe('vault re-lock has one chokepoint', () => {
  it('nothing sets vaultUnlocked(false) except lockVault itself', () => {
    const lines = vaultSrc.split('\n');
    const defIdx = lines.findIndex((l) => l.includes('const lockVault = useCallback'));
    expect(defIdx, 'lockVault no longer exists; the chokepoint is gone').toBeGreaterThan(-1);

    // The only permitted occurrence is the one inside the definition.
    const offenders: string[] = [];
    lines.forEach((line, i) => {
      if (!line.includes('setVaultUnlocked(false)')) return;
      const insideDefinition = i > defIdx && i < defIdx + 8;
      if (!insideDefinition) offenders.push(`Vault.tsx:${i + 1}: ${line.trim()}`);
    });

    expect(
      offenders,
      'a re-lock bypasses lockVault, so it clears only some of the secret state:\n' +
        offenders.join('\n')
    ).toEqual([]);
  });

  it('lockVault clears all four pieces of secret-bearing state', () => {
    const start = vaultSrc.indexOf('const lockVault = useCallback');
    expect(start).toBeGreaterThan(-1);
    const body = vaultSrc.slice(start, start + 400);

    for (const required of [
      'setVaultUnlocked(false)',
      'setVaultEntries([])',
      'setRevealedSecrets(new Set())',
      'setRotatedValue(null)',
    ]) {
      expect(
        body.includes(required),
        `lockVault no longer does ${required}, so locking leaves a secret on screen`
      ).toBe(true);
    }
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
