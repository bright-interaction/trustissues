#!/usr/bin/env bash
# test-gitleaks-allowlist.sh - watch the allowlist REFUSE before trusting it.
#
# .gitleaks.toml used to exempt five locations BY PATH, entire files:
# internal/shield/testdata/.*, and the _test.go of shield, handlers, config and
# columncrypto, plus scripts/mirror-secret-allowlist.txt. Those are exactly the
# files where somebody reproducing a production leak pastes the real credential
# to see whether Shield catches it, and they publish to the open-source mirror.
#
# Measured on gitleaks 8.30.1: a ghp_-shaped token planted in any of them scanned
# CLEAN under that config and DIRTY under the default ruleset, because gitleaks
# resolves `paths` and `regexes` as OR even with condition = "AND". GitHub push
# protection blocked a fixture split-public-repo.sh had already passed, which is
# how it surfaced. The exemptions are keyed BY VALUE now.
#
# That change is only worth anything if an unmarked credential is actually
# reported, so this plants one in every formerly-exempt location and checks.
#
# It checks BOTH directions on purpose. A matcher can fail by refusing
# everything too: if the value entries were wrong the committed tree itself would
# be dirty, and the clean-tree precondition below is what catches that.
set -euo pipefail

cd "$(dirname "$0")/.."
GITLEAKS="${GITLEAKS:-gitleaks}"
# Exit 99 (scripts/ci.sh's did-not-run code), never 0. A security guard that
# prints ok because its scanner is missing is worse than no guard: it looks like
# evidence. ci.sh resolves the binary and passes it in GITLEAKS.
if ! command -v "$GITLEAKS" >/dev/null 2>&1; then
  echo "gitleaks is not installed, so the allowlist guard did NOT run."
  echo "Install it (brew install gitleaks) or set GITLEAKS=/path/to/gitleaks."
  exit 99
fi

scan() { "$GITLEAKS" dir . --config .gitleaks.toml --no-banner --redact 2>&1 || true; }

# Count "no leaks found", not "leaks found": the latter is a SUBSTRING of the
# former, so a clean tree read as dirty in the sibling copy of this test. Same
# family as the `producer | grep -q` pipefail trap in CLAUDE.md 15b, and the same
# lesson: assert on the content you actually mean.
clean() { printf '%s\n' "$1" | grep -c 'no leaks found' || true; }

fail=0

# 1. The config must carry no `paths` key at all. This is the cheap structural
#    half: the planted-secret cases below would catch a re-added path entry for
#    the locations they name, but not for a location added later, and this does.
if grep -qE '^[[:space:]]*paths[[:space:]]*=' .gitleaks.toml; then
  echo "FAIL: .gitleaks.toml has a \`paths\` key. A path entry is a whole-file"
  echo "      exemption whatever else is written beside it (condition = \"AND\""
  echo "      does not narrow it). Allowlist the VALUE instead."
  fail=1
else
  echo "ok: no \`paths\` key in .gitleaks.toml"
fi

# 2. The tree as committed must be clean, or the planted-secret assertions cannot
#    tell their own finding from a pre-existing one -- and a value entry that has
#    gone stale shows up here rather than as a mystery gate refusal at publish.
before="$(scan)"
if [ "$(clean "$before")" -eq 0 ]; then
  echo "FAIL: the working tree already has findings, so this test proves nothing."
  echo "      Either a fixture changed and its allowlist entry did not, or a real"
  echo "      credential landed in the tree. Do not silence it with a path entry."
  printf '%s\n' "$before"
  exit 1
fi
echo "ok: clean tree"

# 3. Plant an unmarked credential in every location the old config exempted
#    wholesale. The literal is assembled at runtime: writing it out here would
#    make THIS file a finding, which is the guard tripping over its own test data
#    (the estate has shipped that shape before -- a gate that refused its own
#    source). ghp_ is the shape GitHub push protection caught while this gate
#    said OK.
TARGETS=(
  internal/shield/redact_hostname_test.go
  internal/shield/marker_forgery_test.go
  internal/shield/testdata/pii.corpus
  internal/handlers/capability_test.go
  internal/config/config_hint_test.go
  internal/columncrypto/columncrypto_test.go
  scripts/mirror-secret-allowlist.txt
)
PLANTED="ghp""_""ABCDEFGHIJ0123456789abcdefghij0123456789"
CURRENT=""
# Always returns 0. Bash exits with the status of the EXIT trap's last command,
# so a restore() that ends in a failed test would turn a PASS into exit 1.
restore() {
  if [ -n "$CURRENT" ] && [ -f "$CURRENT.allowlisttest.bak" ]; then
    mv -f "$CURRENT.allowlisttest.bak" "$CURRENT"
  fi
  return 0
}
trap restore EXIT

for t in "${TARGETS[@]}"; do
  # A missing target is a FAIL, never a skip. If a file is renamed and this list
  # is not, the guard quietly stops covering that location while still printing
  # PASS, which is the exact failure mode it exists to prevent.
  if [ ! -f "$t" ]; then
    echo "FAIL: $t does not exist; this guard has stopped covering it. Re-point"
    echo "      the TARGETS list rather than dropping the entry."
    fail=1
    continue
  fi
  CURRENT="$t"
  cp "$t" "$t.allowlisttest.bak"
  printf '\n// planted by scripts/test-gitleaks-allowlist.sh: %s\n' "$PLANTED" >> "$t"
  after="$(scan)"
  mv -f "$t.allowlisttest.bak" "$t"
  CURRENT=""
  if [ "$(clean "$after")" -gt 0 ]; then
    echo "FAIL: an unmarked credential planted in $t was NOT reported."
    echo "      The allowlist is exempting the file rather than the value."
    fail=1
  else
    echo "ok: refused an unmarked credential in $t"
  fi
done

[ "$fail" = "0" ] || exit 1
echo "PASS"
