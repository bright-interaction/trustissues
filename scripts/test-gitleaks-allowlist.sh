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
# EVERYTHING THIS SCRIPT CHECKS IS DERIVED FROM .gitleaks.toml, NOT LISTED HERE.
#
# The first version of this guard hardcoded a 7-entry list of files to plant in,
# and grepped the config text for a `paths` key. Both halves were evadable, and
# each half alone caught the obvious attack so it looked solid:
#
#   * the grep missed `"paths" = [...]` (a TOML quoted key, which gitleaks
#     HONOURS) and missed a `paths` list living in a file that `[extend] path`
#     pulls in (also honoured).
#   * the hardcoded file list could not see an exemption added anywhere else.
#
# Combine one evasion of each and the guard is fully green while a whole-file
# exemption is live. So: the structural half PARSES the TOML instead of grepping
# it, and the planting half asks gitleaks which files this config is actually
# excusing and plants in every one of them.
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
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is not installed, so the config could not be PARSED and this guard did NOT run."
  echo "A grep over the config text is not a substitute; see the header."
  exit 99
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

# ── 1. structural: the config must not exempt anything BY PATH ───────────────
#
# Parsed, not grepped. tomllib resolves quoted keys, dotted keys and nested
# tables to the same structure, so `"paths" = [...]`, `paths=[...]` and a
# `paths` under any table all look identical here and none of them can hide.
# `[extend] path` is refused outright: it pulls in another config whose own
# allowlist this process cannot see, which is the same whole-file exemption one
# level of indirection away.
python3 - .gitleaks.toml <<'PY' || fail=1
import sys, tomllib

with open(sys.argv[1], "rb") as fh:
    cfg = tomllib.load(fh)

bad = []
def walk(node, trail):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "paths":
                bad.append(".".join(trail + [k]))
            walk(v, trail + [k])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, trail + [f"[{i}]"])

walk(cfg, [])
extend_path = cfg.get("extend", {}).get("path")
if extend_path:
    bad.append(f"extend.path -> {extend_path}")

if bad:
    print("FAIL: .gitleaks.toml exempts by PATH (or includes a config that can):")
    for b in bad:
        print(f"        {b}")
    print("      A path entry is a whole-file exemption whatever else is written")
    print("      beside it; condition = \"AND\" does not narrow it. Allowlist the")
    print("      VALUE instead, anchored, with the reason it is synthetic.")
    sys.exit(1)
print("ok: no path-keyed exemption anywhere in the parsed config")
PY

scan_json() {
  "$GITLEAKS" dir . --config "$1" --no-banner --report-format json \
    --report-path "$2" >/dev/null 2>&1 || true
  [ -f "$2" ] || echo '[]' >"$2"
}

# ── 2. the committed tree must be clean ─────────────────────────────────────
#
# Or the planting below cannot tell its own finding from a pre-existing one --
# and a value entry that has gone stale surfaces HERE, as a named file, instead
# of as a mystery gate refusal minutes before an irreversible force-push. This
# is the direction a matcher fails when it is too NARROW; the planting covers
# the too-broad direction.
scan_json .gitleaks.toml "$WORK/before.json"
if [ "$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$WORK/before.json")" != "0" ]; then
  echo "FAIL: the working tree already has findings, so this test proves nothing."
  echo "      Either a fixture changed and its allowlist entry did not, or a real"
  echo "      credential landed in the tree. Do not silence it with a path entry."
  python3 -c 'import json,sys
for f in json.load(open(sys.argv[1])): print("        %s:%s %s" % (f["File"], f["StartLine"], f["RuleID"]))' "$WORK/before.json"
  exit 1
fi
echo "ok: clean tree"

# ── 3. which files is this config actually excusing? ────────────────────────
#
# Asked, not assumed. A bare useDefault config reports every finding the real
# one suppresses, so its file set IS the blast radius of the allowlist and it
# updates itself when a fixture moves or a new one lands.
printf 'title = "bare"\n\n[extend]\nuseDefault = true\n' >"$WORK/bare.toml"
scan_json "$WORK/bare.toml" "$WORK/bare.json"
mapfile -t TARGETS < <(python3 -c 'import json,sys
print("\n".join(sorted({f["File"] for f in json.load(open(sys.argv[1]))})))' "$WORK/bare.json")

# Anti-vacuity. An empty or near-empty derived set means the derivation broke,
# and a guard that plants in nothing prints PASS having checked nothing --
# precisely the shape this file exists to refuse.
if [ "${#TARGETS[@]}" -lt 5 ]; then
  echo "FAIL: only ${#TARGETS[@]} excused file(s) derived from .gitleaks.toml."
  echo "      The derivation is broken, so this guard would plant in almost"
  echo "      nothing and still print PASS. Refusing to report either way."
  exit 1
fi
echo "ok: derived ${#TARGETS[@]} excused file(s) from the config"

# ── 4. plant a credential of EVERY family the allowlist touches ─────────────
#
# Three, not one. The single ghp_ token the first version planted could not see
# a Stripe or Twilio entry being widened -- un-anchoring
# `^sk_live_ABCDEF1234567890$` to `sk_live_[A-Za-z0-9_]+` was invisible to it.
# Each literal is assembled at runtime: writing them out would make THIS file a
# finding, which is the guard tripping over its own test data.
PLANT_GH="ghp""_""ABCDEFGHIJ0123456789abcdefghij0123456789"
PLANT_STRIPE="sk""_live_""9RtQ4vWxYz7BnMkLpJhGfDsA"
PLANT_TWILIO="SK""9f8e7d6c5b4a39281706f5e4d3c2b1a0"
WANT_RULES="github-pat stripe-access-token twilio-api-key"

CURRENT=""
# Always returns 0. Bash exits with the status of the EXIT trap's last command,
# so a restore() that ends in a failed test would turn a PASS into exit 1.
restore() {
  if [ -n "$CURRENT" ] && [ -f "$WORK/target.bak" ]; then
    mv -f "$WORK/target.bak" "$CURRENT"
  fi
  rm -rf "$WORK"
  return 0
}
trap restore EXIT

for t in "${TARGETS[@]}"; do
  if [ ! -f "$t" ]; then
    echo "FAIL: $t was reported by the bare scan but does not exist; the derivation is wrong"
    fail=1
    continue
  fi
  CURRENT="$t"
  cp "$t" "$WORK/target.bak"
  {
    printf '\n// planted by scripts/test-gitleaks-allowlist.sh: %s\n' "$PLANT_GH"
    printf '// planted by scripts/test-gitleaks-allowlist.sh: %s\n' "$PLANT_STRIPE"
    printf '// planted by scripts/test-gitleaks-allowlist.sh: %s\n' "$PLANT_TWILIO"
  } >>"$t"
  scan_json .gitleaks.toml "$WORK/after.json"
  mv -f "$WORK/target.bak" "$t"
  CURRENT=""
  missing="$(python3 -c 'import json,sys
found={f["RuleID"] for f in json.load(open(sys.argv[1]))}
print(" ".join(r for r in sys.argv[2].split() if r not in found))' "$WORK/after.json" "$WANT_RULES")"
  if [ -n "$missing" ]; then
    echo "FAIL: credentials planted in $t were NOT reported: $missing"
    echo "      The allowlist is exempting the file, or the entry for that family"
    echo "      is broader than the one value it is meant to excuse."
    fail=1
  else
    echo "ok: refused all three planted families in $t"
  fi
done

[ "$fail" = "0" ] || exit 1
echo "PASS"
