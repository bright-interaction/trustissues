#!/usr/bin/env bash
# Produce the public fair-code mirror of Trustissues at
# github.com/bright-interaction/trustissues.
#
# Trustissues is open core: the whole trustissues/ tree ships under the Trustissues
# Sustainable Use License (self-host free, no reselling as a service). Stripped from
# the mirror's entire history: internal agent files and the audit-round bookkeeping
# that means nothing to a self-hoster. Internal infra references are redacted from
# ALL history, then the payload is secret-scanned and build-checked before any push.
#
# Safe by default: with no --push it produces + checks the filtered tree and prints
# what it WOULD push. --push performs the outward mirror.
#
# This product is a SECRETS MANAGER, so the history gates matter more here than
# anywhere else in the estate. Two precedents inform the shape of this script:
# CookieProof published with internal files in its history and needed a rewrite to
# clean them, and Dockyard's kit was completed and then deliberately HELD over
# control-plane plus vault exposure. Publishing a vault is the same judgement call,
# so this script never pushes without an explicit --push.
#
# Pattern (single-branch split-clone + gitleaks gate) mirrors
# cookieproof/hash/mesh/reactor/flare/pare. Gates live in the repo-root scripts/
# and are SOURCED, never copied: see CLAUDE.md section 15.
set -euo pipefail

PUSH=0
REMOTE_URL="git@github.com:bright-interaction/trustissues.git"
PREFIX="trustissues"
SPLIT_BRANCH="trustissues-public-split"

# Internal-ONLY paths (not app code): stripped from the mirror's entire history.
# Paths are relative to trustissues/ (the subtree split strips the prefix).
#
# docker-compose.yml deliberately STAYS: unlike CookieProof, this one IS the
# self-hoster's compose (loopback bind, the documented env list, the drain-aware
# stop_grace_period), and the README tells a new operator to use it.
#
# docker-compose.prod.yml is the opposite case and GOES: it is the estate deploy
# config the deploy-trustissues pipeline drives, it names the house proxy network
# and the house image tag, and a self-hoster who followed it would end up with a
# container attached to a network that does not exist. Same call pare made for
# its estate compose.
STRIP_PATHS=(
  CLAUDE.md
  .claude
  docker-compose.prod.yml
)

# The audit round-ups are stripped by GLOB, not by name.
#
# This list named `AUDIT-ROUND-14-PENDING.md` and nothing else, and five more
# round documents (15 through 19) appeared after it was written. Every one of
# them is a reproducible attack write-up against this exact product, several with
# the working call sequence spelled out, and they would all have been published
# while round 14 was carefully withheld. Nobody edits a strip list when they add
# a document, which is the point: a guard that recognises one spelling is the
# defect that keeps recurring across this estate (CLAUDE.md section 15 is an
# essay about the same shape in the mirror gates themselves).
#
# git filter-repo takes literal paths for --path, so globs go through
# --path-glob and are asserted separately below.
STRIP_GLOBS=(
  'AUDIT-ROUND-*.md'
)

for arg in "$@"; do
  case "$arg" in
    --push) PUSH=1 ;;
    --remote=*) REMOTE_URL="${arg#--remote=}" ;;
    -h|--help) echo "usage: $0 [--push] [--remote=git@github.com:org/repo.git]"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

command -v git-filter-repo >/dev/null 2>&1 || {
  echo "error: git-filter-repo is required (pip install git-filter-repo)." >&2; exit 1; }

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
[ -d "$PREFIX" ] || { echo "error: $PREFIX/ not found at $ROOT" >&2; exit 1; }

# Coarse pre-flight secret guard, shared by every mirror so it cannot drift again.
# The gitleaks scan on the filtered clone below stays the authoritative gate.
# shellcheck source=../../scripts/mirror-secret-preflight.sh
. "$ROOT/scripts/mirror-secret-preflight.sh"
# shellcheck source=../../scripts/mirror-enterprise-check.sh
. "$ROOT/scripts/mirror-enterprise-check.sh"
# shellcheck source=../../scripts/mirror-module-path.sh
. "$ROOT/scripts/mirror-module-path.sh"
mirror_secret_preflight "$PREFIX" "$ROOT/trustissues/scripts/mirror-secret-allowlist.txt"

echo "Splitting $PREFIX/ subtree (history-preserving) into $SPLIT_BRANCH ..."
git branch -D "$SPLIT_BRANCH" >/dev/null 2>&1 || true
git subtree split --prefix="$PREFIX" -b "$SPLIT_BRANCH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# refuse aborts a gate WITHOUT deleting the filtered tree.
#
# The cleanup trap used to fire on every exit, including a gate failure, so the
# evidence was destroyed at exactly the moment an operator needs to inspect it.
# A dry run whose output you cannot examine is not a dry run. Every refusal below
# goes through here so the tree survives for exactly that.
refuse() {
  echo "$@" >&2
  echo >&2
  echo "Filtered tree kept for inspection: $CLONE" >&2
  trap - EXIT
  exit 1
}
CLONE="$WORK/trustissues-public"
# --single-branch + --no-tags: the throwaway clone holds ONLY the disjoint subtree
# history, never the monorepo's other branches (which carry unrelated project CI
# secrets). The clone == the publish payload, which makes the gitleaks scan below
# authoritative. file:// disables the hardlink path.
echo "Cloning $SPLIT_BRANCH -> $CLONE (single-branch) ..."
git clone --quiet --single-branch --no-tags --branch "$SPLIT_BRANCH" "file://$ROOT" "$CLONE"

if [ "${#STRIP_PATHS[@]}" -gt 0 ] || [ "${#STRIP_GLOBS[@]}" -gt 0 ]; then
  FR_ARGS=()
  for p in "${STRIP_PATHS[@]}"; do FR_ARGS+=(--path "$p"); done
  for g in "${STRIP_GLOBS[@]}"; do FR_ARGS+=(--path-glob "$g"); done
  echo "Stripping internal-only paths from all history: ${STRIP_PATHS[*]} ${STRIP_GLOBS[*]}"
  ( cd "$CLONE" && git filter-repo --force --invert-paths "${FR_ARGS[@]}" )
fi

# Redact internal infra references from ALL history (file contents + commit
# messages). Distinctive tokens only, so a literal global replace is safe.
REDACT="$WORK/redactions.txt"
# Shared estate redactions + this product's extras. See CLAUDE.md section 15.
# shellcheck source=../../scripts/mirror-redactions.sh
. "$ROOT/scripts/mirror-redactions.sh"
mirror_redaction_file "$ROOT" "$ROOT/trustissues/scripts/mirror-redactions.txt" "$REDACT"
echo "Redacting internal infra references from all history ..."
( cd "$CLONE" && git filter-repo --force --replace-text "$REDACT" --replace-message "$REDACT" )

# Rewrite authors BEFORE asserting: the redaction check reads COMMIT objects too,
# so it sees the author field, and running it first flags identities this pass is
# about to fix.
mirror_rewrite_authors "$CLONE"

# Assert the redaction actually took, over every blob and commit message.
mirror_redaction_check "$CLONE" "$ROOT" "$ROOT/trustissues/scripts/mirror-redactions.txt"
mirror_blob_sanity_check "$CLONE" "$ROOT/trustissues/scripts/mirror-blob-allowlist.txt"

# Refuse closed-source code in the mirror, at HEAD and in history. A no-op for a
# product with no enterprise surface, wired in anyway so one that GAINS a surface
# is covered from its first commit.
mirror_enterprise_check "$CLONE" || exit 1

# Defense in depth: fail if a stripped path survived.
for p in "${STRIP_PATHS[@]}"; do
  [ -e "$CLONE/$p" ] && { echo "REFUSING: stripped path '$p' still present." >&2; exit 1; }
done
# Same for the globs. Two rules, both learned the hard way:
#
# 1. The survivors are captured and the CONTENT is tested, never a pipeline exit
#    status. `producer | grep -q` returns 141 on SIGPIPE under pipefail, so that
#    form reads "clean" exactly when there is most to find (CLAUDE.md section 15).
# 2. Matching is done by `find -name`, which takes the pattern as a literal
#    argument, NOT by letting the shell expand an unquoted `$g`. Shell globbing of
#    a parameter expansion is interpreter-specific: bash does it, zsh does not
#    without `${~g}`, and `set -f` disables it everywhere. A guard whose matching
#    depends on which shell invoked it is not a guard. The first draft of this
#    block used `ls -d -- $g` and reported CLEAN against a planted file.
for g in "${STRIP_GLOBS[@]}"; do
  survivors="$( find "$CLONE" -maxdepth 1 -name "$g" -print 2>/dev/null || true )"
  if [ -n "$survivors" ]; then
    echo "REFUSING: stripped glob '$g' still matches:" >&2
    echo "$survivors" >&2
    exit 1
  fi
done

# Build-check the mirror. Every gate below uses a blocking if/else, never
# `cmd && echo OK`: under `set -e` a failure on the LEFT of && is exempted, so
# those forms can only ever print OK. flare and slab both published with a
# silently failing build check because of exactly that.
echo "Build-checking the mirror (go build + vet + tests) ..."
if command -v go >/dev/null 2>&1; then
  if ( cd "$CLONE" && go build ./... >/dev/null 2>&1 ); then
    echo "  builds standalone: OK"
  else
    echo "REFUSING: the filtered mirror does not build standalone." >&2
    ( cd "$CLONE" && go build ./... ) >&2 || true
    exit 1
  fi
  if ( cd "$CLONE" && go vet ./... >/dev/null 2>&1 ); then
    echo "  go vet: OK"
  else
    echo "REFUSING: the filtered mirror does not pass go vet." >&2
    exit 1
  fi
  # The tests matter specifically because the redaction pass rewrites FIXTURE
  # values too (Shield's corpus contains host and the production IP as
  # test inputs). If a redaction breaks a test, contributors get a red suite on
  # first clone and the redactor's own coverage is silently wrong.
  if ( cd "$CLONE" && go test ./... >/dev/null 2>&1 ); then
    echo "  unit tests: OK"
  else
    echo "REFUSING: the filtered mirror FAILS its own tests; publishing would hand" >&2
    echo "          contributors a red suite. Common cause: a redaction rewrote a" >&2
    echo "          Shield test fixture into a value the pattern no longer matches." >&2
    ( cd "$CLONE" && go test ./... 2>&1 | grep -E "^(---|FAIL|\s+.*_test\.go)" | head -20 ) >&2 || true
    refuse "REFUSING: the filtered mirror fails its own tests."
  fi
else
  echo "  (go not found; skipping the Go build gate)" >&2
  [ "$PUSH" -eq 1 ] && { echo "REFUSING to --push without the build gate." >&2; exit 1; }
fi

echo "Build-checking the frontend (bun install + build + tests) ..."
if command -v bun >/dev/null 2>&1; then
  if ( cd "$CLONE/frontend" && bun install --frozen-lockfile >/dev/null 2>&1 ); then
    echo "  deps install: OK"
  else
    echo "REFUSING: the mirror's frontend deps do not install from the committed lockfile." >&2
    exit 1
  fi
  if ( cd "$CLONE/frontend" && bun run build >/dev/null 2>&1 ); then
    echo "  frontend builds: OK"
  else
    echo "REFUSING: the mirror's frontend does not build standalone." >&2
    exit 1
  fi
  if ( cd "$CLONE/frontend" && bun run test >/dev/null 2>&1 ); then
    echo "  frontend tests: OK"
  else
    echo "REFUSING: the mirror's frontend FAILS its own tests." >&2
    exit 1
  fi
else
  echo "  (bun not found; skipping the frontend gate)" >&2
  [ "$PUSH" -eq 1 ] && { echo "REFUSING to --push without the frontend gate." >&2; exit 1; }
fi

# A published module whose go.mod path is not exactly the repo it is served from
# cannot be installed by anyone. hash shipped that way for nine days.
echo "Checking the published module path resolves to this repo ..."
mirror_assert_module_path "$CLONE" "$REMOTE_URL"

# Authoritative secret scan: the single-branch clone IS the publish payload.
if command -v gitleaks >/dev/null 2>&1; then
  echo "Scanning mirror history for secrets (gitleaks) ..."
  if ! ( cd "$CLONE" && gitleaks detect --source . --config .gitleaks.toml --no-banner --redact >/dev/null 2>&1 ); then
    ( cd "$CLONE" && gitleaks detect --source . --config .gitleaks.toml --no-banner --redact ) >&2 || true
    refuse "REFUSING: gitleaks found a secret in the mirror history (above)."
  fi
  echo "  no secrets in mirror history: OK"
else
  echo "  WARNING: gitleaks not installed; the secret-scan gate is SKIPPED." >&2
  echo "  Install it before pushing: brew install gitleaks" >&2
  [ "$PUSH" -eq 1 ] && { echo "REFUSING to --push without the gitleaks gate." >&2; exit 1; }
fi

if [ "$PUSH" -eq 0 ]; then
  echo; echo "DRY RUN. Filtered mirror ready at: $CLONE"
  echo "Would push its HEAD -> $REMOTE_URL main"
  trap - EXIT  # keep $WORK so the operator can inspect the dry-run tree
  exit 0
fi

echo "Pushing filtered mirror -> $REMOTE_URL main ..."
# Force-with-lease, because mirror_rewrite_authors and the redaction passes rewrite
# EVERY commit id, so the mirror can never fast-forward over what is published. The
# lease pins the overwrite to the head we actually observed, so a commit landed
# directly on the public repo aborts the push instead of vanishing.
# shellcheck source=../../scripts/mirror-push.sh
. "$ROOT/scripts/mirror-push.sh"
mirror_force_publish "$CLONE" "$REMOTE_URL"

# Cut the release tag when this product's VERSION file names one that is not
# published yet. The push above moves main; a tag is a SEPARATE ref and was
# never pushed at all, which is how reactor shipped every 2026-07-27 audit fix
# to main while `@latest` still resolved to the vulnerable v0.1.0, and how
# trustissues repeated it a day later with vault_entries.name cleartext at its
# only tag. Non-fatal by construction: main is already published by this line,
# so a tag problem warns and never fails the publish.
# shellcheck source=../../scripts/mirror-release-tag.sh
. "$ROOT/scripts/mirror-release-tag.sh"
mirror_release_tag "$CLONE" "$REMOTE_URL"

echo "Done. Cleanup: git branch -D $SPLIT_BRANCH"
