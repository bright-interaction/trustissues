#!/usr/bin/env bash
# Every check CI runs, in one script you can also run yourself:
#
#   bash scripts/ci.sh
#
# Run it before opening a pull request and CI will not tell you anything new.
#
# WHY THE LOGIC LIVES HERE AND NOT IN .github/workflows/ci.yml
#
# Two reasons, and the second is not obvious.
#
# 1. A contributor can run it. Checks that only exist inside a workflow file are
#    checks you cannot reproduce locally, so you discover them after pushing.
#
# 2. It keeps .github/workflows/ci.yml STABLE, which is what makes automated
#    publishing possible at all. This repository is a filtered mirror, published by
#    a job authenticated with a repository deploy key. GitHub does not allow a
#    deploy key (or an OAuth token without the `workflow` scope) to create or update
#    anything under .github/workflows/, so a check that lived in the workflow file
#    would break the publish at its FINAL push, after every gate had already passed,
#    with a raw git error that reads like a mystery. With the steps in this script,
#    changing a check touches scripts/ci.sh (an ordinary file the deploy key may
#    write) and the workflow file stays untouched.
#
# The consequence to remember: editing .github/workflows/ci.yml is a rare, deliberate
# act (an action version bump, a trigger change) that needs a push from a credential
# holding the `workflow` scope. Editing THIS file needs nothing special.
set -uo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null)" 2>/dev/null || true
[ -f go.mod ] || cd trustissues 2>/dev/null || true
[ -f go.mod ] || { echo "error: run this from the Trustissues module root (the directory holding go.mod)" >&2; exit 1; }

FAILED=()
SKIPPED=()
# Exit code 99 means "this check did not run". It is distinct from pass and from fail
# on purpose: a skipped security scan that prints ok is worse than no scan at all,
# because it looks like evidence.
step() {
  local name="$1" rc; shift
  printf '\n=== %s ===\n' "$name"
  "$@"; rc=$?
  case "$rc" in
    0)  printf 'ok: %s\n' "$name" ;;
    99) printf 'SKIPPED: %s\n' "$name"; SKIPPED+=("$name") ;;
    *)  printf 'FAIL: %s\n' "$name" >&2; FAILED+=("$name") ;;
  esac
}

# Are we in the published mirror, or in the private monorepo it is cut from?
# scripts/split-public-repo.sh strips docker-compose.prod.yml (the estate deploy
# config, which names the house proxy network) from every published commit and then
# asserts it is gone, so its presence is a reliable marker. docker-compose.yml is NOT
# usable for this: that one is the self-hoster's compose and ships in both places.
IN_MIRROR=1
[ -f docker-compose.prod.yml ] && IN_MIRROR=0

# Tools outside the Go toolchain are fetched on demand, which needs network. Set
# TRUSTISSUES_CI_SKIP_TOOLS=1 to skip those checks when offline; they then report
# SKIPPED rather than passing quietly. An install that fails for any other reason is a
# FAILURE, not a skip: "I could not check" must never read as "there is nothing here".
tool() {
  local bin="$1" mod="$2" path
  if command -v "$bin" >/dev/null 2>&1; then command -v "$bin"; return 0; fi
  if [ "${TRUSTISSUES_CI_SKIP_TOOLS:-0}" = "1" ]; then return 99; fi
  go install "$mod" >/dev/null 2>&1 || { echo "could not install $bin from $mod (offline?)" >&2; return 1; }
  path="$(go env GOPATH)/bin/$bin"
  [ -x "$path" ] || { echo "installed $bin but $path is not executable" >&2; return 1; }
  printf '%s\n' "$path"
}

# gofmt exits 0 whether or not it found anything: the FILE LIST is the result, so the
# status tells you nothing and has to be ignored in favour of the output. Checked over
# TRACKED files only, so a vendored tree someone has lying around cannot fail the run.
fmt_check() {
  local unformatted files
  if git rev-parse --git-dir >/dev/null 2>&1; then
    files=$(git ls-files '*.go')
  else
    files=$(find . -name '*.go' -not -path './.git/*')
  fi
  [ -n "$files" ] || { echo "no Go files found" >&2; return 1; }
  unformatted=$(printf '%s\n' "$files" | xargs gofmt -l)
  if [ -n "$unformatted" ]; then
    echo "These files are not gofmt-clean:" >&2
    echo "$unformatted" >&2
    echo "Fix with: gofmt -w \$(git ls-files '*.go')" >&2
    return 1
  fi
  echo "every tracked Go file is gofmt-clean"
}

# RUN the tests, do not merely compile them. `go test ./... -run='^$'` compiles every
# _test.go and executes none while still printing ok, and a gate labelled "tests
# compile" was read as "tests pass" for months in a sibling repo. -count=1 disables the
# test cache, so a green run means this tree is green NOW, not that it was green once.
run_tests() {
  go test ./... -count=1 -timeout 20m
}

# Goose applies migrations in numeric order and records each applied version in its own
# table, so the FILES and that table have to agree forever. Two things break that
# agreement silently:
#
#   duplicate version  goose refuses to run at all, which turns a merge of two branches
#                      that both added 00039 into a boot failure of the deployed
#                      server rather than a CI failure.
#   missing Down half  a migration you cannot reverse is a deploy you cannot roll back,
#                      and that is decided while writing it, not during the incident.
#
# Version numbers are deliberately NOT required to be contiguous: this history has real
# gaps (00007 to 00009, 00012 to 00019, 00028) from migrations that were squashed
# before release, and a contiguity rule would have to be waived for all of them.
migrations_check() {
  local dir="internal/database/migrations" f base ver bad=0
  local seen=""
  [ -d "$dir" ] || { echo "$dir is missing (internal/database/migrations.go embeds it)" >&2; return 1; }
  for f in "$dir"/*.sql; do
    [ -e "$f" ] || { echo "no migrations found in $dir" >&2; return 1; }
    base="$(basename "$f")"
    if ! [[ "$base" =~ ^[0-9]{5}_[a-z0-9_]+\.sql$ ]]; then
      echo "$base: name must be NNNNN_lower_snake_case.sql (goose parses the numeric prefix)" >&2
      bad=1; continue
    fi
    ver=$((10#${base:0:5}))
    case " $seen " in
      *" $ver "*) echo "$base: duplicate version $ver; goose refuses to run at all" >&2; bad=1 ;;
      *) seen="$seen $ver" ;;
    esac
    grep -q '^-- +goose Up' "$f"   || { echo "$base: missing '-- +goose Up'" >&2; bad=1; }
    grep -q '^-- +goose Down' "$f" || { echo "$base: missing '-- +goose Down'; an irreversible migration is an unrollbackable deploy" >&2; bad=1; }
  done
  [ "$bad" = "0" ] || return 1
  echo "migration versions are unique and every file has both halves"
}

# The frontend is not decoration here: the Go binary serves it, and `bun run build`
# runs `tsc` first, so this is the only gate that type-checks the UI. It needs bun,
# which is the ONLY package manager this project accepts (npm resolves the overrides
# block differently and produces a tree that fails at build).
frontend_build() {
  command -v bun >/dev/null 2>&1 || {
    echo "bun is not installed, so the UI is neither type-checked nor built by this run."
    echo "Install it from https://bun.sh; npm and pnpm are not substitutes here."
    return 99
  }
  ( cd frontend && bun install --frozen-lockfile && bun run build )
}

step "build"                          go build ./...
step "vet"                            go vet ./...
step "gofmt"                          fmt_check
step "migrations"                     migrations_check
step "tests (RUN, not just compiled)" run_tests
step "frontend build + typecheck"     frontend_build

# .gitleaks.toml allowlists the change-me placeholders in .env.example and the docs, so
# pass it or the examples trip the scan and everyone learns to ignore the result.
#
# In the mirror every commit in the history is this project's, so scanning the full
# history is exactly right and is the last gate before a credential becomes
# world-readable. Upstream the history belongs to a monorepo of unrelated projects, so
# there the working tree is what matters; the publish pipeline scans the filtered
# payload's own full history separately before it pushes.
secret_scan() {
  local bin rc
  bin="$(tool gitleaks github.com/zricethezav/gitleaks/v8@latest)"; rc=$?
  [ "$rc" = "0" ] || return "$rc"
  if [ "$IN_MIRROR" = "1" ]; then
    "$bin" detect --source . --config .gitleaks.toml --no-banner --redact
  else
    "$bin" detect --source . --config .gitleaks.toml --no-git --no-banner --redact
  fi
}

vuln_scan() {
  local bin rc
  bin="$(tool govulncheck golang.org/x/vuln/cmd/govulncheck@latest)"; rc=$?
  [ "$rc" = "0" ] || return "$rc"
  "$bin" ./...
}

step "secret scan"        secret_scan
step "vulnerability scan" vuln_scan

printf '\n'
if [ ${#SKIPPED[@]} -ne 0 ]; then
  printf 'ci: %d check(s) DID NOT RUN: %s\n' "${#SKIPPED[@]}" "${SKIPPED[*]}" >&2
fi
if [ ${#FAILED[@]} -ne 0 ]; then
  # Report EVERY failure, not just the first. A run that stops at the first problem
  # costs a full round trip per issue.
  printf 'ci: %d check(s) failed: %s\n' "${#FAILED[@]}" "${FAILED[*]}" >&2
  exit 1
fi
if [ ${#SKIPPED[@]} -ne 0 ]; then
  echo "ci: every check that RAN passed, but some did not run (see above)"
  exit 0
fi
echo "ci: all checks passed"
