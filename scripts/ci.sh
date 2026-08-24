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
#
# EVERY MODULE BELOW IS VERSION-PINNED. These two binaries are the secret scan and
# the vulnerability scan -- the two checks whose whole job is to refuse a build --
# and they were installed with @latest, so the gate that decides whether this repo
# may publish was whatever version those projects shipped that morning. That is an
# unreviewed third-party upgrade on every CI run, executed in a job holding the
# checkout, and a supply-chain compromise of either module reaches the pipeline
# before anybody reads a release note. Pinning also makes the scanners' own
# behaviour reproducible: an @latest scanner that starts or stops reporting a
# finding changes this repository's verdict with no commit behind it.
#
# Bumping one of these is a deliberate act: change the version here, run the suite,
# and land it as its own commit so the diff records which scanner moved.
# THE PIN HAS TO BE WHAT ACTUALLY RUNS.
#
# This used to return any binary of that name already on PATH before it
# considered the pinned module. So on a developer machine an older -- or planted
# -- gitleaks decided this repository's verdict while the pin guard reported
# everything pinned, and the comment above claiming "EVERY MODULE BELOW IS
# VERSION-PINNED" was true of the source and false of the process. CI runners
# escaped only by luck: neither scanner happens to be preinstalled there.
#
# `go install module@version` is content-addressed and cached, so resolving the
# pin on every run costs nothing after the first and buys the property the pin
# was for. Correctness outranks a second of warm-cache install time in a gate
# whose job is refusing builds.
tool() {
  local bin="$1" mod="$2" path
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

# The e2e suite is behind `-tags e2e`, so `go test ./...` above does NOT run it:
# without this step it would compile in nobody's pipeline and prove nothing, which
# is the exact shape of a sibling repo's regression test that skipped in CI and in
# the deploy pipeline for months while being cited as coverage.
#
# It builds the real server binary and drives it over HTTP, because the question
# it answers cannot be answered by a handler test: can a person starting from an
# empty database reach the gated state and get back out of it? The production
# instance has one admin with totp_enabled=0 and UpdateVaultPolicy refuses to
# enable require_totp unless the acting admin is enrolled, so the whole feature
# was unreachable in production while every unit test passed.
run_e2e() {
  go test -tags e2e ./internal/e2e/ -count=1 -timeout 10m
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

# THE FRONTEND TESTS, WHICH THIS SCRIPT DID NOT RUN UNTIL NOW.
#
# frontend_build above is `tsc && vite build`. It type-checks and it bundles.
# It does not execute a single test. So every case under frontend/src/test --
# and that includes vault-lock-seals-secrets.test.tsx, the RUNTIME proof that
# locking the vault evicts the decrypted values AND the account password from
# the TanStack Query mutation cache -- passed on the author's laptop and was
# never once executed by this pipeline. The suite existed, the gate was green,
# and those two facts had nothing to do with each other.
#
# That is the same defect class as run_tests' warning one level further out:
# there the tests compiled and did not run, here the RUNNER was never invoked.
# "The gate is green" and "the guards run" are separate claims and only the
# second one is worth anything.
#
# `bun run test` is `vitest run`, which is the non-watch mode; the watch mode
# would hang a CI job forever. vitest exits non-zero when it matches no test
# files at all (verified by moving src/test aside: exit 1), so deleting or
# renaming the suite turns this step RED instead of quietly passing it.
frontend_tests() {
  command -v bun >/dev/null 2>&1 || {
    echo "bun is not installed, so the frontend test suite did NOT run."
    echo "Install it from https://bun.sh; npm and pnpm are not substitutes here."
    return 99
  }
  ( cd frontend && bun install --frozen-lockfile && bun run test )
}

step "build"                          go build ./...
step "vet"                            go vet ./...
step "gofmt"                          fmt_check
step "migrations"                     migrations_check
step "tests (RUN, not just compiled)" run_tests
step "e2e against the real binary"    run_e2e
step "frontend build + typecheck"     frontend_build
step "frontend tests (RUN)"           frontend_tests

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
  bin="$(tool gitleaks github.com/zricethezav/gitleaks/v8@v8.30.1)"; rc=$?
  [ "$rc" = "0" ] || return "$rc"
  if [ "$IN_MIRROR" = "1" ]; then
    "$bin" detect --source . --config .gitleaks.toml --no-banner --redact
  else
    "$bin" detect --source . --config .gitleaks.toml --no-git --no-banner --redact
  fi
}

# The secret scan above is only as good as what its allowlist still reports.
# .gitleaks.toml used to exempt five locations BY PATH -- including Shield's own
# fixtures and testdata -- and a path entry is a whole-file exemption whatever
# else is written beside it, so a real credential pasted into any of them scanned
# clean while GitHub push protection blocked it. This plants an unmarked
# credential in each of those locations and asserts the refusal, so the gate
# above cannot go blind again without this step going red.
allowlist_guard() {
  local bin rc
  [ -f scripts/test-gitleaks-allowlist.sh ] || {
    echo "scripts/test-gitleaks-allowlist.sh is missing; nothing proves the secret scan still reports" >&2
    return 1
  }
  bin="$(tool gitleaks github.com/zricethezav/gitleaks/v8@v8.30.1)"; rc=$?
  [ "$rc" = "0" ] || return "$rc"
  GITLEAKS="$bin" bash scripts/test-gitleaks-allowlist.sh
}

vuln_scan() {
  local bin rc
  bin="$(tool govulncheck golang.org/x/vuln/cmd/govulncheck@v1.7.0)"; rc=$?
  [ "$rc" = "0" ] || return "$rc"
  "$bin" ./...
}

# scripts/frontend-audit-allowlist.txt holds reviewed, time-boxed exceptions:
# "<GHSA-id or numeric advisory id> <expiry YYYY-MM-DD> <reason...>", one per line.
# An entry whose expiry has passed is skipped here, so the advisory reasserts itself
# and fails frontend_dep_scan again until someone actually re-reviews it. Without this,
# the first advisory that has no fix yet (a patch that does not exist, or only lands in
# a major nobody has budgeted to migrate to) is exactly the kind of thing that gets
# someone to delete the whole check instead of triaging it once and moving on.
#
# The expiry field is VALIDATED, not trusted: a line with a missing or malformed
# second field (a typo, a tab where a space belongs, someone pasting only the id) must
# never resolve to a permanent silent exemption. If "${line#* }" finds nothing to
# strip, expiry ends up equal to id, and "GHSA-..." sorts before every digit string in
# a plain string compare, so an unguarded expiry check would treat that entry as
# never-expiring. Reject the shape instead: on a bad line, print why and signal the
# caller with a non-zero return so the WHOLE step is treated as did-not-run (99), not
# as a pass with an unknown, possibly-permanent set of findings suppressed.
frontend_audit_ignore_flags() {
  local file="scripts/frontend-audit-allowlist.txt" today line id expiry
  [ -f "$file" ] || return 0
  today="$(date +%Y-%m-%d)"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    id="${line%% *}"
    expiry="${line#* }"
    expiry="${expiry%% *}"
    if ! [[ "$expiry" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
      echo "frontend audit allowlist: malformed line (need '<id> <YYYY-MM-DD> <reason>'): $line" >&2
      return 2
    fi
    if [[ "$today" > "$expiry" ]]; then
      echo "frontend audit allowlist: expired, no longer ignored: $line" >&2
      continue
    fi
    printf '%s\n' "--ignore=$id"
  done < "$file"
}

# The bun-audit counterpart to vuln_scan above, and the only scanner that ever looks at
# the half of this app that decrypts and renders plaintext secrets in a browser. bun
# needs nothing extra installed beyond what frontend_build already requires, but unlike
# govulncheck's vulndb there is no offline mode: bun audit makes a live registry round
# trip on EVERY run, a clean pass prints nothing beyond its own banner, and a network
# failure also exits non-zero with no "N vulnerabilities (" line, so a network failure
# and a real pass cannot be told apart by exit code alone. They are told apart by
# content below: a genuine finding always ends in a literal "N vulnerabilities (...)"
# summary line with a digit immediately before it; a registry failure never produces
# that shape (a bare substring match on "vulnerabilit" would also fire on an unrelated
# error message that happens to mention a vulnerability database), and only the first
# case is a FAIL.
#
# --audit-level=high fails the build on HIGH and CRITICAL only, matching the threshold
# already standardized on this estate's other two Bun frontends (bright-interaction
# -website, hash/frontend). LOW and MODERATE transitive findings are noise at the rate
# the npm ecosystem produces them, and gating on every one of them is how a security
# check gets disabled within a week; run `bun audit` with no level for the full list.
frontend_dep_scan() {
  command -v bun >/dev/null 2>&1 || {
    echo "bun is not installed, so frontend dependencies are not scanned by this run."
    echo "Install it from https://bun.sh; npm and pnpm are not substitutes here."
    return 99
  }
  [ -f frontend/bun.lock ] || {
    echo "frontend/bun.lock is missing, so there is no lockfile to audit."
    return 99
  }
  local ignore_output rc out
  ignore_output="$(frontend_audit_ignore_flags)"; rc=$?
  if [ "$rc" != "0" ]; then
    echo "frontend dependency scan cannot run: the advisory allowlist is malformed, so what it exempts is unknown (see above)." >&2
    return 99
  fi
  # Bash < 4.4 (stock /bin/bash on macOS is 3.2) raises "unbound variable" under
  # set -u when expanding "${arr[@]}" on a zero-element array, so the empty case is
  # kept on a separate branch rather than always expanding ignore_flags.
  local -a ignore_flags=()
  if [ -n "$ignore_output" ]; then
    while IFS= read -r flag; do ignore_flags+=("$flag"); done <<< "$ignore_output"
  fi
  if [ "${#ignore_flags[@]}" -gt 0 ]; then
    out="$(cd frontend && bun audit --audit-level=high "${ignore_flags[@]}" 2>&1)"; rc=$?
  else
    out="$(cd frontend && bun audit --audit-level=high 2>&1)"; rc=$?
  fi
  printf '%s\n' "$out"
  [ "$rc" = "0" ] && return 0
  case "$out" in
    *[0-9]" vulnerabilities ("*) return 1 ;;
    *)
      echo "bun audit did not complete, most likely no network to the registry; treating as did-not-run, never as a pass." >&2
      return 99
      ;;
  esac
}

# THE BACKUP/RESTORE SUITE, ALSO NEVER RUN BY CI UNTIL NOW.
#
# scripts/test-backup-restore.sh is ~50 cases over backup.sh, restore.sh,
# prune-backups.sh, restore-drill.sh and the systemd units in deploy/. Among
# them is the byte-level proof that a securely deleted snapshot leaves no
# plaintext on disk. `go test ./...` cannot reach any of it: it is a shell
# suite, because the code it guards is shell. Nothing else invoked it, so the
# only thing standing between that code and a regression was somebody
# remembering to run it by hand.
#
# It is deliberately the LAST step. With docker present it builds a throwaway
# image and drives real Compose restores, which makes it the slowest check here
# by an order of magnitude, and every step above it has already reported by the
# time it starts.
#
# A run that SKIPPED cases is reported as did-not-run, not as ok. The suite
# exits 0 when the Compose cases could not run (no docker) because the ~40
# cases that did run all passed, and that is a true statement about a narrower
# claim than this gate is asserting. 99 keeps the distinction: on a runner with
# docker -- which ubuntu-latest has -- nothing skips and this is a plain pass
# or fail.
backup_restore_tests() {
  [ -f scripts/test-backup-restore.sh ] || {
    echo "scripts/test-backup-restore.sh is missing; the backup path is unguarded" >&2
    return 1
  }
  command -v sqlite3 >/dev/null 2>&1 || {
    echo "sqlite3 is not installed, so the backup/restore suite did NOT run."
    echo "Install it (apt-get install -y sqlite3); the suite builds its fixtures with it."
    return 99
  }
  local log rc
  log="$(mktemp)" || log=""
  # A temp file we could not create is not a detail to shrug at HERE. Without
  # it, `tee ""` fails, PIPESTATUS[0] still reports the suite's own status, the
  # grep below reads an empty path and finds nothing, and a run with skipped
  # cases comes back as a clean ok. That is this script's own failure mode
  # wearing a different hat, so it is a did-not-run rather than a pass.
  if [ -z "$log" ] || [ ! -f "$log" ]; then
    echo "could not create a temp file, so a run with SKIPPED cases could not be" >&2
    echo "told apart from a complete one. Refusing to report either." >&2
    return 99
  fi
  # tee, rather than capturing into a variable, so a suite that takes minutes
  # prints as it goes instead of going silent and then emitting everything at
  # once. PIPESTATUS[0] is the suite's status; tee's is not interesting.
  bash scripts/test-backup-restore.sh 2>&1 | tee "$log"
  rc="${PIPESTATUS[0]}"
  if [ "$rc" != "0" ]; then rm -f "$log"; return "$rc"; fi
  if grep -q "case(s) did not run" "$log"; then rm -f "$log"; return 99; fi
  rm -f "$log"
  return 0
}

step "secret scan"                secret_scan
step "secret-scan allowlist guard" allowlist_guard
step "vulnerability scan"         vuln_scan
step "frontend dependency scan"   frontend_dep_scan
step "backup/restore suite"       backup_restore_tests

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
