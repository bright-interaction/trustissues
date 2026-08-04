#!/usr/bin/env python3
"""Ablation harness for the round-14 verification pass.

For each ablation: apply a source edit, BUILD, run the guard, classify, restore.

The build step is not a formality. Twice in this work a grep for test failures
counted a compile error as "no findings", which reads as a guard that had nothing
to catch. So a build failure is INVALID here, never CLEAN.

Classification:
  build fails            -> INVALID   (the ablation is wrong, fix it and re-run)
  build ok, test fails   -> CAUGHT    (the guard works for this bug shape)
  build ok, test passes  -> MISSED    (a hole: the guard cannot see this shape)

Restore is always from an in-memory copy of the original bytes, never
`git checkout --`, which silently discards uncommitted work in the same file.
"""
import subprocess, sys, json, os, atexit, signal

# Derived from THIS file's location, never hardcoded.
#
# It used to be an absolute path to one particular checkout. Running it from a
# second git worktree (the documented way to work while another session holds
# the main one) therefore ablated the OTHER worktree: it injected bugs into a
# tree the caller was not looking at, ran the tests there, and reported results
# that had nothing to do with the code under review. Here it only refused to
# start, because that tree happened to be mid-sweep and dirty, which is the
# lucky version of this failure.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(cmd, timeout=900):
    p = subprocess.run(cmd, shell=True, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


# Files currently ablated, so a kill can still put them back.
#
# The per-ablation `finally` does not run when the process is killed from outside
# (an outer command timeout, SIGTERM, Ctrl-C). That happened twice. The first time
# it left hashWait at 24h; the second time it stripped the capacityExhausted calls
# out of three vault re-auth gates, silently reverting a committed security fix,
# and both were noticed only by luck. So the pending restore lives in module state
# with an atexit hook and signal handlers on top of the finally.
_PENDING = {}


def _restore_all(*_):
    for path, blob in list(_PENDING.items()):
        try:
            with open(path, "wb") as fh:
                fh.write(blob)
            print(f"[restore] {os.path.basename(path)}", flush=True)
        except Exception as e:
            print(f"[restore FAILED] {path}: {e}", flush=True)
    _PENDING.clear()


atexit.register(_restore_all)
for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    try:
        signal.signal(_sig, lambda *_: (_restore_all(), sys.exit(130)))
    except Exception:
        pass


def ablate(spec):
    """spec: {id, mech, file, old, new, test, why}"""
    path = os.path.join(ROOT, spec["file"])
    with open(path, "rb") as fh:
        original = fh.read()
    text = original.decode()

    if spec["old"] not in text:
        return {**spec, "result": "INVALID", "detail": "anchor text not found in source"}

    try:
        _PENDING[path] = original
        ablated = text.replace(spec["old"], spec["new"], 1)

        # `extra_import` adds packages the ablation's own code needs.
        #
        # It was in a spec before it was in this harness. Round 20 wrote
        # {"extra_import": "crypto/aes"} for the ablation that plants an aes
        # reference in an undeclared file, the harness silently ignored the field,
        # and the run came back "does not compile: undefined: aes" -> INVALID. The
        # sweep reported that honestly and nobody re-ran it, so the guard the
        # ablation exists to test went unproven while the report looked complete.
        #
        # An unknown key is therefore a hard error rather than a shrug: a spec that
        # asks for something this file does not do must stop the run, not quietly
        # become an INVALID that reads like the ablation's own fault.
        extra = spec.get("extra_import")
        if extra:
            imports = [extra] if isinstance(extra, str) else list(extra)
            anchor = "\nimport (\n"
            if anchor not in ablated:
                return {**spec, "result": "INVALID",
                        "detail": "extra_import needs a parenthesised import block"}
            at = ablated.index(anchor) + len(anchor)
            ablated = ablated[:at] + "".join(f'\t"{p}"\n' for p in imports) + ablated[at:]

        with open(path, "w") as fh:
            fh.write(ablated)

        rc, out = run("go build ./... 2>&1")
        if rc != 0:
            first = next((l for l in out.splitlines() if l.strip() and not l.startswith("#")), "")
            return {**spec, "result": "INVALID", "detail": "does not compile: " + first[:160]}

        # ALWAYS run the whole package, never only the guard you have in mind.
        #
        # Scoping -run to the test I expected to fire reported three ablations as
        # MISSED when the behaviour was in fact caught by a guard in a DIFFERENT test
        # function. A narrow filter is a false-finding generator: it cannot tell
        # "nothing catches this" apart from "I did not run the thing that does".
        # spec["test"] is kept only to name the guard under study in the report.
        # -timeout is not optional. One ablation raised a wait to 24h and hung the
        # whole sweep; a hang is not a result. A timeout counts as CAUGHT only if the
        # guard is what timed out, so it is reported separately.
        # A spec may name the package to test, because the guard for a property is
        # not always in the package that implements it: ablating shield.ValidHintLevel
        # is caught by a test in internal/config, and running only the edited file's
        # package reported MISSED. Default stays the edited file's package.
        pkg = spec.get("pkg") or "./" + os.path.dirname(spec["file"]) + "/"
        rc, out = run(f"go test {pkg} -count=1 -timeout 120s 2>&1")
        if "panic: test timed out" in out:
            return {**spec, "result": "TIMEOUT", "detail": "the ablated code hangs; treat as caught only if a guard bounds it"}
        if rc != 0:
            msg = next((l.strip() for l in out.splitlines()
                        if ".go:" in l and ("Error" in l or ":" in l) and "--- FAIL" not in l), "")
            return {**spec, "result": "CAUGHT", "detail": msg[:200]}
        # A MISS does not distinguish "the guard broke" from "a later fix made this
        # bug unreachable". Three of the four misses in the first full 111-spec
        # sweep were the second kind: the caller had gained a len(patterns)==0
        # deny, leadingWildcardMatch had been deleted, the email pattern had been
        # reordered ahead of personnummer. Each took a manual reproduction to
        # classify, and nothing recorded the answer, so the next sweep would have
        # redone all of it.
        #
        # `expect_miss` records a verdict that was reached by hand, WITH the note
        # explaining why. It is reported as SUPERSEDED rather than silently
        # passing, so a spec that starts catching again (the fix was reverted, the
        # second layer removed) still shows up as a surprise worth reading.
        if spec.get("expect_miss"):
            return {**spec, "result": "SUPERSEDED",
                    "detail": "expected miss: " + spec.get("note", "")[:160]}
        return {**spec, "result": "MISSED", "detail": "guard passed clean with the bug present"}
    finally:
        with open(path, "wb") as fh:
            fh.write(original)
        _PENDING.pop(path, None)


def main():
    # An external kill (an outer timeout, a Ctrl-C) skips the per-ablation finally
    # block and leaves the tree ablated. That happened: a 24h hashWait survived a
    # killed run and was only noticed because a NEW test flagged it. So verify the
    # tree is pristine before starting, and again at the end.
    rc, out = run("git diff --quiet -- . && echo CLEAN")
    if "CLEAN" not in out:
        print("REFUSING TO START: the working tree already differs from HEAD.")
        print("A previous run may have been killed mid-ablation. Inspect `git diff` first.")
        print(out[:400])
        sys.exit(1)

    specs = json.load(open(sys.argv[1]))
    results = []
    for i, s in enumerate(specs, 1):
        r = ablate(s)
        results.append(r)
        mark = {"CAUGHT": "ok  ", "MISSED": "MISS", "INVALID": "BAD ",
                "TIMEOUT": "HANG", "SUPERSEDED": "sup "}[r["result"]]
        print(f"{mark} [{i:2}/{len(specs)}] {s['mech']:<14} {s['id']:<38} {r['detail'][:80]}", flush=True)

    # Guard the harness itself: a run where nothing was CAUGHT means the harness is
    # probably not invoking the tests correctly, not that every guard is perfect.
    counts = {k: sum(1 for r in results if r["result"] == k)
              for k in ("CAUGHT", "MISSED", "INVALID", "TIMEOUT", "SUPERSEDED")}
    print(f"\ncaught {counts['CAUGHT']}  missed {counts['MISSED']}  invalid {counts['INVALID']}"
          f"  hung {counts['TIMEOUT']}  superseded {counts['SUPERSEDED']}")
    # Superseded specs are not expected to catch, so a run made only of them is
    # not evidence the harness is broken.
    if counts["CAUGHT"] == 0 and (len(results) - counts["SUPERSEDED"]) > 0:
        print("ABORT-LIKE: nothing was caught at all; suspect the harness before trusting this.")
    # The results file is optional. It used to be read as sys.argv[2]
    # unconditionally, so the documented one-argument form raised IndexError HERE,
    # after the run but BEFORE the restore verification below, which is the one
    # part of this harness that must never be skipped.
    if len(sys.argv) > 2:
        json.dump(results, open(sys.argv[2], "w"), indent=1)

    # Leave the tree exactly as found.
    #
    # The results file is EXCLUDED from this check, because this harness writes
    # it. The first time a round committed its results, the next run of the same
    # round ended "DIRTY, an ablation did not restore" with an empty diff body,
    # and the only changed file was the report the run had just produced. A
    # restore alarm that cries wolf on its own output is worse than no alarm:
    # this exact line is what caught a 24h hashWait and three reverted re-auth
    # gates that survived a killed run, and it only works if a DIRTY here always
    # means something is genuinely still ablated.
    rc, out = run("go build ./... 2>&1")
    print("tree restored, build:", "ok" if rc == 0 else "BROKEN " + out[:200])
    excl = ""
    if len(sys.argv) > 2:
        rel = os.path.relpath(os.path.abspath(sys.argv[2]), ROOT)
        excl = f" ':(exclude){rel}'"
    rc2, out2 = run(f"git diff --quiet -- .{excl} && echo CLEAN")
    if "CLEAN" in out2:
        print("tree vs HEAD: clean")
    else:
        _, names = run(f"git diff --name-only -- .{excl}")
        print("tree vs HEAD: DIRTY, an ablation did not restore:\n" + (names or out2)[:400])


if __name__ == "__main__":
    main()
