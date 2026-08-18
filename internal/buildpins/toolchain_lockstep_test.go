// Package buildpins holds no code. It exists for one guard: the three files
// that each independently decide which Go toolchain builds or checks
// trustissues must name the same version.
//
// WHY THIS LIVES HERE AND NOT IN HEPHAESTUS. ci-go mounts only <repo>/<service>
// as /src, so a guard written in hephaestus can read hephaestus/Dockerfile and
// nothing else -- a hephaestus-side check of trustissues/Dockerfile self-
// disables on every CI run and fires only on a developer laptop, which reads as
// coverage while providing none. These three files all live inside the
// trustissues subtree, so this test runs with everything it needs during
// trustissues' own ci-go run, and again on the public mirror where this module
// is the whole repository.
//
// WHAT DRIFTED, so the next reader knows this is not hypothetical. As of
// 2026-08-18 all three had come apart:
//
//	Dockerfile         FROM golang:1.26-alpine  -- a FLOATING minor, resolved at
//	                   build time to whatever 1.26.x was newest that morning
//	go.mod             toolchain go1.26.5       -- inert in containers anyway,
//	                   because official golang images bake GOTOOLCHAIN=local
//	.github/ci.yml     go-version-file: go.mod  -- setup-go@v5 parses only the
//	                   `go` directive and has no toolchain support, so it read
//	                   `go 1.26` and never saw the line below it
//
// Three files, three different answers, none of them checked against the
// others, and the CI scan container was a fourth answer again. That is what
// this guard is for.
package buildpins

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	reDockerGo       = regexp.MustCompile(`(?m)^FROM\s+golang:(\S+?)(?:-(\w+))?(?:@sha256:[0-9a-f]{64})?\s`)
	reModGo          = regexp.MustCompile(`(?m)^toolchain\s+go(\d+\.\d+(?:\.\d+)?)\s*$`)
	reModGoDirective = regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)\s*$`)
	reYAMLGo         = regexp.MustCompile(`(?m)^\s*go-version:\s*["']?(\d+\.\d+(?:\.\d+)?)["']?\s*$`)
	reYAMLFile       = regexp.MustCompile(`(?m)^\s*go-version-file:`)
)

// TestGoToolchainPinsAreInLockstep asserts Dockerfile == go.mod == workflow.
//
// Every pin must be a full X.Y.Z. A two-component pin is not a pin: it floats to
// the newest patch at build time, so the binary that ships is decided by the day
// the layer cache missed rather than by anything in the repository.
func TestGoToolchainPinsAreInLockstep(t *testing.T) {
	root := moduleRoot(t)

	pins := map[string]string{}

	// --- Dockerfile: the only one of the three that decides the SHIPPED binary.
	dockerfile := filepath.Join(root, "Dockerfile")
	raw := mustRead(t, dockerfile)
	stages := reDockerGo.FindAllStringSubmatch(raw, -1)
	if len(stages) == 0 {
		t.Fatalf("%s has no `FROM golang:...` stage. Either the Go build stage was removed or "+
			"this guard's regex no longer matches it; both make the guard inert, so it fails "+
			"rather than passing on nothing.", dockerfile)
	}
	for _, m := range stages {
		ver := m[1]
		if strings.Count(ver, ".") != 2 {
			t.Errorf("%s pins `FROM golang:%s`, which is a FLOATING minor: it resolves to "+
				"whatever the newest %s.x is at build time, so the stdlib in the shipped image "+
				"is not decided by this repository. Pin the patch.", dockerfile, ver, ver)
			continue
		}
		pins["Dockerfile"] = ver
	}

	// --- go.mod. The EFFECTIVE pin is the `toolchain` directive when one is
	//     present, and the `go` directive otherwise.
	//
	//     Only the `go` directive is enforced under GOTOOLCHAIN=local, which
	//     every official golang image bakes in: a builder below it refuses,
	//     while a `toolchain` line is silently ignored. The two cannot both name
	//     the same version -- `go build` then fails with "updates to go.mod
	//     needed" and `go mod tidy` deletes the redundant line -- so this reads
	//     whichever one is actually present rather than demanding a fixed shape.
	gomod := filepath.Join(root, "go.mod")
	body := mustRead(t, gomod)
	switch m := reModGo.FindStringSubmatch(body); {
	case m != nil:
		if strings.Count(m[1], ".") != 2 {
			t.Errorf("%s has `toolchain go%s`; use a full X.Y.Z", gomod, m[1])
		} else {
			pins["go.mod (toolchain)"] = m[1]
		}
	default:
		g := reModGoDirective.FindStringSubmatch(body)
		if g == nil {
			t.Errorf("%s has neither a `toolchain goX.Y.Z` line nor a readable `go` directive, "+
				"so nothing in this module states which Go builds it.", gomod)
			break
		}
		if strings.Count(g[1], ".") != 2 {
			t.Errorf("%s pins `go %s`. With no `toolchain` line this is the ONLY "+
				"machine-enforced floor, and a two-component value admits every patch in the "+
				"series -- including the ones carrying the advisories this pin exists to "+
				"exclude. Use a full X.Y.Z.", gomod, g[1])
			break
		}
		pins["go.mod (go directive)"] = g[1]
	}

	// --- The GitHub workflow, which is what runs on the PUBLIC mirror.
	workflow := filepath.Join(root, ".github", "workflows", "ci.yml")
	wf := mustRead(t, workflow)
	if reYAMLFile.MatchString(wf) {
		t.Errorf("%s uses `go-version-file:`. actions/setup-go@v5 parses only the `go` directive "+
			"out of go.mod and stops -- it has no `toolchain` support -- so go-version-file "+
			"silently installs the `go` line's version and ignores the toolchain pin entirely. "+
			"Use a literal `go-version:`.", workflow)
	}
	if m := reYAMLGo.FindStringSubmatch(wf); m != nil {
		if strings.Count(m[1], ".") != 2 {
			t.Errorf("%s pins go-version %q; use a full X.Y.Z", workflow, m[1])
		} else {
			pins[".github/workflows/ci.yml"] = m[1]
		}
	} else {
		t.Errorf("%s has no literal `go-version:` pin, so the version CI installs on the public "+
			"mirror is not stated anywhere in this file.", workflow)
	}

	// --- All three must agree. Reported as the full picture rather than one
	//     mismatch at a time, because the useful question is always "which of
	//     these is the odd one out".
	if len(pins) < 3 {
		t.Fatalf("only %d of 3 toolchain pins could be read (%v); the lockstep was NOT verified",
			len(pins), pins)
	}
	var first string
	for _, v := range pins {
		first = v
		break
	}
	for _, v := range pins {
		if v != first {
			t.Fatalf("the three Go toolchain pins disagree: %v. They decide, in order, the "+
				"stdlib the shipped binary carries, what a laptop build uses, and what the "+
				"public mirror's CI installs. When they diverge, a green check on one is not "+
				"evidence about the others.", pins)
		}
	}
	t.Logf("Go toolchain pins in lockstep at %s across %d files", first, len(pins))
}

// moduleRoot walks up until it finds the directory holding go.mod. It does not
// assume a fixed number of ".." hops, so moving this package does not silently
// point the guard at the wrong tree.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to the filesystem root without finding go.mod, so the guard cannot " +
				"locate the module it is supposed to check")
		}
		dir = parent
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the guard fails rather than skipping: an unreadable pin file is "+
			"an unverified pin, not an absent requirement)", path, err)
	}
	return string(b)
}
