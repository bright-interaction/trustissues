package buildpins

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The second guard in this package. TestGoToolchainPinsAreInLockstep asks
// whether the three Go-version pins AGREE; these ask whether the rest of the
// build inputs are pinned AT ALL.
//
// As of 2026-08-22 they were not. Every third-party GitHub Action ran from a
// mutable tag, the frontend toolchain was `bun-version: latest`, all three
// container base images were floating tags, and -- the sharpest one -- the
// secret scanner and the vulnerability scanner, the two checks whose entire job
// is to refuse a build, were installed with `@latest` on every run. So the gate
// deciding whether a credential vault may publish was whichever version those
// projects shipped that morning, fetched into a job that has the repository
// checked out.
//
// None of that is exotic. It is the ordinary supply-chain surface every
// repository has, and the reason it is worth a guard rather than a one-time
// cleanup is that un-pinning is invisible in review: `@v4` and
// `@11d5960a...  # v4` look equally deliberate in a diff, and the first one is
// how you get somebody else's code in your pipeline.

var (
	// A pinned action reference is owner/repo@<40 hex>. Anything else -- @v4,
	// @main, @a-branch -- is a mutable reference.
	reUses      = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
	reSHAPinned = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	// FROM <image>[:tag][@sha256:...] [AS stage]
	reFrom       = regexp.MustCompile(`(?m)^FROM\s+(\S+)`)
	reBunVersion = regexp.MustCompile(`(?m)^\s*bun-version:\s*["']?([^"'\s]+)["']?`)
	// `go install` module arguments inside the CI script.
	//
	// The VERSION half must exclude the same shell terminators as the path
	// half. It was `@\S+` first, and that made this guard blind to the exact
	// thing it exists to catch: the real call site is
	//
	//	bin="$(tool gitleaks github.com/zricethezav/gitleaks/v8@latest)"; rc=$?
	//
	// and `\S+` ran straight past the closing paren, so the captured module was
	// `...@latest)"; rc=$?` and HasSuffix(mod, "@latest") was false. Reverting
	// both scanners to @latest left this test green. Pinned by the ablation
	// below, not by inspection.
	reGoInstallArg = regexp.MustCompile(`[a-z0-9.\-]+\.[a-z]{2,}/[^\s"'` + "`" + `)]*@[^\s"'` + "`" + `);]+`)
)

func workflowPath(t *testing.T) string {
	return filepath.Join(moduleRoot(t), ".github", "workflows", "ci.yml")
}
func dockerfilePath(t *testing.T) string { return filepath.Join(moduleRoot(t), "Dockerfile") }
func ciScriptPath(t *testing.T) string   { return filepath.Join(moduleRoot(t), "scripts", "ci.sh") }

// Every third-party action runs from an immutable commit.
//
// A tag is a pointer the upstream owner can move. Pinning to it means "run
// whatever that account decides to publish there", in a job that already has
// this repository checked out and a token in the environment.
func TestEveryActionIsSHAPinned(t *testing.T) {
	raw := mustRead(t, workflowPath(t))
	matches := reUses.FindAllStringSubmatch(raw, -1)
	if len(matches) == 0 {
		t.Fatal("no `uses:` found in the workflow; either the workflow moved or this regexp " +
			"stopped matching, and a guard that inspects nothing must fail rather than pass")
	}
	for _, m := range matches {
		ref := m[1]
		// Local composite actions (./.github/...) and docker:// refs are not
		// tag-mutable in the same way and are out of scope.
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue
		}
		if !reSHAPinned.MatchString(ref) {
			t.Errorf("action %q is not SHA-pinned.\n"+
				"Pin it as owner/repo@<40-hex commit> with the version as a trailing comment: "+
				"`uses: owner/repo@abc123... # v4`.", ref)
		}
	}
}

// Every container base image is pinned by digest.
//
// A tag like alpine:3.21 is republished; `golang:1.26.6-alpine` is
// version-exact and still moves whenever the base layer is rebuilt for a CVE.
// That rebuild is usually what you want and is exactly why it must be a
// deliberate commit rather than a surprise at the next cache miss: the shipped
// binary should be decided by the repository, not by the day the layer cache
// happened to miss.
func TestEveryBaseImageIsDigestPinned(t *testing.T) {
	raw := mustRead(t, dockerfilePath(t))
	images := reFrom.FindAllStringSubmatch(raw, -1)
	if len(images) == 0 {
		t.Fatal("no FROM lines found in the Dockerfile; the guard cannot inspect nothing and pass")
	}
	for _, m := range images {
		img := m[1]
		// A later stage may build FROM an earlier stage by name; those carry no
		// registry reference to pin.
		if !strings.Contains(img, ":") && !strings.Contains(img, "/") {
			continue
		}
		if !strings.Contains(img, "@sha256:") {
			t.Errorf("base image %q has no digest.\n"+
				"Pin it as image:tag@sha256:<64-hex>; keep the tag for readability.", img)
		}
	}
}

// The frontend toolchain is pinned.
//
// `bun run build` runs tsc first, so bun decides whether the UI type-checks.
// At `latest` a bun regression arrives as a CI failure on an unrelated PR with
// nothing in the repository having changed.
func TestBunVersionIsPinned(t *testing.T) {
	raw := mustRead(t, workflowPath(t))
	m := reBunVersion.FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("no bun-version found in the workflow. The Go binary serves the built frontend, " +
			"so if the bun setup step is gone the UI is neither type-checked nor built")
	}
	if v := m[1]; v == "latest" || v == "canary" {
		t.Errorf("bun-version is %q; pin an exact version", v)
	}
}

// The PARSER used by TestCIToolsAreVersionPinned, checked against literal
// lines in the shape scripts/ci.sh actually uses.
//
// This exists because that test was written with `@\S+` for the version half
// and was blind: reverting both scanners to @latest left it green, because the
// capture ran past the closing paren and no longer ended in "@latest". A guard
// whose parser is wrong reports success having examined a string that is not
// the one in the file, which is indistinguishable from working. So the parser
// is now pinned separately from the files it reads.
func TestGoInstallArgParserSeesTheRealCallSite(t *testing.T) {
	cases := []struct {
		line   string
		want   string
		pinned bool
	}{
		{`  bin="$(tool gitleaks github.com/zricethezav/gitleaks/v8@latest)"; rc=$?`,
			"github.com/zricethezav/gitleaks/v8@latest", false},
		{`  bin="$(tool gitleaks github.com/zricethezav/gitleaks/v8@v8.30.1)"; rc=$?`,
			"github.com/zricethezav/gitleaks/v8@v8.30.1", true},
		{`  bin="$(tool govulncheck golang.org/x/vuln/cmd/govulncheck@v1.7.0)"; rc=$?`,
			"golang.org/x/vuln/cmd/govulncheck@v1.7.0", true},
		{`  go install golang.org/x/vuln/cmd/govulncheck@master`,
			"golang.org/x/vuln/cmd/govulncheck@master", false},
	}
	for _, c := range cases {
		got := reGoInstallArg.FindAllString(c.line, -1)
		if len(got) != 1 {
			t.Errorf("parsed %d modules from %q, want exactly 1: %v", len(got), c.line, got)
			continue
		}
		if got[0] != c.want {
			t.Errorf("parsed %q, want %q -- a mis-parsed module makes the pin check inspect a "+
				"string that is not in the file", got[0], c.want)
			continue
		}
		unpinned := strings.HasSuffix(got[0], "@latest") || strings.HasSuffix(got[0], "@master") ||
			strings.HasSuffix(got[0], "@main")
		if unpinned == c.pinned {
			t.Errorf("module %q classified wrong: pinned=%v", got[0], !unpinned)
		}
	}
}

// The scanners are pinned, stated as the COMPLEMENT.
//
// The previous version of this asked whether any module ended in @latest,
// @master or @main. That is an existence claim about three magic strings, and a
// denylist only ever refuses the spellings its author thought of. It passed
// every one of these:
//
//	@v8.30      a floating minor -- Go resolves it to the newest v8.30.x
//	@release    a mutable tag
//	@HEAD       whatever landed on the default branch
//	curl ... | sh   not a module argument at all, so the regexp never sees it
//	<deleted>   removing an install entirely, because the other tool kept
//	            `checked` above zero and the vacuity guard stayed satisfied
//
// So it is inverted. Instead of naming bad refs, it requires every ref to BE an
// exact release, and requires each scanner to be there at all. An unknown-to-us
// spelling now fails by default instead of passing by default, which is the only
// property that survives someone inventing a new one.
//
// This is the same defect this codebase keeps re-finding, most recently in the
// enrolment gate's wiring guard: "a gated group exists somewhere" is satisfied
// by a decoy; "every route is gated or is /auth" is not.

// An exact release: v1.2.3, optionally with a prerelease or build suffix.
// Deliberately NOT accepting v8.30 (floating minor), bare SHAs, branch names or
// any tag-shaped thing.
var reExactVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$`)

// The binaries whose entire job is to REFUSE a build. Each must be installed by
// the CI script, and installed from an exactly-pinned module.
//
// Named individually because "some tools are pinned" is exactly the existence
// claim this rewrite exists to stop making: deleting the gitleaks install
// altogether must fail this file, and under the old guard it did not.
var requiredCITools = map[string]string{
	"gitleaks":    "github.com/zricethezav/gitleaks",
	"govulncheck": "golang.org/x/vuln/cmd/govulncheck",
}

// ciScriptCode returns scripts/ci.sh with comments stripped, so the prose
// explaining why pinning matters cannot be mistaken for a call site.
func ciScriptCode(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(mustRead(t, ciScriptPath(t)), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// EVERY module reference in the CI script is an exact release. No exceptions,
// no denylist.
func TestEveryCIToolRefIsAnExactVersion(t *testing.T) {
	code := ciScriptCode(t)

	var checked int
	for _, mod := range reGoInstallArg.FindAllString(code, -1) {
		checked++
		at := strings.LastIndex(mod, "@")
		if at < 0 {
			t.Errorf("module %q carries no version at all", mod)
			continue
		}
		ref := mod[at+1:]
		if !reExactVersion.MatchString(ref) {
			t.Errorf("CI tool %q is not pinned to an exact release (ref %q).\n"+
				"This binary decides whether the build is refused. Pin it to a full "+
				"vMAJOR.MINOR.PATCH and bump it as its own commit, so the diff records "+
				"which scanner moved.", mod, ref)
		}
	}

	if checked == 0 {
		t.Fatal("ABORT: found no module@version arguments in scripts/ci.sh. Either the tools " +
			"moved or reGoInstallArg stopped matching; a guard that checked nothing must not " +
			"report success")
	}
}

// And each scanner is actually INSTALLED. This is the half a denylist cannot
// express: deleting an install is not an unpinned reference, it is the absence
// of one, and "no bad refs found" is trivially true of a script that installs
// nothing.
func TestEveryRequiredCIToolIsInstalledAndPinned(t *testing.T) {
	code := ciScriptCode(t)
	mods := reGoInstallArg.FindAllString(code, -1)

	for bin, modPrefix := range requiredCITools {
		var found string
		for _, mod := range mods {
			if strings.HasPrefix(mod, modPrefix) {
				found = mod
				break
			}
		}
		if found == "" {
			t.Errorf("scripts/ci.sh no longer installs %s (expected a module under %q).\n"+
				"Removing the scanner is not a pinning problem, it is the check disappearing: "+
				"the step it backs can still print ok while nothing scans.", bin, modPrefix)
			continue
		}
		ref := found[strings.LastIndex(found, "@")+1:]
		if !reExactVersion.MatchString(ref) {
			t.Errorf("required CI tool %s is installed from %q, which is not an exact release", bin, found)
		}
	}
}

// Nothing is fetched by piping a network response into a shell.
//
// `curl https://... | sh` installs whatever the server returns at that moment.
// It carries no version, so every guard above is blind to it by construction --
// which is precisely why it needs its own assertion rather than a regexp tweak.
func TestNoToolIsInstalledByPipingToAShell(t *testing.T) {
	rePipeToShell := regexp.MustCompile(`(?i)\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b`)
	code := ciScriptCode(t)
	for _, m := range rePipeToShell.FindAllString(code, -1) {
		t.Errorf("scripts/ci.sh installs something by piping a download into a shell: %q.\n"+
			"That has no version to pin and no digest to check, so every pin guard in this "+
			"file is blind to it.", strings.TrimSpace(m))
	}
}

// The pin has to be what actually RUNS.
//
// tool() returned any binary of that name already on PATH before considering
// the pinned module, so on a developer machine an older -- or planted --
// gitleaks decided the verdict while this file reported everything pinned. CI
// runners were unaffected only by luck: neither scanner happens to be
// preinstalled there. A pin that PATH can override is a comment.
func TestToolResolvesThePinRatherThanWhateverIsOnPATH(t *testing.T) {
	code := ciScriptCode(t)
	start := strings.Index(code, "tool() {")
	if start < 0 {
		t.Fatal("ABORT: tool() not found in scripts/ci.sh; this guard is looking in the wrong place")
	}
	end := strings.Index(code[start:], "\n}")
	if end < 0 {
		t.Fatal("ABORT: could not find the end of tool()")
	}
	body := code[start : start+end]

	if strings.Contains(body, "command -v \"$bin\"") &&
		strings.Contains(body, "return 0") &&
		strings.Index(body, "command -v \"$bin\"") < strings.Index(body, "go install") {
		t.Error("tool() still returns a PATH binary before installing the pinned module.\n" +
			"Then the version this repository pins is not the version that decides whether " +
			"the build is refused, and every other assertion in this file describes a " +
			"module nobody ran.")
	}
}

// tool() must ASK the toolchain where it installed the binary.
//
// `go install` writes to $GOBIN when set and only falls back to $GOPATH/bin
// otherwise. tool() hardcoded the fallback, so on any machine with GOBIN set the
// pinned scanner was installed to one path while whatever already sat at
// $GOPATH/bin was executed -- and the run printed "ci: all checks passed" and
// exited 0. A silent pass is worse than the PATH-preference bug that motivated
// the previous change to this function, because a skip announces itself.
//
// Asserted as the complement of the defect: the resolution must consult GOBIN,
// and must not derive the path from GOPATH alone.
func TestToolAsksTheToolchainWhereItInstalled(t *testing.T) {
	code := ciScriptCode(t)
	start := strings.Index(code, "tool() {")
	if start < 0 {
		t.Fatal("ABORT: tool() not found in scripts/ci.sh; this guard is looking in the wrong place")
	}
	end := strings.Index(code[start:], "\n}")
	if end < 0 {
		t.Fatal("ABORT: could not find the end of tool()")
	}
	body := code[start : start+end]

	if !strings.Contains(body, "go env GOBIN") {
		t.Error("tool() never consults `go env GOBIN`.\n" +
			"`go install` honours GOBIN, so on a machine that sets it the pinned binary is " +
			"installed to one path and a different one is executed -- and the run exits 0.")
	}
	// The GOPATH form is still legitimate AS THE FALLBACK, but it must not be the
	// only thing consulted.
	if strings.Contains(body, "go env GOPATH") && !strings.Contains(body, "go env GOBIN") {
		t.Error("tool() derives the install path from GOPATH alone")
	}
}
