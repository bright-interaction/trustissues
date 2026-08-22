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

// The scanners are pinned.
//
// This is the one that matters most in this file. gitleaks and govulncheck are
// the two gates that can REFUSE a build, and installing them from @latest means
// an upstream change silently alters this repository's verdict -- in either
// direction. A scanner that quietly stops reporting is worse than one that
// breaks, because the build stays green.
func TestCIToolsAreVersionPinned(t *testing.T) {
	raw := mustRead(t, ciScriptPath(t))
	var checked int
	for _, line := range strings.Split(raw, "\n") {
		code := line
		if i := strings.Index(code, "#"); i >= 0 {
			code = code[:i] // ignore the prose explaining why pinning matters
		}
		if !strings.Contains(code, "@") {
			continue
		}
		for _, mod := range reGoInstallArg.FindAllString(code, -1) {
			checked++
			if strings.HasSuffix(mod, "@latest") || strings.HasSuffix(mod, "@master") ||
				strings.HasSuffix(mod, "@main") {
				t.Errorf("CI tool %q is not version-pinned.\n"+
					"This binary decides whether the build is refused; pin it to an exact version "+
					"and bump it as its own commit.", mod)
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no module@version arguments in scripts/ci.sh. Either the tools moved or " +
			"this regexp stopped matching; a guard that checked nothing must not report success")
	}
}
