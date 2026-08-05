package handlers

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/totp"
)

// Dual-key READ, tested at the CALL SITES rather than at the helpers.
//
// The helpers (decryptTOTPSecret, resolveSMTPPassword, urlBlindIndexCandidates)
// each had a unit test proving they try the previous key. Every one of their
// call sites was untested: a review reverted four of them to single-key at once
// and the whole package still passed. That is this codebase's signature defect
// (a guarded helper reached through unguarded call sites) and it is worth being
// precise about what it would have shipped mid-rotation:
//
//   - Login: the ciphertext is handed to the TOTP validator as if it were the
//     seed, so 2FA fails for every enrolled user and nobody can log in.
//   - Invitation email and the SMTP test button: a decrypt error, so no
//     invitation is ever delivered.
//   - Autofill: the blind index computed under the new key matches nothing, so
//     the extension shows an empty list with NO error anywhere. That silent one
//     is the failure this whole workstream is named after.
//
// So every test below drives the real handler on a store that is mid-rotation
// (seeded under the old key, served by a process holding both keys, sweep NOT
// yet run), which is the exact window the dual-key read exists for.

// midRotationCfg is the process configuration during a rotation: new key live,
// old key still loaded for reads only.
func midRotationCfg() *config.Config {
	return &config.Config{
		JWTSecret:        strings.Repeat("j", 32),
		VaultKey:         rekeyNewKey,
		VaultKeyPrevious: rekeyOldKey,
		BaseURL:          "https://vault.example.com",
	}
}

// TestAutofillMatchesMidRotationThroughTheHandler drives GET /api/vault/match.
//
// The blind index is an HMAC, not ciphertext: a stale one does not fail to
// decrypt, it stops MATCHING. So the only assertion that means anything is the
// number of entries the handler returns.
func TestAutofillMatchesMidRotationThroughTheHandler(t *testing.T) {
	dbConn, queries := newRekeyDB(t)
	seeded := seedUnderKey(t, rekeyHandler(dbConn, queries, rekeyOldKey, ""), queries)

	rotating := rekeyHandler(dbConn, queries, rekeyNewKey, rekeyOldKey)

	rec := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/vault/match?url="+seedURL, nil), seeded.userID)
	rotating.Match(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("match: %d %s", rec.Code, rec.Body.String())
	}
	var entries []vaultEntryMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode match response: %v (%s)", err, rec.Body.String())
	}
	if len(entries) != 1 {
		t.Fatalf(`autofill returned %d entries mid-rotation, want 1.

The url_bidx column was written under the old key and the process now computes
indexes under the new one. Nothing errors: the lookup simply matches no rows, the
browser extension shows an empty list, and the user concludes their entry was
deleted. Match must look the host up under EVERY key on the ring
(urlBlindIndexCandidates), not just the current one.`, len(entries))
	}
	if entries[0].ID != seeded.entryID {
		t.Fatalf("autofill returned entry %q, want %q", entries[0].ID, seeded.entryID)
	}

	// And it must keep working once the sweep has run and the old key is gone,
	// or the dual lookup would just be masking a sweep that never converts.
	if _, err := rotating.RekeyVault(context.Background()); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	final := rekeyHandler(dbConn, queries, rekeyNewKey, "")
	rec2 := httptest.NewRecorder()
	final.Match(rec2, withUser(httptest.NewRequest(http.MethodGet, "/api/vault/match?url="+seedURL, nil), seeded.userID))
	var afterSweep []vaultEntryMeta
	if err := json.Unmarshal(rec2.Body.Bytes(), &afterSweep); err != nil {
		t.Fatalf("decode match response after the sweep: %v", err)
	}
	if len(afterSweep) != 1 {
		t.Fatalf("autofill returned %d entries after the sweep with the old key removed, want 1; "+
			"the sweep did not recompute url_bidx", len(afterSweep))
	}
}

// TestLoginWith2FASucceedsMidRotation drives POST /api/auth/login.
//
// decryptTOTPSecret returns the STORED value unchanged when it cannot decrypt
// (legacy plaintext rows are supported), so a single-key read mid-rotation does
// not error: it quietly feeds "tienc:v1:..." to the TOTP validator. Every
// enrolled user is locked out and the server logs nothing.
func TestLoginWith2FASucceedsMidRotation(t *testing.T) {
	ctx := context.Background()
	_, queries := newRekeyDB(t)

	const password = "CorrectHorseBatteryStaple1!"
	userID := mustUser(t, queries, "rotating-2fa@example.com", "admin", password)

	// The seed is sealed under the OLD key, which is what a store looks like
	// before the sweep runs.
	sealed, err := columncrypto.EncryptString(seedTOTP, rekeyOldKey)
	if err != nil {
		t.Fatalf("seal totp seed: %v", err)
	}
	if err := queries.StoreTOTPSecret(ctx, db.StoreTOTPSecretParams{
		TotpSecret: sql.NullString{String: sealed, Valid: true}, ID: userID,
	}); err != nil {
		t.Fatalf("store totp secret: %v", err)
	}
	if err := queries.EnableTOTP(ctx, db.EnableTOTPParams{
		TotpRecoveryCodes: sql.NullString{String: "[]", Valid: true}, ID: userID,
	}); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	code, err := totp.GenerateCode(seedTOTP, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	ah := NewAuthHandler(queries, midRotationCfg())
	rec := httptest.NewRecorder()
	body := `{"email":"rotating-2fa@example.com","password":"` + password + `","totp_code":"` + code + `"}`
	ah.Login(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf(`2FA login was refused mid-rotation (%d %s).

The TOTP seed is still sealed under TRUSTISSUES_VAULT_KEY_PREVIOUS until the
re-encrypt sweep runs. A login path that decrypts with the current key alone
gets the ciphertext back (decryptTOTPSecret falls through to the stored value
for legacy plaintext rows) and validates the code against it, so every enrolled
user is locked out with no error in the log.`, rec.Code, rec.Body.String())
	}
	var resp authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if resp.Token == "" {
		t.Fatalf("login returned no token: %s", rec.Body.String())
	}
}

// TestSMTPTestButtonAuthenticatesMidRotation drives POST /api/settings/smtp/test
// and asserts the credential the RELAY received.
//
// Asserting the HTTP status alone would not be enough: the whole point of
// resolveSMTPPassword is that the relay must see the password, not the
// ciphertext, so the fake relay captures what was actually sent.
func TestSMTPTestButtonAuthenticatesMidRotation(t *testing.T) {
	queries, relay, admin := smtpRotationEnv(t)

	sh := NewSettingsHandler(queries, midRotationCfg())
	rec := httptest.NewRecorder()
	sh.TestSMTP(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/settings/smtp/test", nil), admin))

	if rec.Code != http.StatusOK {
		t.Fatalf("SMTP test was refused mid-rotation (%d %s); the stored password is still sealed "+
			"under the previous key until the sweep runs", rec.Code, rec.Body.String())
	}
	relay.assertAuthenticatedWith(t, seedSMTP, "the SMTP test button")
}

// TestInvitationEmailAuthenticatesMidRotation drives the invitation mailer.
//
// It is the path that matters most on a fresh rotation: an admin who rotates the
// key and then invites a teammate gets "invitation created" from the API while
// the email never leaves, because the send happens detached from the request.
func TestInvitationEmailAuthenticatesMidRotation(t *testing.T) {
	queries, relay, _ := smtpRotationEnv(t)

	uh := NewUserHandler(queries, midRotationCfg())
	uh.trySendInvitationEmail("invitee@example.com", "Invitee", "INVITE-CODE-ABCDEF")

	relay.assertAuthenticatedWith(t, seedSMTP, "the invitation mailer")
}

// smtpRotationEnv builds a store whose smtp_password is sealed under the OLD
// key, plus a fake relay that records the credential it is offered.
func smtpRotationEnv(t *testing.T) (*db.Queries, *authCapturingSMTP, string) {
	t.Helper()
	ctx := context.Background()
	_, queries := newRekeyDB(t)
	relay := newAuthCapturingSMTP(t)

	sealed, err := columncrypto.EncryptString(seedSMTP, rekeyOldKey)
	if err != nil {
		t.Fatalf("seal smtp password: %v", err)
	}
	host, port, err := net.SplitHostPort(relay.addr)
	if err != nil {
		t.Fatalf("split relay addr: %v", err)
	}
	for k, v := range map[string]string{
		"smtp_host":     host,
		"smtp_port":     port,
		"smtp_from":     "vault@example.com",
		"smtp_username": "relay-user",
		"smtp_password": sealed,
		"smtp_use_tls":  "false",
	} {
		if err := queries.UpsertSetting(ctx, db.UpsertSettingParams{Key: k, Value: v}); err != nil {
			t.Fatalf("store setting %s: %v", k, err)
		}
	}
	return queries, relay, mustUser(t, queries, "admin@example.com", "admin", "")
}

// authCapturingSMTP is a fake relay that accepts AUTH PLAIN and records the
// credential. The listener is on 127.0.0.1, which is both what makes Go's
// PlainAuth willing to send a password over a cleartext connection and what
// makes sendMailSTARTTLS willing to proceed without STARTTLS.
type authCapturingSMTP struct {
	addr string

	mu       sync.Mutex
	gotAuth  bool
	gotUser  string
	gotPass  string
	authLine string
}

func newAuthCapturingSMTP(t *testing.T) *authCapturingSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &authCapturingSMTP{addr: ln.Addr().String()}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *authCapturingSMTP) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }

	w("220 fake ESMTP")
	inData := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				w("250 OK")
			}
			continue
		}

		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			w("250-fake")
			w("250 AUTH PLAIN")
		case strings.HasPrefix(up, "HELO"):
			w("250 fake")
		case strings.HasPrefix(up, "AUTH PLAIN "):
			f.recordAuth(strings.TrimPrefix(line, "AUTH PLAIN "))
			w("235 authenticated")
		case strings.HasPrefix(up, "MAIL FROM"), strings.HasPrefix(up, "RCPT TO"):
			w("250 OK")
		case strings.HasPrefix(up, "DATA"):
			inData = true
			w("354 send it")
		case strings.HasPrefix(up, "QUIT"):
			w("221 bye")
			return
		default:
			w("250 OK")
		}
	}
}

func (f *authCapturingSMTP) recordAuth(encoded string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotAuth = true
	f.authLine = encoded
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return
	}
	// PLAIN is authzid\0authcid\0password.
	parts := strings.Split(string(raw), "\x00")
	if len(parts) == 3 {
		f.gotUser, f.gotPass = parts[1], parts[2]
	}
}

// assertAuthenticatedWith waits briefly for the send to land, then asserts the
// relay was offered the PLAINTEXT password.
func (f *authCapturingSMTP) assertAuthenticatedWith(t *testing.T, want, who string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		got, pass := f.gotAuth, f.gotPass
		f.mu.Unlock()
		if got || time.Now().After(deadline) {
			if !got {
				t.Fatalf("%s never authenticated to the relay; the stored password is sealed under the "+
					"previous key, so a single-key read fails with a decrypt error and the send is abandoned", who)
			}
			if pass != want {
				shown := pass
				if strings.HasPrefix(pass, "tienc:") {
					shown = "the CIPHERTEXT (" + pass[:12] + "...)"
				}
				t.Fatalf("%s authenticated with %s, want the plaintext password. "+
					"Mid-rotation the setting is still sealed under TRUSTISSUES_VAULT_KEY_PREVIOUS.", who, shown)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Structural guards: a NEW call site must not be able to skip the helper
// ---------------------------------------------------------------------------

// TestEveryDualKeyHelperCallSitePassesThePreviousKey.
//
// The behavioural tests above cover the call sites that exist today. This covers
// the one added tomorrow. The helpers take the keyring variadically, which makes
// the single-key call compile, read naturally and fail only during a rotation,
// so the shape has to be refused mechanically.
//
// Modelled on TestEveryColumnCryptoWriterIsARegisteredSurface: source-level,
// deliberately coarse, and loud about what to do.
func TestEveryDualKeyHelperCallSitePassesThePreviousKey(t *testing.T) {
	// helper -> the minimum number of call sites that must exist, so a rename or
	// a refactor that removes the calls cannot leave this guard passing over
	// nothing.
	helpers := map[string]int{
		"decryptTOTPSecret":   3,
		"resolveSMTPPassword": 2,
	}

	for helper, minSites := range helpers {
		sites := findCallSites(t, helper)
		if len(sites) < minSites {
			t.Fatalf("ABORT: found %d call site(s) of %s, expected at least %d. This guard is matching "+
				"almost nothing (renamed? inlined?) and would pass over an unguarded call.",
				len(sites), helper, minSites)
		}
		for _, site := range sites {
			if strings.Contains(strings.ToLower(site.args), "previous") {
				continue
			}
			t.Errorf(`%s:%d calls %s with the current key alone.

  %s(%s)

That compiles, reads fine, and works on every store except one mid-rotation. The
value is still sealed under TRUSTISSUES_VAULT_KEY_PREVIOUS until the re-encrypt
sweep runs, and neither helper returns an error you would notice:
decryptTOTPSecret hands the ciphertext to the TOTP validator (2FA fails for
every enrolled user) and resolveSMTPPassword aborts the send (no invitation
email is ever delivered).

Pass the keyring: %s(value, cfg.VaultKey, cfg.VaultKeyPrevious).`,
				site.file, site.line, helper, helper, strings.TrimSpace(site.args), helper)
		}
	}
}

// TestBlindIndexLookupsGoThroughTheCandidateSet.
//
// A stale blind index is the quietest failure in the product: no decrypt error,
// no log line, autofill just returns nothing. The dual lookup lives in
// urlBlindIndexCandidates, and a caller that computes ONE index with
// h.urlBlindIndex and queries with it reintroduces the silence.
//
// Function-scoped rather than file-scoped, which matters here: vault.go both
// WRITES indexes (h.urlBlindIndex, correct: a write must use the current key
// alone) and READS them, so a file-level rule would have to allow
// h.urlBlindIndex everywhere in the file and would then miss a lookup that used
// it. Any function that runs a match query must range over the candidates and
// must not compute a single index itself.
func TestBlindIndexLookupsGoThroughTheCandidateSet(t *testing.T) {
	matchQueries := []string{
		"MatchPersonalVaultEntriesByURL(",
		"MatchCollectionVaultEntriesByURL(",
		"MatchVaultEntriesByURL(",
	}

	checked := 0
	for file, src := range packageSources(t) {
		for name, body := range topLevelFuncs(src) {
			queriesByIndex := false
			for _, q := range matchQueries {
				if strings.Contains(body, q) {
					queriesByIndex = true
				}
			}
			if !queriesByIndex {
				continue
			}
			checked++
			if !strings.Contains(body, "urlBlindIndexCandidates(") {
				t.Errorf(`%s in %s looks entries up by blind index without ranging over the candidate set.

url_bidx is an HMAC keyed by the vault key. It does not fail to decrypt when the
key changes, it stops MATCHING, so a single-key lookup returns nothing at all
during a rotation and reports no error anywhere: the extension shows an empty
list and the user concludes the entry was deleted.

Range over h.urlBlindIndexCandidates(scope, url), query once per candidate, and
dedupe the rows.`, name, file)
			}
			if strings.Contains(body, "h.urlBlindIndex(") {
				t.Errorf(`%s in %s computes a single blind index (h.urlBlindIndex) and queries with it.

That is the WRITE-side helper: it answers "the index under the key we encrypt
with today", which is exactly the wrong question when reading a store whose rows
were indexed under the previous key. Use urlBlindIndexCandidates for lookups.`,
					name, file)
			}
		}
	}
	if checked == 0 {
		t.Fatal("ABORT: no function queries by blind index at all; this guard is matching nothing " +
			"(did the queries get renamed?)")
	}
}

// TestColumnCryptoIsOnlyDecryptedByTheDualKeyReaders is the read-side twin of
// TestEveryColumnCryptoWriterIsARegisteredSurface.
//
// The writer guard stops a new ENCRYPTED surface from being orphaned by a
// rotation. This stops a new READER from being written that opens a
// columncrypto value with one key, which is the same defect facing the other
// way: it works everywhere except mid-rotation, and the failure is a locked-out
// user rather than an error anyone sees.
func TestColumnCryptoIsOnlyDecryptedByTheDualKeyReaders(t *testing.T) {
	allowed := map[string]string{
		"auth.go":          "decryptTOTPSecret + MigrateTOTPSecrets, both pass the keyring",
		"smtp_password.go": "resolveSMTPPassword, passes the keyring",
		"vault_keycheck.go": "the boot gate and SentinelOnPreviousKey, which ask WHICH key opens the " +
			"sentinel and therefore try them one at a time on purpose",
		"vault_rekey.go": "the sweep's classifier, which tries each key separately to report the answer",
	}
	needles := []string{
		"columncrypto." + "DecryptString(",
		"columncrypto." + "DecryptStringAny(",
	}

	callers := map[string]bool{}
	for file, src := range packageSources(t) {
		for _, n := range needles {
			if strings.Contains(src, n) {
				callers[file] = true
			}
		}
	}
	if len(callers) == 0 {
		t.Fatal("ABORT: no columncrypto decrypt call sites found at all; this guard is vacuous")
	}

	for file := range callers {
		if _, ok := allowed[file]; !ok {
			t.Errorf(`%s decrypts a columncrypto value directly.

Every reader of a vault-keyed column has to try the whole keyring, or it works on
every store except one mid-rotation. Route it through decryptTOTPSecret or
resolveSMTPPassword (or columncrypto.DecryptStringAny with cfg.VaultKey AND
cfg.VaultKeyPrevious), then add this file to the allowed map above with a reason.`, file)
		}
	}
	for file, why := range allowed {
		if !callers[file] {
			t.Errorf("the allowed list still names %s (%s) but that file no longer decrypts anything; "+
				"drop the entry so this list keeps meaning something", file, why)
		}
	}
}

// topLevelFuncs splits a source file into its top-level function bodies, keyed
// by declaration line. Textual, because the guards above ask textual questions
// and a real parse would be a heavier dependency than the question deserves.
func topLevelFuncs(src string) map[string]string {
	out := map[string]string{}
	const marker = "\nfunc "
	for i := strings.Index(src, marker); i >= 0; {
		start := i + 1
		next := strings.Index(src[start+1:], marker)
		end := len(src)
		if next >= 0 {
			end = start + 1 + next
		}
		body := src[start:end]
		name := body
		if nl := strings.IndexByte(name, '\n'); nl >= 0 {
			name = name[:nl]
		}
		out[strings.TrimSuffix(strings.TrimSpace(name), " {")] = body
		if next < 0 {
			break
		}
		i = start + 1 + next
	}
	return out
}

// callSite is one textual call to a helper, with its argument list.
type callSite struct {
	file string
	line int
	args string
}

// findCallSites returns every call to name in the package's non-test sources,
// skipping the declaration itself. Arguments are extracted by matching
// parentheses, so a call split across lines is still seen whole.
func findCallSites(t *testing.T, name string) []callSite {
	t.Helper()
	var out []callSite
	for file, src := range packageSources(t) {
		for i := 0; i+len(name)+1 <= len(src); i++ {
			if !strings.HasPrefix(src[i:], name+"(") {
				continue
			}
			// Skip identifiers that merely end with this name, and the func
			// declaration.
			if i > 0 && (isIdentByte(src[i-1]) || src[i-1] == '.') {
				continue
			}
			if i >= 5 && src[i-5:i] == "func " {
				continue
			}
			args, ok := balancedArgs(src[i+len(name):])
			if !ok {
				continue
			}
			out = append(out, callSite{
				file: file,
				line: 1 + strings.Count(src[:i], "\n"),
				args: args,
			})
		}
	}
	return out
}

func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// balancedArgs returns the text inside the leading parenthesis of s.
func balancedArgs(s string) (string, bool) {
	if len(s) == 0 || s[0] != '(' {
		return "", false
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[1:i], true
			}
		}
	}
	return "", false
}

// packageSources reads every non-test .go file in this package once.
var (
	packageSourcesOnce sync.Once
	packageSourcesMap  map[string]string
	packageSourcesErr  error
)

func packageSources(t *testing.T) map[string]string {
	t.Helper()
	packageSourcesOnce.Do(func() {
		files, err := filepath.Glob("*.go")
		if err != nil {
			packageSourcesErr = err
			return
		}
		packageSourcesMap = make(map[string]string, len(files))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, rErr := os.ReadFile(f)
			if rErr != nil {
				packageSourcesErr = rErr
				return
			}
			packageSourcesMap[filepath.Base(f)] = string(src)
		}
	})
	if packageSourcesErr != nil {
		t.Fatalf("read package sources: %v", packageSourcesErr)
	}
	if len(packageSourcesMap) == 0 {
		t.Fatal("ABORT: no package sources were read; every source guard in this file would pass vacuously")
	}
	return packageSourcesMap
}
