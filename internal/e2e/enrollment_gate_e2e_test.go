//go:build e2e

// Package e2e drives the REAL server binary over HTTP.
//
// Everything else proving the enrolment gate is a handler test or a jsdom
// render: they call functions and mount components. Neither can answer the
// question that actually decides whether this feature ships -- can a person
// starting from an empty database reach the gated state and get out of it
// again, through the same HTTP surface a browser uses?
//
// That question was open for the whole of this branch's life, and it is not
// academic: the production instance has one admin with totp_enabled=0, and
// UpdateVaultPolicy refuses to enable require_totp unless the acting admin is
// already enrolled. So the entire feature was unreachable in production while
// every unit test passed.
//
// Run: go test -tags e2e ./internal/e2e/
package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/totp"
)

const (
	adminEmail  = "admin@e2e.example.com"
	adminPass   = "AdminCorrectHorseBattery1!"
	userEmail   = "member@e2e.example.com"
	userPass    = "MemberCorrectHorseBattery1!"
	gateCodeKey = "totp_enrollment_required"
)

type server struct {
	t       *testing.T
	baseURL string
}

// freePort asks the OS for a port and hands it back, so parallel runs and a
// developer's already-running instance on 8080 cannot collide.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// realKey returns a genuine random hex key. Config validation rejects
// low-entropy placeholders like strings.Repeat("k", 32) outright -- a defence
// worth keeping, so the test satisfies it rather than working around it.
// nbytes is the RAW byte count; the returned string is twice that in hex.
// SHIELD_KEY is validated as exactly 32 characters (AES-256 via a 16-byte hex
// seed), while JWT_SECRET and VAULT_KEY take the full 64.
func realKey(t *testing.T, nbytes int) string {
	t.Helper()
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func startServer(t *testing.T) *server {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "trustissues-e2e")
	build := exec.Command("go", "build", "-o", bin, "./cmd/server")
	build.Dir = ".."
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, out)
	}

	port := freePort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	dataDir := t.TempDir()

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"TRUSTISSUES_PORT="+fmt.Sprint(port),
		"TRUSTISSUES_BIND_HOST=127.0.0.1",
		"TRUSTISSUES_DATA_DIR="+dataDir,
		"TRUSTISSUES_BASE_URL="+baseURL,
		"TRUSTISSUES_JWT_SECRET="+realKey(t, 32),
		"TRUSTISSUES_VAULT_KEY="+realKey(t, 32),
		"TRUSTISSUES_SHIELD_KEY="+realKey(t, 16),
		"TRUSTISSUES_FRONTEND_DIR="+filepath.Join("..", "..", "frontend", "dist"),
		"TRUSTISSUES_LOG_LEVEL=error",
	)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	// A server that refuses to boot (bad config, port clash, failed migration)
	// must surface its reason immediately. Polling alone would spend the whole
	// timeout and then report "not ready", hiding the actual error.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		if t.Failed() {
			t.Logf("server output:\n%s", logs.String())
		}
	})

	// Boot can involve migrations; poll rather than sleeping a fixed guess.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/api/auth/status")
		if err == nil {
			resp.Body.Close()
			return &server{t: t, baseURL: baseURL}
		}
		select {
		case err := <-exited:
			t.Fatalf("server exited during boot (%v):\n%s", err, logs.String())
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server did not become ready within 30s:\n%s", logs.String())
	return nil
}

// client is one browser: its own cookie jar, and the Origin header the CSRF
// check demands on every state-changing request.
type client struct {
	t    *testing.T
	srv  *server
	http *http.Client
}

func (s *server) newClient() *client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		s.t.Fatalf("cookie jar: %v", err)
	}
	return &client{t: s.t, srv: s, http: &http.Client{
		Jar: jar,
		// Do not follow redirects: a redirect would mask a refusal.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (c *client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.srv.baseURL+path, rdr)
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// csrfOriginCheck refuses a state-changing request whose Origin is not the
	// configured BaseURL, exactly as a browser would send it.
	req.Header.Set("Origin", c.srv.baseURL)

	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if len(out) == 0 && len(raw) > 0 {
		out["_raw"] = string(raw)
	}
	return resp.StatusCode, out
}

// enrol runs the real two-step enrolment: setup mints a seed, verify turns it
// on and requires the password.
func (c *client) enrol(password string) {
	c.t.Helper()
	code, body := c.do(http.MethodPost, "/api/auth/totp/setup", nil)
	if code != http.StatusOK {
		c.t.Fatalf("totp/setup: %d %v", code, body)
	}
	secret, _ := body["secret"].(string)
	if secret == "" {
		c.t.Fatalf("totp/setup returned no secret: %v", body)
	}
	otp, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		c.t.Fatalf("generate code: %v", err)
	}
	code, body = c.do(http.MethodPost, "/api/auth/totp/verify", map[string]any{
		"code": otp, "password": password,
	})
	if code != http.StatusOK {
		c.t.Fatalf("totp/verify: %d %v", code, body)
	}
}

// TestTheGateCanActuallyBeTurnedOnAndEscaped is the whole feature, start to
// finish, against the real binary.
func TestTheGateCanActuallyBeTurnedOnAndEscaped(t *testing.T) {
	srv := startServer(t)

	// --- 1. First-run: the instance has no users at all. ---
	admin := srv.newClient()
	if code, body := admin.do(http.MethodPost, "/api/auth/register", map[string]any{
		"email": adminEmail, "password": adminPass, "name": "E2E Admin",
	}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("first-run register: %d %v", code, body)
	}

	code, body := admin.do(http.MethodPost, "/api/auth/login", map[string]any{
		"email": adminEmail, "password": adminPass,
	})
	if code != http.StatusOK {
		t.Fatalf("admin login: %d %v", code, body)
	}

	// Read the live policy and flip one field, the way the settings UI does.
	// Sending a hand-built object instead made the first version of this test
	// "pass" step 2 on a 400 VALIDATION_ERROR about min_password_length -- a
	// refusal, but not the refusal under test. An assertion of "not 200" is
	// satisfied by any bug at all.
	policy := func() map[string]any {
		code, body := admin.do(http.MethodGet, "/api/settings/vault-policy", nil)
		if code != http.StatusOK {
			t.Fatalf("read vault policy: %d %v", code, body)
		}
		return body
	}

	withTOTP := func(on bool) map[string]any {
		p := policy()
		delete(p, "request_id")
		p["require_totp"] = on
		return p
	}

	// --- 2. The admin cannot turn the policy on before enrolling. ---
	//
	// This is the guard that makes production's totp_enabled=0 a SAFE state
	// rather than a latent one, so it is worth pinning: it is the reason the
	// exposed configuration is currently unreachable in prod.
	code, body = admin.do(http.MethodPut, "/api/settings/vault-policy", withTOTP(true))
	if code == http.StatusOK {
		t.Fatal("an UN-ENROLLED admin enabled require_totp. That is how an instance " +
			"locks out its only administrator: the policy would refuse them every route " +
			"except enrolment, and no admin unlock endpoint exists.")
	}
	// And it must be refused for the RIGHT reason. A validation error or a 500
	// would also be "not 200" while proving nothing about the guard.
	if code != http.StatusForbidden && code != http.StatusConflict &&
		code != http.StatusBadRequest {
		t.Fatalf("the refusal was %d %v, which is not a recognisable policy refusal", code, body)
	}
	t.Logf("un-enrolled admin refused with %d: %v", code, body)

	// --- 3. Admin enrols, then the policy can go on. ---
	admin.enrol(adminPass)

	code, body = admin.do(http.MethodPut, "/api/settings/vault-policy", withTOTP(true))
	if code != http.StatusOK {
		t.Fatalf("an ENROLLED admin could not enable require_totp: %d %v.\n"+
			"Then the feature cannot be switched on at all.", code, body)
	}

	// Confirm it actually stuck, rather than trusting the 200.
	if on, _ := policy()["require_totp"].(bool); !on {
		t.Fatal("the policy update answered 200 but require_totp did not persist")
	}

	// --- 4. A second, un-enrolled user. ---
	code, body = admin.do(http.MethodPost, "/api/admin/users", map[string]any{
		"email": userEmail, "password": userPass, "name": "E2E Member", "role": "user",
	})
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("create member: %d %v", code, body)
	}

	member := srv.newClient()
	code, body = member.do(http.MethodPost, "/api/auth/login", map[string]any{
		"email": userEmail, "password": userPass,
	})
	if code != http.StatusOK {
		t.Fatalf("member login: %d %v", code, body)
	}

	// --- 5. THE LOGIN RESPONSE ITSELF must carry the flag. ---
	//
	// This is the P0 that made the escape hatch invisible: the SPA does not call
	// /auth/me after login, the field has omitempty, and Login built its userInfo
	// without it -- so the key vanished and a gated user landed on /vault, watched
	// every query 403, and saw no banner at all. A reload fixed it, which nobody
	// would guess.
	user, _ := body["user"].(map[string]any)
	if user == nil {
		t.Fatalf("login response carried no user object: %v", body)
	}
	if flag, _ := user["totp_enrollment_required"].(bool); !flag {
		t.Fatalf("the LOGIN response did not set totp_enrollment_required (user=%v).\n"+
			"The SPA never calls /auth/me after login, so the enrolment banner never "+
			"renders and the gated user is given no way out.", user)
	}

	// --- 6. Gated: every route outside /api/auth is refused, WITH the code. ---
	for _, path := range []string{"/api/vault", "/api/collections", "/api/api-keys", "/api/activity"} {
		code, body = member.do(http.MethodGet, path, nil)
		if code != http.StatusForbidden {
			t.Errorf("GET %s answered %d, expected 403 for an un-enrolled user under require_totp: %v",
				path, code, body)
			continue
		}
		if got, _ := body["code"].(string); got != gateCodeKey {
			t.Errorf("GET %s refused with code %q, expected %q. The frontend routes on this "+
				"string; without it the refusal is indistinguishable from an ordinary 403.",
				path, got, gateCodeKey)
		}
	}

	// --- 7. The escape hatch is open, and says why. ---
	code, body = member.do(http.MethodGet, "/api/auth/me", nil)
	if code != http.StatusOK {
		t.Fatalf("/api/auth/me answered %d for a gated user: %d %v.\n"+
			"That is the route the banner and the enrolment form depend on; gating it "+
			"leaves no way out at all.", code, code, body)
	}
	if flag, _ := body["totp_enrollment_required"].(bool); !flag {
		t.Fatalf("/api/auth/me did not report totp_enrollment_required: %v", body)
	}

	// --- 8. Enrol through the gate, and the vault comes back. ---
	member.enrol(userPass)

	code, body = member.do(http.MethodGet, "/api/vault", nil)
	if code != http.StatusOK {
		t.Fatalf("after enrolling, GET /api/vault answered %d %v.\n"+
			"Enrolment is the only exit from the gate; if it does not restore access "+
			"the account is permanently locked out.", code, body)
	}

	code, body = member.do(http.MethodGet, "/api/auth/me", nil)
	if code != http.StatusOK {
		t.Fatalf("/api/auth/me after enrolment: %d %v", code, body)
	}
	if flag, _ := body["totp_enrollment_required"].(bool); flag {
		t.Fatal("the user has enrolled but is still flagged as requiring enrolment; " +
			"the banner would never go away")
	}
}

// TestAStrangerCannotHoldTheGateShut is the lockout P0, end to end.
//
// The handler test seeds login_attempts rows directly. This one actually POSTs
// wrong passwords at the PUBLIC login endpoint from a client with no
// credentials, and then checks the victim's own enrolment still works -- which
// is the property that matters and the one a seeded test cannot fully prove.
func TestAStrangerCannotHoldTheGateShut(t *testing.T) {
	srv := startServer(t)

	admin := srv.newClient()
	if code, body := admin.do(http.MethodPost, "/api/auth/register", map[string]any{
		"email": adminEmail, "password": adminPass, "name": "E2E Admin",
	}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, body)
	}
	if code, body := admin.do(http.MethodPost, "/api/auth/login", map[string]any{
		"email": adminEmail, "password": adminPass,
	}); code != http.StatusOK {
		t.Fatalf("login: %d %v", code, body)
	}

	// The attacker: a client with no session, who merely knows the address.
	//
	// Spray until the LOGIN door actually locks, rather than a fixed five.
	//
	// A fixed count binds the constant, not the property: a review mutation that
	// reintroduced the shared counter but moved the threshold from 5 to 6 left
	// this test green, because five failures no longer tripped anything at all
	// and enrolment was never under threat. What must be true is "however many
	// failures a stranger causes at the public door, the victim's own enrolment
	// is unaffected" -- so the spray runs until login is demonstrably locked,
	// and only then is enrolment checked. That holds at any threshold.
	//
	// Capped because Login sleeps a graduated 2s, 4s, 6s... from the fourth
	// failure onward, and this is real wall-clock in an e2e.
	stranger := srv.newClient()
	const maxSpray = 12
	locked := false
	sprayed := 0
	for i := 0; i < maxSpray && !locked; i++ {
		code, _ := stranger.do(http.MethodPost, "/api/auth/login", map[string]any{
			"email": adminEmail, "password": "definitely-not-the-password",
		})
		sprayed++
		switch code {
		case http.StatusUnauthorized:
		case http.StatusTooManyRequests:
			locked = true
		default:
			t.Fatalf("spray %d answered %d, expected 401 or 429", i+1, code)
		}
	}
	if !locked {
		t.Fatalf("ABORT: %d wrong passwords at the public login endpoint never locked the login "+
			"door. The spray is not reaching the per-email lockout, so this test cannot show "+
			"anything about whether enrolment is insulated from it.", sprayed)
	}
	t.Logf("login door locked after %d stranger failures; enrolment must still work", sprayed)

	// The victim, holding a valid session, must still be able to enrol -- which
	// under require_totp is the only way out of a 403 on every other route.
	code, body := admin.do(http.MethodPost, "/api/auth/totp/setup", nil)
	if code == http.StatusTooManyRequests {
		t.Fatalf("a stranger's %d wrong passwords at the PUBLIC login endpoint refused "+
			"the owner's own enrolment setup (429 %v).", sprayed, body)
	}
	if code != http.StatusOK {
		t.Fatalf("totp/setup: %d %v", code, body)
	}
	secret, _ := body["secret"].(string)
	otp, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	code, body = admin.do(http.MethodPost, "/api/auth/totp/verify", map[string]any{
		"code": otp, "password": adminPass,
	})
	if code == http.StatusTooManyRequests {
		t.Fatalf("a stranger closed the gate's only exit: %d wrong passwords at the "+
			"public login endpoint refused the owner's enrolment with a valid session, "+
			"the correct password and a correct live code (429 %v).\n"+
			"There is no self-heal -- Login enforces the same counter before the password "+
			"check -- so this holds the entire vault shut, renewably, forever.", sprayed, body)
	}
	if code != http.StatusOK {
		t.Fatalf("totp/verify: %d %v", code, body)
	}
}
