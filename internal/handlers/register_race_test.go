package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/config"
)

// slowBody delivers a JSON body one chunk at a time, holding the request open the
// way a trickling client does against the 30s ReadTimeout.
type slowBody struct {
	parts []string
	i     int
	gate  chan struct{} // released after the competing request has finished
}

func (s *slowBody) Read(p []byte) (int, error) {
	if s.i == 1 && s.gate != nil {
		<-s.gate // hold HERE: past the CountUsers check, before the body is decoded
	}
	if s.i >= len(s.parts) {
		return 0, io.EOF
	}
	n := copy(p, s.parts[s.i])
	s.i++
	return n, nil
}
func (s *slowBody) Close() error { return nil }

// First-run registration must be atomic, because it mints an ADMIN and is
// unauthenticated.
//
// Register read CountUsers, then decoded the request body, then INSERTed, with no
// transaction and no recheck. The gap is not instantaneous and it is
// ATTACKER-EXTENDABLE: the body decode sits inside it and the server's ReadTimeout
// is 30s, so a client that trickles its body holds the window open at will.
//
// Measured before the fix: attacker=201 owner=201, 2 users, 2 admins. A request that
// passed the count==0 gate and then stalled mid-body still created an account after
// the legitimate operator finished setup. That is a full takeover of a fresh
// instance by anyone who can reach it during the setup window, and it is the
// code-level reason for the operational rule that a public instance must never be
// left at setup_required=true.
//
// The fix is one statement (INSERT ... WHERE NOT EXISTS), so there is no window to
// race. This test is the proof, and it is written as a RACE rather than as a
// sequential 409 because the sequential case always passed.
func TestRegisterRaceWithATrickledBody(t *testing.T) {
	vh, queries := newCollectionAuthzEnv(t)
	ah := NewAuthHandler(queries, &config.Config{
		JWTSecret: strings.Repeat("j", 32), VaultKey: strings.Repeat("k", 32),
	})

	gate := make(chan struct{})

	// Attacker: passes the count==0 gate, then stalls mid-body.
	slow := &slowBody{
		parts: []string{`{"email":"attacker@evil.test",`, `"password":"CorrectHorseBattery1!","name":"E"}`},
		gate:  gate,
	}
	slowReq := httptest.NewRequest(http.MethodPost, "/api/auth/register", slow)
	slowRec := httptest.NewRecorder()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ah.Register(slowRec, slowReq) }()

	time.Sleep(150 * time.Millisecond) // let it get past CountUsers and into the read

	// Legitimate operator completes setup entirely.
	okReq := httptest.NewRequest(http.MethodPost, "/api/auth/register",
		strings.NewReader(`{"email":"owner@example.com","password":"CorrectHorseBattery1!","name":"Owner"}`))
	okRec := httptest.NewRecorder()
	ah.Register(okRec, okReq)
	if okRec.Code != http.StatusOK && okRec.Code != http.StatusCreated {
		t.Fatalf("ABORT: the legitimate setup did not succeed (%d %s), so this proves nothing",
			okRec.Code, okRec.Body.String())
	}

	close(gate) // the attacker's body now finishes arriving
	wg.Wait()

	var users, admins int
	_ = vh.db.QueryRow(`SELECT count(*) FROM users`).Scan(&users)
	_ = vh.db.QueryRow(`SELECT count(*) FROM users WHERE role='admin'`).Scan(&admins)
	t.Logf("attacker=%d owner=%d | users=%d admins=%d", slowRec.Code, okRec.Code, users, admins)

	if slowRec.Code == http.StatusOK || slowRec.Code == http.StatusCreated {
		t.Errorf("RACE CONFIRMED: a request that passed the first-run gate BEFORE setup completed "+
			"still created an account afterwards (%d). Register is unauthenticated and mints an "+
			"ADMIN, so this is a full takeover of a fresh instance by anyone who can reach it "+
			"during setup.", slowRec.Code)
	}
	if users > 1 || admins > 1 {
		t.Errorf("RACE CONFIRMED: %d users / %d admins after one legitimate setup", users, admins)
	}
}
