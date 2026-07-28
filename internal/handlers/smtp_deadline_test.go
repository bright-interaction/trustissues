package handlers

import (
	"net"
	"net/smtp"
	"testing"
	"time"
)

// TestSMTPSendsGiveUpOnASilentRelay locks the fix for a send that hung forever.
//
// Neither transport had a dial or IO deadline. A relay that accepts the TCP
// connection and then says nothing (a tarpit, a greylister, a firewall that
// accepts then drops, or simply port 465 with "Use TLS" unticked, where we wait
// for a 220 banner while the relay waits for a ClientHello) blocked the sending
// goroutine for the life of the process.
//
// The invitation path is the one that bites: users.go launches it detached with
// `go trySendInvitationEmail(...)`, so POST /api/admin/invitations returns 201
// "invitation created", the invitee never receives anything, and even the error
// log never fires because the call never returns. The admin has no signal at
// all, and the one diagnostic they would reach for, Settings > Send test email,
// is synchronous and hangs the request too.
//
// The listener below is exactly that: it accepts and never writes a byte.
func TestSMTPSendsGiveUpOnASilentRelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 8)
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			// Hold the connection open and stay silent. Deliberately never
			// closed: a close would produce an EOF error and the test would
			// pass without any deadline being involved.
			defer c.Close()
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	addr := net.JoinHostPort(host, port)
	auth := smtp.PlainAuth("", "u", "p", host)
	msg := []byte("Subject: t\r\n\r\nbody\r\n")

	// Generous relative to the 10s dial / 30s IO bounds, but finite. Without a
	// deadline these never return and the test fails on the whole-binary timeout
	// instead, which is the failure this is preventing.
	const budget = 75 * time.Second

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"STARTTLS", func() error { return sendMailSTARTTLS(addr, host, auth, "a@b.c", "d@e.f", msg, false) }},
		{"implicit TLS", func() error { return sendMailTLS(addr, host, auth, "a@b.c", "d@e.f", msg) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan error, 1)
			start := time.Now()
			go func() { done <- tc.run() }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("a silent relay reported SUCCESS; the caller would record the mail as sent")
				}
				t.Logf("gave up after %s: %v", time.Since(start).Round(time.Second), err)
			case <-time.After(budget):
				t.Fatalf("still blocked after %s with no deadline; the invitation goroutine and its socket "+
					"would be pinned for the life of the process and the admin would never learn the mail was lost", budget)
			}
		})
	}

	// Guard the fixture: if nothing ever connected, the assertions above could
	// have passed on a dial error rather than on the hang they target.
	select {
	case <-accepted:
	default:
		t.Fatal("ABORT: the fake relay was never connected to; this test proved nothing")
	}
}
