package handlers

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// fakeSMTP is a minimal SMTP server that can be told whether to advertise
// STARTTLS. It records whether a message body was ever accepted, which is the
// thing that must not happen in cleartext.
type fakeSMTP struct {
	addr        string
	advertise   bool
	gotDataBody bool
	ln          net.Listener
}

func newFakeSMTP(t *testing.T, advertiseSTARTTLS bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeSMTP{addr: ln.Addr().String(), advertise: advertiseSTARTTLS, ln: ln}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
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
				f.gotDataBody = true
				inData = false
				w("250 OK")
			}
			continue
		}

		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			if f.advertise {
				w("250-fake")
				w("250 STARTTLS")
			} else {
				w("250 fake")
			}
		case strings.HasPrefix(up, "HELO"):
			w("250 fake")
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

// TestSTARTTLSRefusesCleartextDelivery locks the fix for a silent cleartext
// send.
//
// sendMailSTARTTLS used to upgrade only `if ok, _ := client.Extension("STARTTLS"); ok`
// and otherwise carry on unencrypted, returning no error. Invitation emails
// carry the redemption code that creates an account, so that code could cross a
// network in the clear while the admin believed TLS was on. Separately, "Use
// TLS" only ever selected implicit TLS on port 465, so ticking it on 587 was
// silently discarded.
//
// The invariant: if the relay will not encrypt, the message body is never sent.
func TestSTARTTLSRefusesCleartextDelivery(t *testing.T) {
	t.Run("relay without STARTTLS and TLS required is refused", func(t *testing.T) {
		f := newFakeSMTP(t, false)
		host, _, _ := net.SplitHostPort(f.addr)
		// Use a non-loopback-looking host name so the local-relay exemption does
		// not apply; the connection still goes to the fake on 127.0.0.1.
		err := sendMailSTARTTLS(f.addr, "mail.example.com", nil, "a@x", "b@y", []byte("body"), true)
		if err == nil {
			t.Fatal("cleartext delivery was ALLOWED with TLS required")
		}
		if !strings.Contains(err.Error(), "STARTTLS") {
			t.Fatalf("unhelpful error for an operator: %v", err)
		}
		if f.gotDataBody {
			t.Fatal("the message body was transmitted in cleartext before the refusal")
		}
		_ = host
	})

	t.Run("relay without STARTTLS is refused even when TLS was not explicitly required", func(t *testing.T) {
		f := newFakeSMTP(t, false)
		err := sendMailSTARTTLS(f.addr, "mail.example.com", nil, "a@x", "b@y", []byte("body"), false)
		if err == nil {
			t.Fatal("an invitation code would have crossed the network in cleartext with no error")
		}
		if f.gotDataBody {
			t.Fatal("the message body was transmitted in cleartext")
		}
	})

	t.Run("a loopback relay is still allowed without TLS", func(t *testing.T) {
		f := newFakeSMTP(t, false)
		// A local mail catcher never puts the message on a network.
		err := sendMailSTARTTLS(f.addr, "127.0.0.1", nil, "a@x", "b@y", []byte("body"), false)
		if err != nil {
			t.Fatalf("local relay was refused, breaking dev and sidecar setups: %v", err)
		}
		if !f.gotDataBody {
			t.Fatal("local relay accepted no body, the test did not exercise delivery")
		}
	})
}

// TestLoopbackSMTPHostDetection pins the exemption's boundary: it must cover a
// genuinely local relay and nothing else, or it becomes a way to send an
// invitation code in cleartext to an arbitrary host.
func TestLoopbackSMTPHostDetection(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST", "127.0.0.1", "::1", " 127.0.0.1 "} {
		if !isLoopbackSMTPHost(h) {
			t.Errorf("%q should be treated as local", h)
		}
	}
	for _, h := range []string{
		"smtp.gmail.com", "mail.example.com", "10.0.0.5", "192.168.1.10",
		"localhost.evil.com", "notlocalhost", "0.0.0.0", "",
	} {
		if isLoopbackSMTPHost(h) {
			t.Errorf("%q must NOT be treated as local: cleartext mail would be allowed to it", h)
		}
	}
}
