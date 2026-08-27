package handlers

import (
	"crypto/tls"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// sendInvitationEmail sends a branded invitation email via SMTP.
func sendInvitationEmail(host, port, from, username, password string, useTLS bool, toEmail, name, code, serverURL string) error {
	if port == "" {
		// 587 either way.
		//
		// A blank port used to select 465 (implicit TLS) whenever useTLS was on,
		// while the schema default and the UI placeholder both say 587. Nothing
		// in the product tells the operator that ticking a TLS box also silently
		// changes the port, and 465 is blocked outbound in this estate, so the
		// send hangs until the dial timeout rather than failing fast. 587 with
		// STARTTLS is the path that works and the one the rest of the product
		// advertises; an operator who genuinely wants implicit TLS still sets
		// 465 explicitly.
		port = "587"
	}

	addr := net.JoinHostPort(host, port)

	subject := "You've been invited to Trustissues"
	htmlBody := buildInvitationHTML(name, code, serverURL)

	msg := buildMIMEMessage(from, toEmail, subject, htmlBody)

	var auth smtp.Auth
	if username != "" && password != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}

	if useTLS && port == "465" {
		// Implicit TLS (SMTPS)
		return sendMailTLS(addr, host, auth, from, toEmail, msg)
	}

	// STARTTLS (port 587 or 25). "Use TLS" on any port other than 465 used to be
	// silently discarded: the toggle only ever selected implicit TLS, so an
	// admin on 587 who ticked it got opportunistic STARTTLS that degraded to
	// cleartext without complaint. Pass it through so the request is enforced.
	return sendMailSTARTTLS(addr, host, auth, from, toEmail, msg, useTLS)
}

// sendTestEmail sends a short test message so admins can verify their SMTP
// settings from the Settings page.
func sendTestEmail(host, port, from, username, password string, useTLS bool, toEmail string) error {
	if port == "" {
		// 587 either way.
		//
		// A blank port used to select 465 (implicit TLS) whenever useTLS was on,
		// while the schema default and the UI placeholder both say 587. Nothing
		// in the product tells the operator that ticking a TLS box also silently
		// changes the port, and 465 is blocked outbound in this estate, so the
		// send hangs until the dial timeout rather than failing fast. 587 with
		// STARTTLS is the path that works and the one the rest of the product
		// advertises; an operator who genuinely wants implicit TLS still sets
		// 465 explicitly.
		port = "587"
	}

	addr := net.JoinHostPort(host, port)
	subject := "Trustissues SMTP test"
	htmlBody := `<p>This is a test email from Trustissues. Your SMTP settings work.</p>`
	msg := buildMIMEMessage(from, toEmail, subject, htmlBody)

	var auth smtp.Auth
	if username != "" && password != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}

	if useTLS && port == "465" {
		return sendMailTLS(addr, host, auth, from, toEmail, msg)
	}
	// Same enforcement as the real send, so the Settings test button exercises
	// the transport the invitation email will actually use rather than a more
	// permissive one.
	return sendMailSTARTTLS(addr, host, auth, from, toEmail, msg, useTLS)
}

func buildMIMEMessage(from, to, subject, htmlBody string) []byte {
	// Sanitize header values to prevent CRLF header injection
	sanitize := func(s string) string {
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\n", "")
		return s
	}
	headers := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n",
		sanitize(from), sanitize(to), sanitize(subject),
	)
	return []byte(headers + htmlBody)
}

// SMTP network bounds. Neither transport had any: a relay that accepts the
// connection and then stays silent pinned the sending goroutine (and its socket)
// for the life of the process, with zero user-visible signal.
// Variables, not constants, so the deadline test can assert the BEHAVIOUR
// (a silent relay is given up on) without paying the production wait. The test
// that proves these exist took 40 of the handler package's 51 seconds, which is
// most of a suite budget spent watching two timers expire.
var (
	smtpDialTimeout = 10 * time.Second
	smtpIOTimeout   = 30 * time.Second
)

// setSMTPTimeoutsForTest shortens the network bounds and returns a restore func.
// Test-only by convention; the production values are pinned by a test so a
// permanent change has to be deliberate.
func setSMTPTimeoutsForTest(dial, io time.Duration) func() {
	prevDial, prevIO := smtpDialTimeout, smtpIOTimeout
	smtpDialTimeout, smtpIOTimeout = dial, io
	return func() { smtpDialTimeout, smtpIOTimeout = prevDial, prevIO }
}

func sendMailTLS(addr, host string, auth smtp.Auth, from, to string, msg []byte) error {
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	// Bounded dial. Without a timeout a relay that accepts the TCP connection and
	// then says nothing blocks this goroutine forever: the invitation send runs
	// detached (go trySendInvitationEmail), so the HTTP request still returns
	// "invitation created", the invite is never delivered, and even the error log
	// never fires because the call never returns. The admin gets no signal at all.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: smtpDialTimeout}, "tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()
	// The dial timeout only covers connect+handshake; this bounds the banner and
	// every command after it.
	if dErr := conn.SetDeadline(time.Now().Add(smtpIOTimeout)); dErr != nil {
		return fmt.Errorf("TLS deadline: %w", dErr)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP client failed: %w", err)
	}
	defer client.Quit()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP write failed: %w", err)
	}
	return w.Close()
}

// isLoopbackSMTPHost reports whether the relay is on this machine, where
// unencrypted SMTP never crosses a network. Used only to allow a local mail
// catcher or sidecar relay to keep working without TLS.
func isLoopbackSMTPHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// sendMailSTARTTLS delivers over a plain connection upgraded with STARTTLS.
//
// requireTLS makes the upgrade mandatory. It used to be purely opportunistic:
// if the relay did not advertise STARTTLS the client carried on in CLEARTEXT
// and returned no error, so an invitation email (which carries the redemption
// code that creates an account) could cross the network in the clear while the
// admin had explicitly ticked "Use TLS". Go's PlainAuth refuses to hand
// credentials to an unencrypted non-local server, so the SMTP password was
// never the exposure; the message body was.
func sendMailSTARTTLS(addr, host string, auth smtp.Auth, from, to string, msg []byte, requireTLS bool) error {
	// Same bound for the STARTTLS path, and it is the likelier one to hang: an
	// admin who sets port 465 but leaves "Use TLS" unticked lands here, sends
	// plaintext at an implicit-TLS port, and then both ends wait forever (us for
	// a 220 banner, the relay for a ClientHello).
	rawConn, err := (&net.Dialer{Timeout: smtpDialTimeout}).Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	// Covers banner, handshake, AUTH and DATA. Re-armed after STARTTLS below.
	if dErr := rawConn.SetDeadline(time.Now().Add(smtpIOTimeout)); dErr != nil {
		rawConn.Close()
		return fmt.Errorf("smtp deadline: %w", dErr)
	}
	client, err := smtp.NewClient(rawConn, host)
	if err != nil {
		rawConn.Close()
	}
	if err != nil {
		return fmt.Errorf("SMTP dial failed: %w", err)
	}
	defer client.Quit()

	ok, _ := client.Extension("STARTTLS")
	switch {
	case ok:
		tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
		}
	case requireTLS:
		return fmt.Errorf("SMTP server at %s does not offer STARTTLS but TLS is required; "+
			"use port 465 for implicit TLS, or untick \"Use TLS\" only if this relay is on a trusted network", addr)
	case !isLoopbackSMTPHost(host):
		// Even without an explicit TLS request, refuse to push an invitation
		// code across a network in cleartext. A local relay or mail catcher is
		// still allowed, since that traffic never leaves the host.
		return fmt.Errorf("SMTP server at %s does not offer STARTTLS; refusing to send mail in cleartext "+
			"(invitation emails carry an account-creation code). Use a relay that supports STARTTLS or implicit TLS on port 465", addr)
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP write failed: %w", err)
	}
	return w.Close()
}

func buildInvitationHTML(name, code, serverURL string) string {
	greeting := "Hi"
	if name != "" {
		greeting = "Hi " + html.EscapeString(name)
	}

	serverURL = strings.TrimRight(serverURL, "/")
	inviteURL := serverURL + "/invite?code=" + url.QueryEscape(code)

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<div style="max-width:520px;margin:40px auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1)">
  <div style="background:#0f172a;padding:28px 32px;text-align:center">
    <span style="color:white;font-size:20px;font-weight:700;vertical-align:middle">Trustissues</span>
  </div>
  <div style="padding:32px">
    <h2 style="color:#0f172a;margin:0 0 8px;font-size:22px">You've been invited to Trustissues</h2>
    <p style="color:#475569;margin:0 0 24px;font-size:15px;line-height:1.6">
      %s, you've been invited to use Trustissues, a secure password manager for your team.
    </p>
    <div style="background:#f1f5f9;border-radius:8px;padding:20px;text-align:center;margin-bottom:24px">
      <p style="color:#64748b;margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:1px">Your Invitation Code</p>
      <p style="color:#0f172a;margin:0;font-size:32px;font-weight:700;letter-spacing:4px;font-family:monospace">%s</p>
    </div>
    <div style="text-align:center;margin-bottom:24px">
      <a href="%s" style="display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;border-radius:8px;padding:12px 20px;font-size:14px;font-weight:600">Accept invitation</a>
    </div>
    <h3 style="color:#0f172a;margin:0 0 12px;font-size:15px">Getting Started</h3>
    <ol style="color:#475569;margin:0 0 24px;padding-left:20px;font-size:14px;line-height:2">
      <li>Open the secure invitation link above</li>
      <li>Choose a password for your account</li>
      <li>Sign in to review and accept any shared-vault invitations</li>
    </ol>
    <p style="color:#94a3b8;margin:0;font-size:12px">
      This invitation expires in 48 hours. If it has expired, ask your administrator for a new one.
    </p>
  </div>
  <div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 32px;text-align:center">
    <p style="color:#94a3b8;margin:0;font-size:12px">Sent from Trustissues &middot; Self-hosted Secret Management</p>
  </div>
</div>
</body>
</html>`, greeting, html.EscapeString(code), html.EscapeString(inviteURL))
}
