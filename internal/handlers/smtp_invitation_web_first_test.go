package handlers

import (
	"strings"
	"testing"
)

func TestInvitationEmailDirectsInviteeToSameOriginWebRedemption(t *testing.T) {
	body := buildInvitationHTML("Client", "INV-ABCD2345", "https://vault.example.test/")

	if !strings.Contains(body, `href="https://vault.example.test/invite?code=INV-ABCD2345"`) {
		t.Fatalf("invitation email does not link to the same-origin /invite page: %s", body)
	}
	for _, stale := range []string{
		"browser extension",
		"Have a setup code?",
		"Enter your setup code",
		"Your Setup Code",
	} {
		if strings.Contains(body, stale) {
			t.Errorf("invitation email still advertises extension setup-code activation %q", stale)
		}
	}
	if !strings.Contains(body, "Choose a password for your account") {
		t.Errorf("invitation email does not explain the web-first password step: %s", body)
	}
}

func TestInvitationEmailEscapesInviteeControlledHTML(t *testing.T) {
	body := buildInvitationHTML(`<img src=x onerror=alert(1)>`, `INV-ABCD2345`, "https://vault.example.test")
	if strings.Contains(body, `<img src=x`) {
		t.Fatalf("invitee name was interpolated as active HTML: %s", body)
	}
	if !strings.Contains(body, `&lt;img src=x onerror=alert(1)&gt;`) {
		t.Fatalf("escaped invitee name missing from email: %s", body)
	}
}
