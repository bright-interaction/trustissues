package middleware

import (
	"database/sql"
	"log/slog"
	"net/http"
)

// TOTPEnrollmentRequiredCode is the machine-readable error code returned when
// the vault policy requires two-factor authentication and the caller has not
// enrolled. The frontend routes on this string, so it is part of the API
// contract: see FRONTEND-CONTRACT.md.
const TOTPEnrollmentRequiredCode = "totp_enrollment_required"

// RequireTOTPEnrollment refuses every request from a user who has not enrolled
// TOTP, while the `require_totp` vault policy is on. Session or API key alike:
// see the withdrawn exemption below.
//
// WHY THIS EXISTS AS A GATE AND NOT A BANNER.
//
// "Require two-factor authentication for all users" was enforced in exactly two
// places, and neither of them was the door. TOTPDisable refuses while the policy
// is on, so a user who HAD enrolled could not switch it off; and /api/auth/me
// returned a `totp_enrollment_required` flag that the frontend rendered as a
// prompt. Nothing anywhere required a user to enrol. Login gates on the
// per-user `totp_enabled` column alone, so an account that never enrolled
// authenticated on a password and nothing else while the settings page
// displayed "2FA required for all users". An administrator who ticked that box
// got a compliance indicator, which is the same defect the disable path was
// fixed for and the same one this middleware finishes.
//
// WHY THE ESCAPE HATCH IS A ROUTE GROUP AND NOT A PATH ALLOWLIST.
//
// A gate that refuses everything also refuses enrolment, which would lock out
// every un-enrolled user the moment the policy is switched on -- including,
// on a fresh instance, the only administrator. So /api/auth must stay
// reachable. The obvious way to arrange that is a list of exempt paths
// consulted inside this function, and that is the shape this codebase keeps
// losing to: a guard that recognises one spelling passes the route somebody
// adds next to it under a different one. Instead the escape hatch is
// structural. cmd/server/main.go registers /api/auth OUTSIDE the group this
// middleware is mounted on, so what is exempt is decided by where a route is
// declared and is visible at the declaration. A route added anywhere in the
// gated group is gated by default, and exempting one is a deliberate move to
// a different block rather than an edit to a list somewhere else.
//
// WHY API KEYS ARE GATED TOO, AFTER AN EXEMPTION WAS TRIED AND WITHDRAWN.
//
// The first version of this middleware exempted PrincipalAPIKey, reasoning that
// TOTP is an interactive-login control and that an API key is a credential the
// user minted while already authenticated, so gating it would break the browser
// extension without denying an attacker anything. Review refuted that premise
// and demonstrated the exemption was a self-renewing bypass:
//
//	GET /api/vault + session cookie -> 403 totp_enrollment_required
//	GET /api/vault + X-API-Key      -> 200, full entry list
//	POST /api/api-keys + X-API-Key  -> 201, a BRAND NEW key, expires_at null
//
// The third line is the one that settles it. POST /api/api-keys lives inside
// the gated group, so a session is correctly refused -- but an api-key
// principal walked the exemption through to the same handler and minted a fresh
// key, with no recorded parentage, so revoking the parent did not touch the
// child. The expiry cap at apikeys.go:171-190 does not bind when the parent key
// has no expiry, which is the default. An exemption that can mint its own
// successors is not an exemption, it is an escape hatch with no lock.
//
// Fixing it by keeping the exemption would have needed UpdateVaultPolicy to
// revoke every api_keys row belonging to an un-enrolled user in the same
// transaction as the settings write -- otherwise keys already in flight defeat
// the fix retroactively. That is more machinery, defending a premise that was
// wrong to begin with. So the gate now asks one question of every principal:
// is this user enrolled. The browser extension stops working for an un-enrolled
// user while the policy is on, and that is the correct reading of "two-factor
// authentication is required for all users" on a credential vault.
//
// FAIL CLOSED. A database error here refuses the request. The alternative is a
// gate that stops enforcing exactly when the database is unhealthy, and this is
// the same rule the login path already applies to its own 2FA lookup ("A DB
// error MUST block login to prevent 2FA bypass").
func RequireTOTPEnrollment(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := GetUserID(r.Context())
			if userID == "" {
				// Unauthenticated requests never reach here in the mounted
				// configuration, because JWTOrAPIKeyAuth runs first and
				// rejects them. Refusing rather than passing through keeps
				// that true if the mounting ever changes.
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}

			// One statement for both facts. Read together so the policy and the
			// enrolment state cannot be observed at two different instants: a
			// caller enrolling concurrently would otherwise be able to land
			// between them.
			//
			// A missing users row yields enrolled=false and therefore a refusal.
			// enrichUserContext has already rejected unknown and disabled users
			// upstream, so this is a belt-and-braces fail-closed default rather
			// than a reachable branch.
			var policyOn, enrolled bool
			err := db.QueryRowContext(r.Context(),
				`SELECT
				   COALESCE((SELECT value FROM settings WHERE key = 'require_totp'), 'false') = 'true',
				   COALESCE((SELECT totp_enabled FROM users WHERE id = ?), 0) = 1`,
				userID,
			).Scan(&policyOn, &enrolled)
			if err != nil {
				slog.Error("totp enrollment gate: database error", "error", err, "user_id", userID)
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				return
			}

			if policyOn && !enrolled {
				// 403 with a machine-readable code, not a redirect: every
				// caller here is an XHR from the SPA, which routes to the
				// enrolment screen on this code.
				http.Error(w,
					`{"error":"two-factor authentication is required by the vault policy; enrol an authenticator to continue","code":"`+
						TOTPEnrollmentRequiredCode+`"}`,
					http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
