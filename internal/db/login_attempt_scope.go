package db

// Hand-written, not sqlc output: sqlc owns db.go, models.go, querier.go and
// *.sql.go in this package and does not touch this file.

// The legal values of login_attempts.scope, mirrored by a CHECK constraint in
// migration 00042. Passing a string literal instead of one of these is how the
// split quietly comes undone, so the callers name a constant and a typo is a
// compile error rather than a row that counts toward nothing.
const (
	// LoginAttemptScopePasswordLogin is a password attempt at the PUBLIC
	// POST /api/auth/login. Anyone who knows an address can make these accrue;
	// that is the point of the endpoint and the reason this scope must gate
	// nothing except login itself.
	LoginAttemptScopePasswordLogin = "password_login"

	// LoginAttemptScopeSessionReauth is a password or code attempt made by a
	// caller that ALREADY authenticated as the account in question: TOTP
	// enrolment, TOTP disable, and vault re-auth (unlock, rotate, validate,
	// retry-pending-revoke).
	//
	// Writing one of these requires holding a live session or API key for that
	// user, which is exactly the property that makes this counter safe to put in
	// front of the enrolment path: an outsider cannot fill it, so an outsider
	// cannot hold the require_totp gate's only exit shut.
	LoginAttemptScopeSessionReauth = "session_reauth"
)
