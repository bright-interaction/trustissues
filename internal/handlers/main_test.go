package handlers

import (
	"os"
	"testing"

	"github.com/bright-interaction/trustissues/internal/passwordhash"
	"github.com/bright-interaction/trustissues/internal/totp"
)

// TestMain lowers the argon2id cost for this package.
//
// Production cost is 64 MiB at t=3, and this package makes about 90 hash or
// verify calls, which put it at roughly 51 seconds and 228 seconds under -race
// before this change. The rotation behaviour matrix adds tens more environments;
// without this the package would approach Go's default 10-minute timeout, and a
// suite that is too slow to run is a worse security outcome than a cheap KDF in
// tests.
//
// passwordhash.SetTestCost panics if it is ever reached from a non-test binary.
//
// The prediction above came true anyway, because only the argon2 half was capped.
// Enrolling 2FA mints eight bcrypt hashes at DefaultCost and a wrong recovery
// code compares against all eight, and dozens of tests in this package enrol. The
// package measured 612s under -race against ci-go's 600s ceiling with none of the
// 2026-08-05 tests present, so it was over budget on the bcrypt half alone.
// totp.SetTestCost carries the same non-test-binary panic.
func TestMain(m *testing.M) {
	passwordhash.SetTestCost()
	totp.SetTestCost()
	os.Exit(m.Run())
}
