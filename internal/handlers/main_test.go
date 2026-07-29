package handlers

import (
	"os"
	"testing"

	"github.com/brightinteraction/trustissues/internal/passwordhash"
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
func TestMain(m *testing.M) {
	passwordhash.SetTestCost()
	os.Exit(m.Run())
}
