module github.com/bright-interaction/trustissues

// go 1.26.6, not 1.26, and deliberately without a `toolchain` line.
//
// The `go` directive is the ONLY machine-enforced floor: under
// GOTOOLCHAIN=local, which every official golang image bakes in, a builder
// below it refuses outright --
//   go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)
// -- while a `toolchain` directive is silently ignored in that same setting.
// Measured 2026-08-18 in both images. So this line, not the toolchain line,
// is what stops anyone building this vault against a stdlib carrying the
// five advisories 1.26.6 fixes. It fails loudly, which is the safe
// direction.
//
// No `toolchain` line, for two measured reasons: with `go` already at
// 1.26.6 a redundant `toolchain go1.26.6` makes `go build` fail with
// "updates to go.mod needed", and `go mod tidy` deletes the line anyway
// the moment the go directive catches up to it.
go 1.26.6

require (
	github.com/getsentry/sentry-go v0.47.0
	github.com/go-chi/chi/v5 v5.3.0
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/pressly/goose/v3 v3.27.0
	golang.org/x/crypto v0.52.0
	golang.org/x/net v0.55.0
	golang.org/x/text v0.40.0
)

require (
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/sethvargo/go-retry v0.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)
