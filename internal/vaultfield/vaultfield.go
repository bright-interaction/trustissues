// Package vaultfield is THE ONE PLACE a vault-key-encrypted value becomes
// plaintext, and therefore the one place that can know the whole list.
//
// # Why this package exists
//
// Round 18 shipped theEncryptedFieldLedger: a map classifying every
// at-rest-encrypted thing in the product, checked by a test that DERIVED the
// real set from the module's AST and failed in both directions. That was a real
// improvement on the prose paragraph it replaced, and it was still the same
// mistake one level up.
//
// It derived the set by matching FOUR CALL SHAPES: decryptColumnOrLog,
// OpenEntrySecret, DecryptInstanceConfig, columncrypto.DecryptString. A fifth
// door already existed. VaultHandler.decryptColumn was the raw primitive and
// decryptColumnOrLog was merely its logging wrapper, so
// UserHandler.openInviteCode opened the vault-key-encrypted invitations.code
// column through the raw door, matched none of the four shapes, and never
// entered the derived set. The ledger reported coverage it did not have over a
// column the codebase itself describes as a path to every vault secret.
//
// Recognising decryption by the SHAPE OF THE CALL is the same error as
// recognising builds by argv or writes by a source regex. Enumerating doors will
// always miss one, because a door is whatever somebody writes tomorrow.
//
// # The construction
//
// The knowledge comes from the one place plaintext is PRODUCED, not from the
// places that call it.
//
//   - Every AES-GCM open in the vault-key family happens in this file. Nothing
//     else in the module imports crypto/aes or crypto/cipher, which
//     TestAESGCMIsOpenedInExactlyOneFile checks module-wide.
//
//     That guard is a NET and this comment used to sell it as a proof. It said
//     opening AES-GCM data REQUIRES those two packages, so the importer set was
//     "closed by the language". It is not: AES-GCM is arithmetic, a pure-Go
//     implementation imports nothing from crypto/*, and a vendored AEAD imports
//     none of it either. What a reader of THIS PRODUCT's ciphertext genuinely
//     cannot do without is the KEY, and that is pinned separately by
//     TestVaultKeyMaterialIsHeldOnlyByDeclaredFiles, which declares every file
//     able to name, receive or derive vault key material. The import pin still
//     earns its place: it is what a real new door reddens.
//
//   - Every open here takes a [Field]. A Field's contents are unexported and
//     [Declare] is its only constructor, so obtaining one means declaring the
//     column, its class and the reason. The zero Field opens nothing.
//
//   - [Declare] records into the package ledger. The ledger is therefore a
//     BY-PRODUCT of being able to decrypt at all, not a list somebody maintains
//     alongside the code.
//
// So a NEW decryption path has exactly three outcomes, and silent omission is
// not among them: it fails to compile (no Field to pass), or it does its own
// crypto and reddens the import guard, or it calls [Declare] and the ledger
// gains the entry automatically.
//
// # What this does NOT claim
//
// A door can borrow an EXISTING Field belonging to another column. The ledger
// then knows a decryption happens and knows a classification, but under the
// wrong column name. Closing that takes binding the field name into the
// ciphertext as AES-GCM additional authenticated data, which is a storage-format
// change; see the residual note in encrypted_field_ledger.go for why it was not
// done in this round.
package vaultfield

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// cryptoRand is the nonce source for [SealColumn]. Named so a test can see it is
// the real CSPRNG; the separate-nonce sealers take their reader as an argument
// because their callers already had one.
var cryptoRand io.Reader = rand.Reader

// ── the classification ──────────────────────────────────────────────────────

// Class is what an at-rest-encrypted value is allowed to do once it is
// plaintext. Every [Declare] must pick one; there is no default that means
// "unreviewed", because [Unclassified] is refused at declaration time.
type Class uint8

const (
	// Unclassified is the zero value and is refused by [Declare]. A Class
	// somebody forgot to set must not read as a decision.
	Unclassified Class = iota
	// ThroughTheExit: this plaintext can leave the process as a VALUE, so it
	// goes through secretexit.Exit and names an entry in theExitList.
	ThroughTheExit
	// InProcessOnly: decrypted and consumed here, never emitted. The reason has
	// to say what consumes it and why nothing is transmitted.
	InProcessOnly
	// NotACredential: encrypted at rest so a stolen database file is not a
	// readable one, but the plaintext is metadata rather than a credential. It
	// is returned to callers who already hold read on the row.
	NotACredential
	// InstanceOwned: belongs to the INSTANCE rather than to any vault entry,
	// written and read only through admin-only routes, so there is no entry
	// owner to ask. The route gate is the load-bearing part of this class and
	// has to be pinned by a test, or the classification is a claim.
	InstanceOwned
)

// String names the class for guard failure messages.
func (c Class) String() string {
	switch c {
	case ThroughTheExit:
		return "through-the-exit"
	case InProcessOnly:
		return "in-process-only"
	case NotACredential:
		return "not-a-credential"
	case InstanceOwned:
		return "instance-owned"
	default:
		return "UNCLASSIFIED"
	}
}

// ── the handle ──────────────────────────────────────────────────────────────

// decl is one declared field. It is never copied out of this package by value:
// callers hold a [Field], which is a pointer to one of these plus nothing else.
type decl struct {
	name       string
	class      Class
	exitKey    string
	why        string
	declaredAt string
}

// Field is the handle every decryption in this package demands.
//
// It holds an unexported pointer and has no exported fields, so the only Field a
// caller outside this package can build with a composite literal is the ZERO
// one, which decrypts nothing. Every usable Field comes from [Declare], and
// [Declare] is what writes the ledger.
type Field struct{ d *decl }

// IsZero reports whether this is the zero Field: no column, no classification,
// no reason, and no ability to open anything.
func (f Field) IsZero() bool { return f.d == nil }

// Name is the column this field opens, as "table.column".
func (f Field) Name() string {
	if f.d == nil {
		return ""
	}
	return f.d.name
}

// Class is the ruling recorded for this field.
func (f Field) Class() Class {
	if f.d == nil {
		return Unclassified
	}
	return f.d.class
}

// ExitKey is the theExitList key that governs this field, empty unless the class
// is [ThroughTheExit].
func (f Field) ExitKey() string {
	if f.d == nil {
		return ""
	}
	return f.d.exitKey
}

// Why is the recorded reason for the classification.
func (f Field) Why() string {
	if f.d == nil {
		return ""
	}
	return f.d.why
}

// ── the ledger ──────────────────────────────────────────────────────────────

var (
	ledgerMu sync.RWMutex
	ledger   = map[string]*decl{}
)

// minReasonLength is how much of a reason counts as one. A rubber stamp is
// worse than nothing here, because it reads as review.
const minReasonLength = 60

// Declare registers a vault-key-encrypted column and returns the handle needed
// to decrypt it. It is the ONLY constructor of a usable [Field].
//
// It panics rather than returning an error, deliberately and at init time:
//
//   - a duplicate name means two declarations disagree about one column, and
//     whichever one a reader finds first would be believed;
//   - an [Unclassified] class, an empty reason or a too-short one is a
//     declaration that satisfies the compiler and tells an operator nothing;
//   - a [ThroughTheExit] field with no exitKey claims a gate it does not name,
//     and a non-exit field WITH one claims the opposite.
//
// None of those can be a runtime condition: the arguments are constants at every
// call site, so a panic here is a crash on the first line of any test binary,
// which is the loudest and earliest place to be told.
func Declare(name string, class Class, exitKey, why string) Field {
	name = strings.TrimSpace(name)
	if name == "" {
		panic("vaultfield.Declare: a field with no name cannot be classified")
	}
	if class == Unclassified {
		panic("vaultfield.Declare: " + name + " must be classified. An unset class is not a decision, " +
			"and the whole point of this package is that decrypting something implies a ruling about it")
	}
	if len(strings.TrimSpace(why)) < minReasonLength {
		panic("vaultfield.Declare: " + name + " is declared without a reason worth reading (" +
			strconv.Itoa(len(strings.TrimSpace(why))) + " chars, want at least " +
			strconv.Itoa(minReasonLength) + "). Say what the plaintext IS and why this class is right")
	}
	if class == ThroughTheExit && strings.TrimSpace(exitKey) == "" {
		panic("vaultfield.Declare: " + name + " is classified through-the-exit and names no exit. " +
			"Name the theExitList key that governs it, or the classification is a claim with nothing behind it")
	}
	if class != ThroughTheExit && strings.TrimSpace(exitKey) != "" {
		panic("vaultfield.Declare: " + name + " names an exit (" + exitKey + ") but is not classified " +
			"through-the-exit. One of the two is wrong")
	}

	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	if prior, dup := ledger[name]; dup {
		panic("vaultfield.Declare: " + name + " is already declared at " + prior.declaredAt +
			". Two declarations of one column will disagree, and a reader believes whichever they find first")
	}
	d := &decl{name: name, class: class, exitKey: exitKey, why: why, declaredAt: callerSite()}
	ledger[name] = d
	return Field{d: d}
}

// callerSite records where a Declare happened, so a guard failure can name the
// line rather than only the column. Two frames up: callerSite -> Declare -> the
// declaration.
func callerSite() string {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}
	if i := strings.LastIndex(file, "/trustissues/"); i >= 0 {
		file = file[i+len("/trustissues/"):]
	}
	return file + ":" + strconv.Itoa(line)
}

// Entry is one ledger row, copied out so no caller can mutate a declaration.
type Entry struct {
	Name       string
	Class      Class
	ExitKey    string
	Why        string
	DeclaredAt string
}

// Ledger is every vault-key-encrypted field this binary can decrypt, sorted by
// name.
//
// It is complete by construction rather than by review: an entry exists because
// somebody obtained a [Field], and a [Field] is what every open in this package
// demands.
func Ledger() []Entry {
	ledgerMu.RLock()
	defer ledgerMu.RUnlock()
	out := make([]Entry, 0, len(ledger))
	for _, d := range ledger {
		out = append(out, Entry{
			Name: d.name, Class: d.class, ExitKey: d.exitKey, Why: d.why, DeclaredAt: d.declaredAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns the entry for a column name.
func Lookup(name string) (Entry, bool) {
	ledgerMu.RLock()
	defer ledgerMu.RUnlock()
	d, ok := ledger[name]
	if !ok {
		return Entry{}, false
	}
	return Entry{Name: d.name, Class: d.class, ExitKey: d.exitKey, Why: d.why, DeclaredAt: d.declaredAt}, true
}

// ── the raw crypto, which is why the Field is not optional ──────────────────

// ErrUndeclared is returned by every open in this package when the caller passes
// the zero [Field].
//
// It fails CLOSED and it fails LOUDLY. `vaultfield.Field{}` is a composite
// literal any package can write, so the type alone does not stop a door being
// written without a declaration; this does, at the first call, with a message
// that says what to do.
var ErrUndeclared = fmt.Errorf("vaultfield: refusing to decrypt for the zero Field. " +
	"Every vault-key-encrypted column is declared with vaultfield.Declare, which is what puts it in " +
	"the ledger; a decryption that names no field is one nothing knows about")

// ColumnPrefix marks a metadata column as encrypted-at-rest.
//
// SECURITY: it is a storage-format marker ONLY. It must never decide whether to
// encrypt a value that came from a client. [SealColumn] therefore always
// encrypts, including input that already carries the prefix: a passthrough here
// turns the server into a universal decryption oracle, which is a defect this
// product has already had once.
const ColumnPrefix = "enc:v1:"

// IsSealedColumn reports whether a stored value carries the marker. Pure prefix
// check, no key needed.
func IsSealedColumn(s string) bool { return strings.HasPrefix(s, ColumnPrefix) }

// SealColumn encrypts a cleartext column into prefix + base64(nonce||ciphertext).
//
// It ALWAYS encrypts a non-empty input. See the note on [ColumnPrefix]: making
// this content-dependent is the decryption-oracle defect.
func SealColumn(key [32]byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	gcm, err := gcmFor(key)
	if err != nil {
		return "", err
	}
	nonce, err := newNonce(gcm)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	packed := make([]byte, 0, len(nonce)+len(sealed))
	packed = append(packed, nonce...)
	packed = append(packed, sealed...)
	return ColumnPrefix + base64.StdEncoding.EncodeToString(packed), nil
}

// OpenColumn reverses [SealColumn] for the declared field f.
//
// An UNPREFIXED value (pre-migration cleartext, empty, a row written by an older
// binary) is returned unchanged, which is what makes it safe to apply at every
// read choke. The Field is still required for that case: whether a particular
// row happens to be sealed yet is not the question the ledger asks.
func OpenColumn(key [32]byte, stored string, f Field) (string, error) {
	if f.IsZero() {
		return "", ErrUndeclared
	}
	if !IsSealedColumn(stored) {
		return stored, nil
	}
	packed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, ColumnPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted column %s: %w", f.Name(), err)
	}
	plain, err := openPacked(key, packed)
	if err != nil {
		return "", fmt.Errorf("decrypt column %s: %w", f.Name(), err)
	}
	return string(plain), nil
}

// ColumnOpens reports whether a stored column opens under this key, WITHOUT
// releasing the plaintext.
//
// It is the boot key-check probe. It returns one bit that the caller needs to
// decide whether to refuse to start, and it discards everything else, which is
// why the probe is a separate function rather than a call to [OpenColumn] whose
// result is thrown away: a function that cannot return plaintext cannot leak it
// later when somebody edits the caller.
func ColumnOpens(key [32]byte, stored string, f Field) bool {
	if f.IsZero() || !IsSealedColumn(stored) {
		return false
	}
	packed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, ColumnPrefix))
	if err != nil {
		return false
	}
	plain, err := openPacked(key, packed)
	zero(plain)
	return err == nil
}

// Seal encrypts with AES-256-GCM, returning the ciphertext and nonce separately.
// This is the shape vault_entries uses (the nonce lives in its own column).
func Seal(key [32]byte, plaintext []byte, rand io.Reader) (ciphertext, nonce []byte, err error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

// Open decrypts a separate-nonce value for the declared field f.
func Open(key [32]byte, ciphertext, nonce []byte, f Field) ([]byte, error) {
	if f.IsZero() {
		return nil, ErrUndeclared
	}
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	// gcm.Open PANICS on a wrong-length nonce rather than returning an error,
	// which would otherwise surface as a bare HTTP 500 through chi's Recoverer.
	// A malformed stored nonce must degrade to a handled decrypt error.
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("decrypt %s: invalid nonce length %d (want %d)",
			f.Name(), len(nonce), gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Opens is [Open] reduced to the one bit the boot key check needs, with the
// plaintext wiped rather than returned. Same reason as [ColumnOpens].
func Opens(key [32]byte, ciphertext, nonce []byte, f Field) bool {
	plain, err := Open(key, ciphertext, nonce, f)
	zero(plain)
	return err == nil
}

// SealPacked encrypts into a single nonce||ciphertext blob, base64 of which is
// what the PBKDF2-keyed column family (internal/columncrypto) stores.
func SealPacked(key [32]byte, plaintext []byte, rand io.Reader) ([]byte, error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// OpenPacked decrypts a nonce||ciphertext blob for the declared field f.
func OpenPacked(key [32]byte, packed []byte, f Field) ([]byte, error) {
	if f.IsZero() {
		return nil, ErrUndeclared
	}
	return openPacked(key, packed)
}

// openPacked is the unexported half: the Field check lives in the exported
// entry points so this one cannot be reached without passing it.
func openPacked(key [32]byte, packed []byte) ([]byte, error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(packed) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, packed[:ns], packed[ns:], nil)
}

func gcmFor(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newNonce(gcm cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(cryptoRand, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
