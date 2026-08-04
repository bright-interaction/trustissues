// Package secretexit is the ONE EXIT.
//
// # Why this package exists
//
// Six audit rounds asked "can a client you invite into a shared collection get
// one of your secrets delivered to a machine they control?", answered "not
// through THAT field", and were wrong six times:
//
//	round 1  the proxy PATH                  closed -> the attack moved to the HOST
//	round 2  the inference allowlist         closed -> moved to destination_patterns
//	round 3  destination_patterns            closed -> moved to provider_meta
//	round 4  provider / provider_meta        closed -> moved to rotation_targets.webhook_url
//	round 5  rotation_targets                closed -> the guard was regexes, bypassed by a table alias
//	round 6  a compile-error narrowed API    closed -> and then a VIEWER walked around all six
//
// The round-6 break did not write a host-choosing column of the victim's entry
// at all. An accepted vault_only VIEWER of a shared collection put a
// forgejo_secret target on their OWN personal entry, with auth_token naming the
// team's secret, and rotated their own entry. Every gate on the path said yes
// and every one of them was right: it was their entry, they were its creator,
// and a viewer may USE a shared secret. The team secret left as
// "Authorization: token sk_live_..." to a host the viewer chose.
//
// Enforcement placed on the INPUTS to a dangerous operation has to enumerate
// every input, and stays wrong until the enumeration is complete, which it never
// is. Enforcement placed at the OPERATION is complete by construction, because
// the operation is one point.
//
// # The construction
//
// A decrypted secret is a [Plaintext]. Its bytes are unexported and this package
// has exactly one exported accessor for them, [Exit]. No amount of care or
// review is required to keep the list of exits complete: the compiler keeps it,
// because a new exit cannot obtain the bytes without calling [Exit], and [Exit]
// takes a [Destination] and asks the [Authority] whether the OWNER of that
// secret authorised it.
//
// Nothing else can transmit a decrypted secret anywhere:
//
//   - it cannot be logged: [Plaintext] implements fmt.Formatter, fmt.Stringer
//     and json.Marshaler and all three redact, so %v, %+v, %#v, %s, %q, %x and
//     encoding/json every one of them print "[redacted secret]".
//   - it cannot be compared out byte by byte: the only comparison is
//     [Plaintext.EqualsString], which is constant-time and returns a bool.
//   - it cannot be reached through reflection-free field access: there is no
//     exported field and no getter.
//
// # The question at the exit
//
// Not "may this caller read the entry", and not "who wrote the row". Those are
// the two questions the six earlier rounds kept asking, and the round-6 attacker
// passed both. The question is:
//
//	Did the OWNER of the secret being sent authorise this destination?
//
// "Owner" is the entry's creator, or an instance admin, in both cases only while
// they still hold manage on that entry. That is exactly the WIDENING RIGHT the
// product already defines (see VaultHandler.mayDirectSecretEgress), and it is
// the only right that means "may choose where this secret goes".
//
// A viewer, an editor, an API-key-only caller, the scheduler and an admin are
// all answered by that same rule, because they all arrive at the same [Exit].
//
// # Default-deny is what makes it total
//
// [Exit] refuses unless the [Authority] says yes, and every [Destination]
// constructor demands a [Chooser]: an explicit statement of WHO picked this
// destination. There is no zero value that means "allowed" and no way to spell
// "I forgot to ask" that looks like "I asked and was allowed".
//
// So a host-choosing column added tomorrow authorises NOTHING until somebody
// deliberately feeds it into the owner's recorded destination set. The failure
// mode of forgetting is "the feature does not work", never "the secret leaks".
// That is the direction round 3 through round 6 were pointed the wrong way.
package secretexit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ── what a secret is, and whose it is ───────────────────────────────────────

// Origin says which vault entry a decrypted secret came from, and therefore
// whose authorisation the exit has to ask for.
//
// EntryID is the load-bearing field. The round-6 attack put ANOTHER entry's
// secret on the wire during a rotation of the attacker's own entry, so an exit
// that asked about "the entry being rotated" asked about the wrong row.
type Origin struct {
	// EntryID is the vault_entries.id the plaintext was decrypted from. Empty
	// means the secret belongs to no entry, which no owner can authorise, so
	// [Exit] refuses it to any host.
	EntryID string
	// Name is the entry name, for refusal messages only. Never an input to a
	// decision: names are not unique across users.
	Name string
	// Instance marks a value that is instance-owned operator configuration
	// rather than a vault entry (see [InstanceOrigin]).
	Instance bool
}

// InstanceOrigin is the origin for a value that belongs to the INSTANCE rather
// than to any vault entry: notification-channel configuration and the SMTP
// relay password, both of which are written only through admin-only routes.
//
// It is a distinct origin rather than a fake entry id so the refusal messages,
// and any future rule, can tell the two apart.
func InstanceOrigin(what string) Origin { return Origin{Name: what, Instance: true} }

// Describe renders the origin for a refusal message.
func (o Origin) Describe() string {
	switch {
	case o.Instance:
		return "instance configuration " + strconv.Quote(o.Name)
	case o.Name != "":
		return fmt.Sprintf("the secret in entry %q (%s)", o.Name, o.EntryID)
	case o.EntryID != "":
		return "the secret in entry " + o.EntryID
	default:
		return "a secret with no recorded entry"
	}
}

// ── who chose the destination ───────────────────────────────────────────────

type chooserKind uint8

const (
	// chooserNobody is the zero value. It authorises nothing, which is the
	// point: a Destination built with a struct literal instead of a constructor
	// is refused rather than trusted.
	chooserNobody chooserKind = iota
	chooserEntryRecord
	chooserUser
	chooserInstance
)

// Chooser names the principal who picked a destination. Every [Destination]
// carries one, and the [Authority] answers a different question for each.
//
// There is no constructor that means "unknown". If the code cannot say who
// chose a destination, it does not get to send a secret there.
type Chooser struct {
	kind   chooserKind
	userID string
	why    string
}

// ChosenByTheEntrysOwnRecord is for a destination read off the SECRET'S OWN
// entry row: its destination_patterns ceiling, its provider configuration, its
// own delivery targets.
//
// The [Authority] does not take that on trust. It re-derives the entry's
// currently recorded destinations and requires the host to be inside them, so a
// row written by an older binary, an import or a restored backup is refused at
// the moment of delivery rather than only at the write it never passed through.
func ChosenByTheEntrysOwnRecord() Chooser {
	return Chooser{kind: chooserEntryRecord, why: "recorded on the secret's own entry"}
}

// ChosenBy is for a destination a named principal recorded SOMEWHERE ELSE: most
// importantly a rotation target on a DIFFERENT entry whose auth_token spends
// this secret as its bearer token.
//
// This is the round-6 constructor. The [Authority] requires userID to hold the
// widening right on the entry the secret came from, which the attacker held on
// their own carrier entry and never on the victim's.
func ChosenBy(userID string) Chooser {
	return Chooser{kind: chooserUser, userID: userID, why: "chosen by user " + userID}
}

// ChosenByTheInstance is for a destination fixed by the deployment itself: an
// admin-only settings row joined to a compile-time host table (the AI gateway
// pin), or a notification channel an admin configured.
//
// An instance admin holds the widening right on every entry, so this is not a
// widening of the rule, it is the same rule with the answer already known.
func ChosenByTheInstance(why string) Chooser {
	return Chooser{kind: chooserInstance, why: why}
}

func (c Chooser) describe() string {
	if c.why == "" {
		return "nobody (this destination has no recorded chooser)"
	}
	return c.why
}

// ── where a secret is going ─────────────────────────────────────────────────

// HostSet is a set of network hosts. Exact hosts are the normal case; suffixes
// exist for the one vendor that hands back its own storage host at runtime
// (Backblaze) and are spelled out at each use.
type HostSet struct {
	Hosts    []string
	Suffixes []string
}

// Empty reports whether this set allows no host at all.
func (s HostSet) Empty() bool { return len(s.Hosts) == 0 && len(s.Suffixes) == 0 }

// Allows reports whether host is inside the set. Normalization is
// [NormalizeHost] on both sides so a spelling one gate accepts cannot be
// refused by another.
func (s HostSet) Allows(host string) bool {
	h := NormalizeHost(host)
	if h == "" {
		return false
	}
	for _, want := range s.Hosts {
		if h == NormalizeHost(want) {
			return true
		}
	}
	for _, suffix := range s.Suffixes {
		x := strings.ToLower(suffix)
		if strings.HasSuffix(h, x) && len(h) > len(x) {
			return true
		}
	}
	return false
}

// Describe renders the set for an error message.
func (s HostSet) Describe() string {
	parts := append([]string{}, s.Hosts...)
	for _, x := range s.Suffixes {
		parts = append(parts, "*"+x)
	}
	if len(parts) == 0 {
		return "nowhere (this operation is not allowed to make outbound requests)"
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// NormalizeHost lowercases a host and strips an explicit port. It is the one
// spelling rule the whole product uses, exported so the handlers cannot grow a
// second one that disagrees.
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(h, ":"); i >= 0 {
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i] // explicit port
		}
	}
	return h
}

type destKind uint8

const (
	destNowhere destKind = iota
	destNetwork
	destCaller
	destInProcess
)

// Destination is where a decrypted secret is about to go, plus who chose to
// send it there. The zero value goes nowhere.
type Destination struct {
	kind      destKind
	hosts     HostSet
	principal string
	chooser   Chooser
	// what names the operation for the refusal message ("provider datadog",
	// "this forgejo_secret delivery target").
	what string
}

// ToHosts builds a NETWORK destination: the secret is about to be put on the
// wire toward one of these hosts.
func ToHosts(what string, chooser Chooser, hosts HostSet) Destination {
	return Destination{kind: destNetwork, hosts: hosts, chooser: chooser, what: what}
}

// ToHost is ToHosts for the common single-host case.
func ToHost(what string, chooser Chooser, host string) Destination {
	h := NormalizeHost(host)
	var set HostSet
	if h != "" {
		set.Hosts = []string{h}
	}
	return ToHosts(what, chooser, set)
}

// ToNowhere builds an IN-PROCESS destination: the value is computed with and
// never transmitted.
//
// It exists for the local generators (shared-secret, generated-key-32) and for
// any adapter that declares no hosts at all. Those still need the bytes, and
// pretending they are going somewhere would put a host in a receipt that nothing
// ever checked.
//
// Exit mints NO RECEIPT for it, which is the strong part: an outbound request
// built after one of these has no receipt at all, so [CheckHost] refuses it. A
// local generator that grows an HTTP call fails closed on the day it is written
// rather than inheriting whatever the last exit authorised.
func ToNowhere(what string) Destination {
	return Destination{kind: destInProcess, what: what,
		chooser: Chooser{kind: chooserInstance, why: "used in-process; nothing is transmitted"}}
}

// IsInProcess reports whether this value is used locally and never transmitted.
func (d Destination) IsInProcess() bool { return d.kind == destInProcess }

// ToCaller builds a PRINCIPAL destination: the secret is about to be handed
// back to a human or a machine identity in a response body.
//
// The chooser is the principal themselves, because a caller asking for a value
// is not choosing a network destination and the widening right is not the
// question. The [Authority] asks the read question instead.
func ToCaller(what string, userID string) Destination {
	return Destination{kind: destCaller, principal: userID, what: what,
		chooser: Chooser{kind: chooserUser, userID: userID, why: "returned to " + userID}}
}

// Kind helpers, for an [Authority] implementation.

// IsNetwork reports whether this destination puts the secret on the wire.
func (d Destination) IsNetwork() bool { return d.kind == destNetwork }

// IsCaller reports whether this destination returns the secret to a principal.
func (d Destination) IsCaller() bool { return d.kind == destCaller }

// Hosts is the network host set. Empty for a caller destination.
func (d Destination) Hosts() HostSet { return d.hosts }

// Principal is the user id a caller destination returns the secret to.
func (d Destination) Principal() string { return d.principal }

// ChosenByEntryRecord reports whether the destination was read off the secret's
// own entry row.
func (d Destination) ChosenByEntryRecord() bool { return d.chooser.kind == chooserEntryRecord }

// ChosenByInstance reports whether the deployment itself fixed this destination.
func (d Destination) ChosenByInstance() bool { return d.chooser.kind == chooserInstance }

// ChoosingUser is the principal who recorded this destination, empty unless the
// chooser is a user.
func (d Destination) ChoosingUser() string {
	if d.chooser.kind == chooserUser {
		return d.chooser.userID
	}
	return ""
}

// What names the operation, for refusal messages.
func (d Destination) What() string { return d.what }

// Describe renders the destination for an error message.
func (d Destination) Describe() string {
	switch d.kind {
	case destNetwork:
		return fmt.Sprintf("%s -> %s (%s)", d.what, d.hosts.Describe(), d.chooser.describe())
	case destCaller:
		return fmt.Sprintf("%s -> caller %s", d.what, d.principal)
	case destInProcess:
		return d.what + " -> nowhere (used in-process)"
	default:
		return "nowhere"
	}
}

// ── the rule ────────────────────────────────────────────────────────────────

// Authority is the OWNER rule, and there is exactly one implementation of it in
// this product (VaultHandler).
//
// It is an interface rather than a concrete type for one reason only: this
// package must not import the handlers. It is NOT an extension point. A second
// implementation is a second rule, which is how the write gate and the delivery
// gate came to disagree about instance admins in round 5.
type Authority interface {
	// AuthorizeSecretExit returns nil when the owner of o authorises d, and an
	// error explaining the refusal otherwise.
	AuthorizeSecretExit(ctx context.Context, o Origin, d Destination) error
}

// ── the secret itself ───────────────────────────────────────────────────────

// Plaintext is a decrypted secret value.
//
// The bytes are unexported and there is no getter. [Exit] is the only exported
// function in this package that returns them, which is what makes the list of
// exits something the compiler maintains rather than something a reviewer
// remembers.
type Plaintext struct {
	b []byte
	o Origin
	a Authority
}

// Open decrypts an AES-256-GCM vault value and wraps it.
//
// The decryption lives HERE, not in the handlers, so that the only code in the
// product holding a decrypted vault value in a plain []byte is code inside this
// package. A caller cannot obtain the plaintext by doing the crypto itself
// without also reimplementing the key handling, which is a change no review
// misses.
//
// A nil authority is accepted and produces a Plaintext that exits NOWHERE, so a
// handler assembled by hand (a test fixture, a future refactor) fails closed and
// loudly instead of silently disabling the rule.
func Open(key [32]byte, ciphertext, nonce []byte, o Origin, a Authority) (Plaintext, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return Plaintext{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Plaintext{}, err
	}
	// gcm.Open PANICS on a wrong-length nonce rather than returning an error,
	// which would otherwise surface as a bare HTTP 500 via chi's Recoverer. A
	// malformed stored nonce must degrade to a handled decrypt error.
	if len(nonce) != gcm.NonceSize() {
		return Plaintext{}, fmt.Errorf("decrypt: invalid nonce length %d (want %d)", len(nonce), gcm.NonceSize())
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Plaintext{}, err
	}
	return Plaintext{b: pt, o: o, a: a}, nil
}

// Seal encrypts a plaintext with AES-256-GCM using rand for the nonce. It is
// here rather than in the handlers so encrypt and decrypt stay one pair.
func Seal(key [32]byte, plaintext []byte, rand io.Reader) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

// Reseal re-encrypts a Plaintext for storage WITHOUT releasing its bytes.
//
// Storing a value back under the same key is not an exit: nothing leaves the
// process and the value is ciphertext again on the other side. Without this, a
// rotation would have to call [Exit] merely to save the value it just minted,
// which would make the exit list read as though every rotation transmits
// somewhere. It does not, and the list has to stay honest to be useful.
func Reseal(key [32]byte, p Plaintext, rand io.Reader) (ciphertext, nonce []byte, err error) {
	return Seal(key, p.b, rand)
}

// Minted wraps a secret value that was CREATED rather than decrypted: the fresh
// value a rotation generates locally, or the successor key a provider hands
// back.
//
// It is exactly as dangerous as a decrypted one (it is the secret the consumer
// is about to start using), so it is the same type and goes through the same
// exit. Callers pass the origin of the entry the value is being stored into.
func Minted(value []byte, o Origin, a Authority) Plaintext {
	return Plaintext{b: append([]byte(nil), value...), o: o, a: a}
}

// Origin returns whose secret this is. Metadata only: it yields nothing that
// could reconstruct the value.
func (p Plaintext) Origin() Origin { return p.o }

// IsZero reports whether this is the zero Plaintext, which holds no value and
// no authority and therefore exits nowhere.
func (p Plaintext) IsZero() bool { return p.b == nil && p.a == nil }

// Len is the length of the value in bytes.
func (p Plaintext) Len() int { return len(p.b) }

// Empty reports whether the value is zero-length.
func (p Plaintext) Empty() bool { return len(p.b) == 0 }

// EqualsString compares the value against a candidate in constant time.
//
// This is the ONLY in-process use of a secret that does not go through [Exit],
// and it is safe because it emits one bit that the caller already knew how to
// obtain: they supplied the candidate. VaultHandler.Update needs it to tell
// "the user re-saved the same value" (not a rotation) from a real change.
func (p Plaintext) EqualsString(candidate string) bool {
	return subtle.ConstantTimeCompare(p.b, []byte(candidate)) == 1
}

// Wipe zeroes the backing array. Best effort: any []byte already handed out by
// [Exit] is the caller's to wipe.
func (p Plaintext) Wipe() {
	for i := range p.b {
		p.b[i] = 0
	}
}

// ── the redactions that close the log and error paths ───────────────────────

const redaction = "[redacted secret]"

// Format makes every fmt verb print the redaction, including %x, %d and %#v.
//
// Stringer alone is not enough: fmt consults it only for %v, %s, %q, %x and %X,
// so a %d or a %#v on a struct holding a Plaintext would have printed the bytes.
// Formatter is consulted first for every verb, which is why it is here.
func (p Plaintext) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, redaction) }

// String makes a Plaintext safe to interpolate anywhere.
func (p Plaintext) String() string { return redaction }

// GoString covers %#v.
func (p Plaintext) GoString() string { return "secretexit.Plaintext{" + redaction + "}" }

// MarshalJSON makes a Plaintext safe to embed in a response struct: encoding/json
// emits the redaction instead of reaching the bytes.
func (p Plaintext) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(redaction)), nil }

// ── THE ONE EXIT ────────────────────────────────────────────────────────────

// ErrNoAuthority is returned when a Plaintext carries no Authority, which means
// nobody can be asked and therefore nothing is allowed.
var ErrNoAuthority = errors.New("secretexit: this secret carries no authority, so no destination can be authorised")

// Exit is THE ONE EXIT. Every path by which a decrypted secret value leaves this
// process goes through here, because it is the only exported way to obtain the
// bytes.
//
// It returns a derived context carrying a RECEIPT for what it just authorised.
// [CheckHost] refuses any outbound request whose host is not covered by every
// receipt in its context, which closes the residual an argument-shaped gate
// always leaves: claiming one destination and then sending to another. Claim a
// host the owner did not authorise and Exit refuses; claim one they did and send
// somewhere else and [CheckHost] refuses.
//
// Callers MUST use the returned context for the request that carries the value.
// Forgetting is not a silent bypass: a request built on the original context has
// no receipt and [CheckHost] fails closed.
func Exit(ctx context.Context, p Plaintext, d Destination) (context.Context, []byte, error) {
	if p.a == nil {
		return ctx, nil, fmt.Errorf("%w: %s was not sent to %s", ErrNoAuthority, p.o.Describe(), d.Describe())
	}
	if d.kind == destNowhere {
		return ctx, nil, fmt.Errorf("secretexit: refusing to release %s: no destination was stated. "+
			"Build one with ToHosts, ToHost or ToCaller; the zero Destination authorises nothing",
			p.o.Describe())
	}
	if d.chooser.kind == chooserNobody {
		return ctx, nil, fmt.Errorf("secretexit: refusing to release %s to %s: the destination has no "+
			"recorded chooser, so there is nobody whose authority could be checked",
			p.o.Describe(), d.what)
	}
	if d.kind == destNetwork && d.hosts.Empty() {
		return ctx, nil, fmt.Errorf("secretexit: refusing to release %s: %s resolves to no host at all",
			p.o.Describe(), d.what)
	}
	if err := p.a.AuthorizeSecretExit(ctx, p.o, d); err != nil {
		return ctx, nil, fmt.Errorf("egress refused: %w", err)
	}
	out := ctx
	if d.kind == destNetwork {
		out = withReceipt(ctx, receipt{origin: p.o, dest: d})
	}
	return out, p.b, nil
}

// ExitString is Exit for the call sites that need a Go string. It is a thin
// wrapper and NOT a second exit: it calls Exit.
//
// It exists because a []byte converted to a string cannot be wiped, so the
// conversion is worth naming at the call site rather than hiding.
func ExitString(ctx context.Context, p Plaintext, d Destination) (context.Context, string, error) {
	out, b, err := Exit(ctx, p, d)
	if err != nil {
		return out, "", err
	}
	return out, string(b), nil
}

// ── receipts, and the second half of the gate ───────────────────────────────

type receipt struct {
	origin Origin
	dest   Destination
}

type receiptKeyType struct{}

var receiptKey = receiptKeyType{}

func withReceipt(ctx context.Context, r receipt) context.Context {
	existing, _ := ctx.Value(receiptKey).([]receipt)
	next := make([]receipt, len(existing), len(existing)+1)
	copy(next, existing)
	return context.WithValue(ctx, receiptKey, append(next, r))
}

// CheckHost is what every outbound-request chokepoint calls before it forwards.
//
// It refuses when the context carries NO receipt (fail closed: a request built
// without going through [Exit] has no business carrying a secret, and a request
// that carries no secret has no business on a client reserved for ones that do),
// and when any receipt in the context does not allow the host.
//
// "Any" rather than "some" is deliberate. A forgejo delivery carries TWO
// secrets: the entry's freshly rotated value in the body and another entry's
// personal access token in the Authorization header. Both owners have to have
// authorised the same host, and the round-6 attack is precisely the case where
// one of them had and the other had not.
func CheckHost(ctx context.Context, host string) error {
	rs, _ := ctx.Value(receiptKey).([]receipt)
	if len(rs) == 0 {
		return fmt.Errorf("egress refused: an outbound request to %q was built with no secret-exit "+
			"receipt in its context. Whoever decrypted the secret must call secretexit.Exit and use the "+
			"context it returns; see internal/secretexit", NormalizeHost(host))
	}
	for _, r := range rs {
		if !r.dest.hosts.Allows(host) {
			return fmt.Errorf("egress refused: %s may only reach %s, and %q is not that. %s",
				r.dest.what, r.dest.hosts.Describe(), NormalizeHost(host), r.origin.Describe())
		}
	}
	return nil
}

// ReceiptCount reports how many secrets the context has authorised for release.
// Observation only, for guards that must tell "reached a declared host" apart
// from "reached nothing at all".
func ReceiptCount(ctx context.Context) int {
	rs, _ := ctx.Value(receiptKey).([]receipt)
	return len(rs)
}
