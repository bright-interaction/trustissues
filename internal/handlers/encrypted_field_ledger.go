package handlers

// THE SCOPE BOUNDARY, DERIVED INSTEAD OF REMEMBERED.
//
// internal/secretexit makes the set of EXITS something the compiler maintains:
// a decrypted vault value is an opaque type and Exit is the only accessor, so a
// new exit that does not call it does not compile. That property is about one
// column, vault_entries.encrypted_value.
//
// The round that built it also wrote a prose SCOPE BOUNDARY naming the two
// encrypted things deliberately outside the exit (alert_channels.config and the
// smtp_password setting) and saying they were named "so the boundary is a
// decision rather than an oversight". It missed custom_fields, which is
// AES-encrypted at rest exactly like the value, can hold operator-designated
// secret material (secret:true, which the UI masks for that reason), and left in
// a response body with no destination, no chooser and no receipt. A list of what
// is out of scope is exactly the kind of claim that rots, and a rotted one reads
// as coverage.
//
// So the list is not prose any more. It is this map, and
// TestEveryEncryptedFieldIsClassified derives the REAL set from the AST of the
// whole module (every decryptColumnOrLog field literal, every columncrypto
// decrypt site, every OpenEntrySecret, every DecryptInstanceConfig) and fails in
// BOTH directions: an encrypted field nobody classified fails on the day it is
// added, and a classification describing something that no longer exists fails
// too.
//
// That is the same shape as theExitList, for the same reason: the two facts an
// operator needs (what is encrypted, and whether it can leave) are not visible
// from any single call site.

// encryptedFieldClass is what an at-rest-encrypted value is allowed to do.
type encryptedFieldClass int

const (
	// classThroughTheExit: this plaintext can leave the process as a VALUE, so
	// it goes through secretexit.Exit and has an entry in theExitList.
	classThroughTheExit encryptedFieldClass = iota
	// classInProcessOnly: decrypted and consumed here, never emitted. The
	// justification has to say what consumes it and why nothing is transmitted.
	classInProcessOnly
	// classNotACredential: encrypted at rest so a stolen database file is not a
	// readable one, but the plaintext is metadata rather than a credential. It is
	// returned to callers who already hold read on the entry.
	classNotACredential
	// classInstanceOwned: belongs to the INSTANCE rather than to any vault entry,
	// written only through AdminOnly routes, so there is no entry owner to ask.
	classInstanceOwned
)

// encryptedFieldRuling is one classification, with the reason it is that one.
type encryptedFieldRuling struct {
	class encryptedFieldClass
	// exitKey is the theExitList key that governs this field. Required for
	// classThroughTheExit and empty otherwise, and cross-checked, so "it goes
	// through the exit" cannot be asserted about a field no exit mentions.
	exitKey string
	why     string
}

// theEncryptedFieldLedger is every at-rest-encrypted thing in this module.
//
// Keys are derived, not invented:
//
//	vault_entries.<column>          from the field literal decryptColumnOrLog is
//	                                called with, or from the one door that opens
//	                                encrypted_value.
//	columncrypto:<file>:<func>      from the call site, because these decrypts
//	                                take a key and a blob and never name a column.
//	alert_channels.config           the one DecryptInstanceConfig door.
var theEncryptedFieldLedger = map[string]encryptedFieldRuling{
	// ── through the exit ────────────────────────────────────────────────
	"vault_entries.encrypted_value": {
		class: classThroughTheExit, exitKey: "any",
		why: "THE client credential this product exists to hold. VaultHandler.OpenEntrySecret is the " +
			"only door and what it returns is opaque, so every path it leaves by is one of the ten " +
			"registered exits.",
	},
	"vault_entries.custom_fields": {
		class: classThroughTheExit, exitKey: "vault.go:VaultHandler.customFieldsForCaller",
		why: "a field with secret:true is a SECOND credential on the same entry: an API key an " +
			"operator pasted into a labelled field, a recovery PIN, a database password. The whole " +
			"blob is encrypted at rest for that reason and the UI masks those values. It used to be " +
			"decrypted straight into the response body next to the entry's own value, which is a " +
			"second exit with no destination, no chooser and no receipt.",
	},

	// ── metadata, not a credential ──────────────────────────────────────
	//
	// Each of these is returned to a caller who already holds read on the entry,
	// which is how they obtained the row at all. They are encrypted at rest so a
	// stolen database FILE is not a readable one, not because releasing them is a
	// decision anybody has to make.
	"vault_entries.url": {class: classNotACredential,
		why: "the site this login belongs to, for browser-extension autofill matching. Not a secret: " +
			"the blind index over it is what autofill actually queries."},
	"vault_entries.alias_url": {class: classNotACredential,
		why: "a second autofill match for the same entry. Same shape as url."},
	"vault_entries.username": {class: classNotACredential,
		why: "the account name the credential belongs to. Half of a login pair and deliberately the " +
			"half that is not the secret; the value is the other half and it goes through the exit."},
	"vault_entries.category": {class: classNotACredential,
		why: "a display label from a fixed vocabulary (login, api_key, ssh_key, ...). It cannot hold " +
			"a value a user typed."},
	"vault_entries.notes": {class: classNotACredential,
		why: "free text the operator wrote ABOUT the credential. It is not designated secret material " +
			"the way a secret:true custom field is, and the product renders it unmasked, so treating " +
			"it as a credential would be a claim the UI already contradicts. An operator who pastes a " +
			"key into notes should use a custom field, and the field limits and the UI both say so."},

	// ── operator configuration returned to callers who may already write it ──
	"vault_entries.provider_meta": {class: classNotACredential,
		why: "the provider binding (site, tenant, project_ref, the key id a rotation minted). " +
			"Encrypted at rest because account and key identifiers are worth not leaking from a stolen " +
			"file. It is returned in every entry response, and it is also a HOST-CHOOSING column, so " +
			"who may WRITE it is the question that matters and vaultegress answers it."},
	"vault_entries.rotation_targets": {class: classNotACredential,
		why: "delivery configuration, including each webhook's HMAC SIGNING secret. That signing " +
			"secret is the one value here worth arguing about, and the argument was settled the other " +
			"way: it is not a client credential, it belongs to the delivery configuration rather than " +
			"to the vault, and GET /api/vault/{id}/targets is deliberately gated on MANAGE rather " +
			"than read for exactly this reason (see GetTargets). What the exit governs is the ROTATED " +
			"VALUE this configuration delivers, and that goes through deliverToWebhook."},

	// ── in-process only ─────────────────────────────────────────────────
	"columncrypto:auth.go:decryptTOTPSecret": {class: classInProcessOnly,
		why: "the TOTP seed. It is a credential, and it never leaves: the only consumer is " +
			"totp.ValidateCode, which takes the seed and a six-digit code and returns a bool. The " +
			"seed is shown to a user exactly once, at ENROLMENT, from the value the server just " +
			"generated rather than from a decrypt of the column."},
	"columncrypto:auth.go:MigrateTOTPSecrets": {class: classInProcessOnly,
		why: "the boot backfill that seals plaintext TOTP seeds. It decrypts only to tell an " +
			"already-sealed row from a legacy plaintext one, and re-seals; nothing is emitted."},
	"columncrypto:vault_keycheck.go:VerifyVaultKey": {class: classInProcessOnly,
		why: "the boot key sentinel. It decrypts a known constant and compares it to that constant, " +
			"so the only thing that leaves is the boolean 'this key opens this database'."},
	"columncrypto:vault_keycheck.go:vaultKeyOpensExistingData": {class: classInProcessOnly,
		why: "the same boot gate's probes across every encrypted family. It discards every plaintext " +
			"it obtains and returns two booleans."},

	// ── instance-owned ──────────────────────────────────────────────────
	"columncrypto:smtp_password.go:resolveSMTPPassword": {class: classInstanceOwned,
		why: "the SMTP relay password, an AdminOnly settings row. It belongs to the instance, not to " +
			"any vault entry, so there is no entry owner to ask, and what it authenticates is the " +
			"instance's own outbound mail."},
	"alert_channels.config": {class: classInstanceOwned,
		why: "notification-channel configuration (a Slack webhook URL, relay credentials), written " +
			"only through the AdminOnly notification-channel routes. It carries no entry's value: " +
			"Dispatch sends the entry NAME and a redacted detail string. " +
			"TestOnlyTheAlertsPathDecryptsInstanceConfig pins its caller set so this door cannot " +
			"quietly become a second way to open an entry secret."},
}
