package handlers

import (
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

// THE SCOPE BOUNDARY, DERIVED FROM DECRYPTION ITSELF.
//
// # What was here before, and why it was not enough
//
// Round 18 replaced a prose paragraph with a map, theEncryptedFieldLedger, and a
// test that derived the REAL set from the module's AST and failed in both
// directions. Deriving beat remembering, and it was still wrong, because of WHAT
// it derived from: four call shapes.
//
//	decryptColumnOrLog / decryptCustomFields
//	OpenEntrySecret
//	DecryptInstanceConfig
//	columncrypto.DecryptString
//
// VaultHandler.decryptColumn was the raw primitive and decryptColumnOrLog was
// its logging wrapper, so a FIFTH door existed the whole time.
// UserHandler.openInviteCode opened invitations.code, a vault-key-encrypted
// bearer credential this file's own neighbour describes as a path to every vault
// secret, straight through the raw door. It matched none of the four shapes, so
// it never entered the derived set, and the guard reported a clean boundary over
// a column nothing had classified.
//
// Recognising decryption by the SHAPE OF THE CALL is the same mistake as
// recognising builds by argv or writes by a source regex. The list of wrappers
// is open: it is whatever somebody writes tomorrow.
//
// # What is here now
//
// The ledger is not a map any more. It is internal/vaultfield, and it is a
// by-product of being able to decrypt at all:
//
//   - every AES-GCM open in the vault-key family happens in
//     internal/vaultfield/vaultfield.go, and TestAESGCMIsOpenedInExactlyOneFile
//     checks module-wide that nothing else imports crypto/aes or crypto/cipher.
//     That is complete rather than broad, because opening AES-GCM data REQUIRES
//     those packages.
//   - every open there demands a vaultfield.Field, whose contents are unexported
//     and whose only constructor is vaultfield.Declare.
//   - Declare writes the ledger.
//
// A new decryption path therefore has three outcomes and silent omission is not
// one of them: it does not compile, or it reddens the import guard, or the
// ledger gains the entry by itself.
//
// The declarations below are the fields THIS package opens. secretexit declares
// vault_entries.encrypted_value next to the door that opens it, for the same
// reason: the declaration belongs where the plaintext is produced.
//
// # Residuals this construction does NOT close
//
//  1. A door can borrow an EXISTING Field belonging to a different column. The
//     ledger then knows that a decryption happens and knows a classification,
//     but under the wrong name. Closing it means binding the field name into the
//     ciphertext as AES-GCM additional authenticated data, so a blob sealed as
//     invitations.code refuses to open as vault_entries.notes. That is a
//     storage-format change, and the boot key-check probe samples a blob without
//     knowing which column it came from (vaultKeyOpensExistingData), so a
//     half-migrated database would answer "this key does not open my data" and
//     the gate would refuse to start on a CORRECT key. Deliberately deferred
//     rather than half-done. TestNoFieldIsDeclaredAndNeverOpened keeps the
//     declaration set from drifting into fiction in the meantime.
//  2. A caller holding plaintext can still copy it anywhere. That is the
//     residual the exit and its receipts exist for and is unchanged here.

// ── the fields this package opens ───────────────────────────────────────────

// vault_entries.custom_fields is the second credential an entry can hold.
var vaultFieldCustomFields = vaultfield.Declare(
	"vault_entries.custom_fields", vaultfield.ThroughTheExit,
	"vault.go:VaultHandler.customFieldsForCaller",
	"a field with secret:true is a SECOND credential on the same entry: an API key an operator pasted "+
		"into a labelled field, a recovery PIN, a database password. The whole blob is encrypted at rest "+
		"for that reason and the UI masks those values. It used to be decrypted straight into the "+
		"response body next to the entry's own value, which is a second exit with no destination, no "+
		"chooser and no receipt.")

// ── metadata, not a credential ──────────────────────────────────────────────
//
// Each of these is returned to a caller who already holds read on the entry,
// which is how they obtained the row at all. They are encrypted at rest so a
// stolen database FILE is not a readable one, not because releasing them is a
// decision anybody has to make.

var vaultFieldName = vaultfield.Declare(
	"vault_entries.name", vaultfield.NotACredential, "",
	"the label the operator gave the entry, and the column that describes it best. It is shown in every "+
		"list and every picker, so it is not a credential and releasing it is not a decision. It is "+
		"encrypted at rest for the same reason url and username are: \"Stripe live key\" beside an "+
		"encrypted value hands a keyless reader the whole inventory, which is most of what the other "+
		"encrypted columns were meant to withhold. Per-user uniqueness moved to name_bidx when this "+
		"stopped being comparable in SQL.")

var vaultFieldURL = vaultfield.Declare(
	"vault_entries.url", vaultfield.NotACredential, "",
	"the site this login belongs to, for browser-extension autofill matching. Not a secret: the blind "+
		"index over it is what autofill actually queries.")

var vaultFieldAliasURL = vaultfield.Declare(
	"vault_entries.alias_url", vaultfield.NotACredential, "",
	"a second autofill match for the same entry. Same shape as url, and it is decrypted on the same "+
		"paths, so it carries the same ruling.")

var vaultFieldUsername = vaultfield.Declare(
	"vault_entries.username", vaultfield.NotACredential, "",
	"the account name the credential belongs to. Half of a login pair and deliberately the half that is "+
		"not the secret; the value is the other half and it goes through the exit.")

var vaultFieldCategory = vaultfield.Declare(
	"vault_entries.category", vaultfield.NotACredential, "",
	"a display label from a fixed vocabulary (login, api_key, ssh_key, ...). It cannot hold a value a "+
		"user typed.")

var vaultFieldNotes = vaultfield.Declare(
	"vault_entries.notes", vaultfield.NotACredential, "",
	"free text the operator wrote ABOUT the credential. It is not designated secret material the way a "+
		"secret:true custom field is, and the product renders it unmasked, so treating it as a credential "+
		"would be a claim the UI already contradicts. An operator who pastes a key into notes should use "+
		"a custom field, and the field limits and the UI both say so.")

// ── operator configuration returned to callers who may already write it ─────

var vaultFieldProviderMeta = vaultfield.Declare(
	"vault_entries.provider_meta", vaultfield.NotACredential, "",
	"the provider binding (site, tenant, project_ref, the key id a rotation minted). Encrypted at rest "+
		"because account and key identifiers are worth not leaking from a stolen file. It is returned in "+
		"every entry response, and it is also a HOST-CHOOSING column, so who may WRITE it is the question "+
		"that matters and vaultegress answers it.")

var vaultFieldRotationTargets = vaultfield.Declare(
	"vault_entries.rotation_targets", vaultfield.NotACredential, "",
	"delivery configuration, including each webhook's HMAC SIGNING secret. That signing secret is the "+
		"one value here worth arguing about, and the argument was settled the other way: it is not a "+
		"client credential, it belongs to the delivery configuration rather than to the vault, and GET "+
		"/api/vault/{id}/targets is deliberately gated on MANAGE rather than read for exactly this reason "+
		"(see GetTargets). What the exit governs is the ROTATED VALUE this configuration delivers, and "+
		"that goes through deliverToWebhook.")

// ── in-process only ─────────────────────────────────────────────────────────

var vaultFieldTOTPSecret = vaultfield.Declare(
	"users.totp_secret", vaultfield.InProcessOnly, "",
	"the TOTP seed. It is a credential, and it never leaves: the only consumer is totp.ValidateCode, "+
		"which takes the seed and a six-digit code and returns a bool. The seed is shown to a user exactly "+
		"once, at ENROLMENT, from the value the server just generated rather than from a decrypt of the "+
		"column. The boot backfill that seals legacy plaintext seeds decrypts only to tell an "+
		"already-sealed row from a cleartext one, and emits nothing.")

var vaultFieldKeySentinel = vaultfield.Declare(
	"settings.vault_key_check", vaultfield.InProcessOnly, "",
	"the boot key sentinel. It decrypts a known constant and compares it to that constant, so the only "+
		"thing that leaves is the boolean 'this key opens this database'. Nothing here is a credential: "+
		"the plaintext is a literal in the source.")

var vaultFieldBootProbe = vaultfield.Declare(
	"boot key probe (any sealed column)", vaultfield.InProcessOnly, "",
	"the sample blob vaultKeyOpensExistingData pulls from whichever encrypted family a database happens "+
		"to have, to answer 'does the configured key open this data' before the server starts. It is the "+
		"ONE field that does not name a column, because the probe deliberately does not know which column "+
		"it got: AnyEncryptedColumnSample returns the first ciphertext of each family. It is safe as an "+
		"in-process ruling regardless of which column it lands on, because the probe entry points return "+
		"a bool and wipe the plaintext rather than returning it. If AAD binding ever lands (see residual "+
		"1 above), this is the field that has to be reworked first.")

var vaultFieldEntryValueProbe = vaultfield.Declare(
	"vault_entries.encrypted_value (boot key probe)", vaultfield.InProcessOnly, "",
	"the same column secretexit owns, opened by the BOOT KEY CHECK before any handler exists and "+
		"therefore before there is an exit to route it through. It is a separate declaration rather than "+
		"a reuse of secretexit's because exporting that field would hand every package a way to open an "+
		"entry's value as a bare []byte, which is exactly what the opaque Plaintext type exists to "+
		"prevent. The probe entry point (vaultfield.Opens) returns a bool and wipes the plaintext, so "+
		"this door cannot release a value however its caller is edited.")

// ── instance-owned ──────────────────────────────────────────────────────────
//
// These belong to the INSTANCE rather than to any vault entry, so there is no
// entry owner to ask, and the admin-only route gate is what the classification
// rests on. That premise is not asserted here: TestInstanceOwnedFieldsAreOnlyReachableByAdmins
// re-derives the route table and fails if any of them stops being admin-gated.

var vaultFieldSMTPPassword = vaultfield.Declare(
	"settings.smtp_password", vaultfield.InstanceOwned, "",
	"the SMTP relay password, an admin-only settings row. It belongs to the instance, not to any vault "+
		"entry, so there is no entry owner to ask, and what it authenticates is the instance's own "+
		"outbound mail.")

// vaultFieldInvitationCode is THE FIFTH DOOR, ruled.
var vaultFieldInvitationCode = vaultfield.Declare(
	"invitations.code", vaultfield.InstanceOwned, "",
	"a pending invitation's setup code: a bearer credential that redeems into an ACCOUNT, and for a "+
		"target_role of admin into an account that can reset a colleague's password and then unlock their "+
		"vault. That is why it is sealed at rest at all (see invitation_code.go: a keyless backup taken "+
		"while an invite was pending used to be readable and redeemable against the live server). It is "+
		"instance-owned rather than through-the-exit because it belongs to no vault entry, so the exit's "+
		"question ('did the OWNER of this secret authorise this destination') has no owner to ask; the "+
		"principal who chose both destinations is an instance admin, who holds the widening right on "+
		"every entry anyway. Both destinations are admin-only by construction: it is returned by GET "+
		"/api/admin/invitations and mailed by POST /api/admin/invitations/{id}/resend to the address the "+
		"admin typed at creation, and nothing else in the module opens the column.")

// alertChannelConfigField is declared in vault.go next to DecryptInstanceConfig,
// the one door that opens it. Declaring a field where the plaintext is produced
// is the rule this package now follows without exception; it is repeated here
// only so a reader of the ledger file is not left thinking the list is short.
