package handlers

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// THE OWNER RULE, STATED ONCE, AT THE EXIT.
//
// internal/secretexit owns the CONSTRUCTION (a decrypted secret is an opaque
// type with exactly one accessor). This file is the DECISION that accessor
// consults, and it is the only implementation of secretexit.Authority in the
// product.
//
// The question is not "may this caller read the entry" and not "who wrote the
// row". Those are the two questions rounds 1 through 6 kept asking, and the
// round-6 attacker passed both: an accepted vault_only VIEWER of a shared
// collection, who wrote nothing on the victim's entry at all, put a
// forgejo_secret target on their OWN entry with auth_token naming the team's
// secret and rotated their own entry. Every gate on that path said yes and every
// one of them was right about the question it was asking.
//
// The question is:
//
//	Did the OWNER of the secret being sent authorise this destination?
//
// # The three answers
//
//	chooser                     the rule
//	───────────────────────────────────────────────────────────────────────────
//	ChosenBy(u)                 u must hold the WIDENING RIGHT on the entry the
//	                            secret came from: mayDirectSecretEgress, which
//	                            is the entry's creator or an instance admin, in
//	                            both cases only while they still hold manage.
//	                            THIS IS THE ROUND-6 KILL. The attacker held it
//	                            on their carrier entry and never on the victim's.
//
//	ChosenByTheEntrysOwnRecord  the host must be inside the destinations
//	                            currently recorded ON THAT ENTRY. Not taken on
//	                            trust: re-derived here, at the moment of
//	                            delivery, so a row written by an older binary, an
//	                            import or a restored backup is refused even
//	                            though it never passed a write gate.
//
//	ChosenByTheInstance         allowed. An admin-only settings row, and an
//	                            instance admin holds the widening right on every
//	                            entry (grantFor row 3), so this is the same rule
//	                            with the answer already known.
//
// A caller destination (the secret is returned in a response body) asks the READ
// question instead, because handing a value to a principal is not choosing a
// network destination.
//
// # Why this is complete where the per-column guards were not
//
// ownerRecordedDestinations below is an ALLOWLIST, and secretexit.Exit is
// default-deny. A host-choosing column added tomorrow contributes nothing to it,
// so it can authorise nothing. The failure mode of forgetting to wire a new
// column in is "the feature does not work", never "the secret leaks".
//
// Rounds 3 through 6 were pointed the other way round: every unenumerated field
// was allowed until somebody thought to deny it.

// AuthorizeSecretExit implements secretexit.Authority. It is the ONE decision
// every decrypted secret in this product passes through on its way out.
func (h *VaultHandler) AuthorizeSecretExit(ctx context.Context, o secretexit.Origin, d secretexit.Destination) error {
	if d.IsCaller() {
		return h.authorizeSecretToCaller(ctx, o, d)
	}
	if d.IsInProcess() {
		// Nothing is transmitted, and Exit mints no receipt, so the next
		// outbound request built on this context is refused for having none.
		// There is no destination to authorise.
		return nil
	}
	if !d.IsNetwork() {
		return fmt.Errorf("%s has no destination kind, so nothing can be authorised", d.Describe())
	}

	// Instance configuration (a notification channel, the SMTP relay password)
	// belongs to no entry. Only an instance admin can write those rows, and an
	// instance admin holds the widening right on every entry, so there is no
	// narrower principal to ask about.
	if o.Instance {
		if d.ChosenByInstance() {
			return nil
		}
		return fmt.Errorf("%s may only be sent to a destination the instance itself configured, and %s "+
			"was not", o.Describe(), d.Describe())
	}

	if o.EntryID == "" {
		return fmt.Errorf("this secret records no vault entry, so there is no owner who could authorise "+
			"%s", d.Describe())
	}

	switch {
	case d.ChosenByInstance():
		// An admin-only settings row joined to a compile-time host table: the AI
		// gateway pin. Nobody who can edit the entry can move it.
		return nil

	case d.ChosenByEntryRecord():
		recorded, err := h.ownerRecordedDestinations(ctx, o.EntryID)
		if err != nil {
			// A read error DENIES. Treating "cannot tell" as "allowed" is how a
			// guard stops guarding without anybody noticing, and this one stands
			// between a decrypted secret and a host somebody named.
			return fmt.Errorf("the destinations recorded on %s could not be read, so its secret was not "+
				"sent anywhere: %w", o.Describe(), err)
		}
		for _, host := range d.Hosts().Hosts {
			if !recorded.Allows(host) {
				return fmt.Errorf("%s is not a destination recorded on %s. Its owner has authorised %s. "+
					"(%s)", secretexit.NormalizeHost(host), o.Describe(), recorded.Describe(), d.What())
			}
		}
		if len(d.Hosts().Suffixes) > 0 && len(recorded.Suffixes) == 0 {
			return fmt.Errorf("%s would let the upstream choose a host under %s, and no such destination "+
				"is recorded on %s", d.What(), strings.Join(d.Hosts().Suffixes, ", "), o.Describe())
		}
		return nil

	default:
		chooser := d.ChoosingUser()
		if chooser == "" {
			return fmt.Errorf("%s has no recorded chooser, so there is nobody whose authority could be "+
				"checked against %s", d.Describe(), o.Describe())
		}
		// THE ROUND-6 KILL, in one call. mayConfigureDelivery is
		// mayDirectSecretEgress with the admin question resolved from the users
		// row rather than from a session claim, which is what keeps the write
		// half and this half from ever disagreeing again (round 5).
		//
		// Note WHICH entry it is asked about: o.EntryID, the entry the SECRET
		// came from. The pre-fix code asked about the entry being rotated, which
		// on the round-6 path is the attacker's own.
		if !h.mayConfigureDelivery(ctx, chooser, o.EntryID) {
			return fmt.Errorf("%s was chosen by a user who may not choose where %s goes. "+
				"That takes the secret's owner or an instance admin (%s)",
				d.Describe(), o.Describe(), d.What())
		}
		return nil
	}
}

// authorizeSecretToCaller answers the read question for a value that is about to
// be put in a response body.
//
// Deliberately grantFor(...).read rather than .use. "May spend this credential
// against a destination somebody else chose" and "may be handed the value" are
// different rights, and conflating them is what the whole use-without-see model
// exists to keep apart. A viewer HAS use and passes the reveal path only because
// that path re-verifies their password first; this is the row-level half of the
// same answer.
func (h *VaultHandler) authorizeSecretToCaller(ctx context.Context, o secretexit.Origin,
	d secretexit.Destination) error {

	if o.Instance {
		return fmt.Errorf("%s is not returned to callers", o.Describe())
	}
	who := d.Principal()
	if who == "" || o.EntryID == "" {
		return fmt.Errorf("%s cannot be returned to an unidentified caller", o.Describe())
	}
	if !h.grantFor(ctx, who, h.instanceAdminByRecord(ctx, who), o.EntryID).read {
		return fmt.Errorf("%s may not be returned to %s: they have no read access to it (%s)",
			o.Describe(), who, d.What())
	}
	return nil
}

// ownerRecordedDestinations is every network host the OWNER of this entry has
// recorded as somewhere its secret may go.
//
// EVERY SOURCE ANSWERS "WHOSE IS THIS". That sentence is the round-8 fix and it
// used to be true of exactly one of the four:
//
//	the AI gateway pin           the INSTANCE's. An AdminOnly settings row joined
//	                             to a compile-time host table. No member can
//	                             write either side, so there is no narrower
//	                             principal to ask about, and it CAPS rather than
//	                             contributes.
//	destination_patterns         the entry's RECORDED OWNER's, and counted only
//	                             while that owner still holds the widening right
//	                             on this entry.
//	provider + provider_meta     split. The hosts a provider reaches with NO meta
//	                             at all are compile-time constants and belong to
//	                             nobody, so they always count. The hosts
//	                             provider_meta chooses (datadog's site, grafana's
//	                             instance, forgejo's whole base URL) are the
//	                             owner's, under the same test as the ceiling.
//	its own rotation targets     each target's recorded ConfiguredBy, under that
//	                             same test. This one already did it.
//
// # Why the answer for steps 2 and 3 is "the owner's"
//
// Both columns are written through internal/vaultegress, and every wrapper there
// refuses without an egressgate.Ticket for that entry and that field. A Ticket
// that ADDS a destination is minted only when the authority oracle says yes, and
// the oracle is mayDirectSecretEgress: the recorded owner, or an instance admin,
// in both cases only while they still hold manage. So a host sitting in either
// column was put there by the owner of the time or by an admin. Asking whether
// the RECORDED OWNER may still direct this secret is therefore the same question
// step 4 asks about ConfiguredBy, asked about the principal these two columns
// record implicitly rather than in a field of their own.
//
// WHAT THAT FIXES. On a database where the round-7 adoption already ran, both
// migrations withhold secret_owner_user_id and mayDirectSecretEgress refuses
// everybody. Before this change that refusal governed step 4 alone, and the
// attacker's planted ceiling and planted provider_meta still authorised their
// own host: the migration cleared the ANSWER and left the QUESTION EVIDENCE in
// place. Now an entry with no recorded owner records no destinations either,
// which is the fail-closed reading of "nobody has answered".
//
// WHAT IT COSTS, stated rather than discovered. An entry whose owner is recorded
// but who no longer holds manage (they were removed from the collection the
// entry lives in) stops contributing recorded destinations, exactly as its
// delivery targets already did. Settings -> Ownership is where an admin takes
// such a row back, and ClaimSecretOwnership deliberately CLEARS the plantable
// evidence as it does so, so a repair cannot silently re-arm a host the previous
// holder chose.
//
// A read error is returned, never swallowed.
func (h *VaultHandler) ownerRecordedDestinations(ctx context.Context, entryID string) (secretexit.HostSet, error) {
	var set secretexit.HostSet
	if entryID == "" {
		return set, fmt.Errorf("no entry id")
	}

	// 1. The pin. Read first because a pinned entry is CAPPED by it: an entry an
	// admin wired into the AI gateway goes to that provider and nowhere else,
	// whatever any other column says.
	pin, err := providerPinFor(ctx, h.queries, entryID)
	if err != nil {
		return secretexit.HostSet{}, fmt.Errorf("read the AI provider binding: %w", err)
	}
	if pin.pinned() {
		return secretexit.HostSet{Hosts: append([]string(nil), pin.hosts...)}, nil
	}

	meta, err := h.queries.GetVaultEntryMeta(ctx, entryID)
	if err != nil {
		return secretexit.HostSet{}, fmt.Errorf("read entry %s: %w", entryID, err)
	}

	// WHOSE RECORD THIS IS, asked once for the two columns that record it
	// implicitly. A read error denies, like every other read on this path.
	ownerMayDirect, err := h.recordedOwnerMayDirect(ctx, entryID)
	if err != nil {
		return secretexit.HostSet{}, fmt.Errorf("read the recorded owner of entry %s: %w", entryID, err)
	}

	seen := map[string]bool{}
	add := func(host string) {
		x := secretexit.NormalizeHost(host)
		if x == "" || strings.Contains(x, "*") || seen[x] {
			return
		}
		seen[x] = true
		set.Hosts = append(set.Hosts, x)
	}

	// 2. destination_patterns, the capability ceiling. The owner's record, and
	// it counts only while the owner is somebody who may direct this secret.
	if ownerMayDirect {
		for _, pat := range parseDestinationPatterns(meta.DestinationPatterns) {
			if hostIsWildcarded(pat) {
				// destMatches refuses to honour these at match time, so honouring
				// them here would authorise a host the matcher would then reject,
				// or worse the sibling domains it exists to keep out.
				continue
			}
			host, _ := splitHostPath(strings.TrimSpace(pat))
			add(host)
		}
	}

	// 3. provider + provider_meta, through the same declaration table the
	// derivation gate uses, so "site: datadoghq.eu" is read as api.datadoghq.eu
	// rather than as an opaque string.
	//
	// SPLIT BY WHO CHOSE THE HOST, not by which column it came out of. A fixed
	// vendor host is a compile-time constant in providerEgress and no writable
	// field moves it, so no principal has to vouch for it. A meta-derived host
	// IS a writable field, and it is the round-4 class: it needs the same answer
	// the ceiling needs.
	providerMeta := ParseProviderMeta(h.decryptColumnOrLog(meta.ProviderMeta.String, "{}", vaultFieldProviderMeta))
	declared := metaIndependentProviderEgress(meta.Provider.String, providerMeta)
	if ownerMayDirect {
		declared = declaredProviderEgress(meta.Provider.String, providerMeta)
	}
	for _, host := range declared.Hosts {
		add(host)
	}
	set.Suffixes = append(set.Suffixes, declared.Suffixes...)

	// 4. This entry's OWN delivery targets, each still traceable to somebody who
	// may choose where this entry's secret goes.
	//
	// The ConfiguredBy check is not decoration. Without it a target planted by an
	// editor, or left behind by a departed member, would re-authorise its own
	// host and the delivery gate would be reading its answer out of the thing it
	// is supposed to be judging.
	targets, tErr := h.queries.GetVaultEntryTargets(ctx, entryID)
	if tErr == nil && strings.TrimSpace(targets.String) != "" {
		for _, t := range ParseRotationTargets(h.decryptColumnOrLog(targets.String, "[]", vaultFieldRotationTargets)) {
			if !targetTransmitsSecret(t) {
				continue
			}
			if t.ConfiguredBy == "" || !h.mayConfigureDelivery(ctx, t.ConfiguredBy, entryID) {
				continue
			}
			switch t.Type {
			case "webhook":
				add(hostFromRawURL(t.WebhookURL))
			case "forgejo_secret":
				add(hostFromRawURL(t.Instance))
			}
		}
	}

	sort.Strings(set.Hosts)
	return set, nil
}

// recordedOwnerMayDirect answers "is there somebody recorded as this entry's
// secret owner who may still choose where its plaintext goes".
//
// It is deliberately the SAME call step 4 makes about a rotation target's
// ConfiguredBy, so the uniform rule is uniform by construction rather than by
// two functions agreeing. mayConfigureDelivery resolves the admin question from
// the users row, which is what keeps the write half and the delivery half from
// disagreeing (round 5), and it refuses a principal who has lost manage.
//
// An EMPTY owner is not a principal, so it answers nothing and the caller counts
// nothing. That is the migration's own ruling read back at delivery: 00034 and
// 00035 withhold the owner on every row the database cannot prove, and a
// withheld answer must not leave the evidence standing.
//
// The error is a READ error and is returned rather than folded into false, so a
// caller cannot mistake "the database is unreachable" for "this entry has no
// owner". Both deny; only one of them is worth an operator's attention.
func (h *VaultHandler) recordedOwnerMayDirect(ctx context.Context, entryID string) (bool, error) {
	info, err := h.queries.GetVaultEntryAccess(ctx, entryID)
	if err != nil {
		return false, err
	}
	owner := strings.TrimSpace(info.SecretOwnerUserID)
	if owner == "" {
		return false, nil
	}
	return h.mayConfigureDelivery(ctx, owner, entryID), nil
}

// hostFromRawURL pulls the host out of a stored URL. An unparseable value
// contributes nothing, which is the safe direction.
func hostFromRawURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return u.Hostname()
}

// entrySecretSource is what a handler needs from the vault to OPEN an entry's
// value: the opaque type, never bytes.
//
// It exists because the capability bridge and the service-identity fetch hold
// the vault behind an interface rather than as a *VaultHandler, and before round
// 7 that interface was alerts.ConfigDecrypter, whose method returned a []byte.
// So the two surfaces that spend other people's secrets on their behalf were
// wired to the door meant for instance-owned notification config, and a test fake
// of it could hand out plaintext with nobody to ask.
//
// TestVaultHandlerIsTheOnlyProductionAuthority pins the implementation set.
type entrySecretSource interface {
	OpenEntrySecret(ciphertext, nonce []byte, encVersion int,
		o secretexit.Origin) (secretexit.Plaintext, error)
	// EntryNamePlain opens vault_entries.name, which has been encrypted at rest
	// since 00040. The capability bridge resolves a secret BY name and then
	// writes that name into capability_log and into its own response, so it needs
	// the cleartext for both and holds no vault key of its own. It goes through
	// the ledger like every other opened column; see vaultFieldName.
	EntryNamePlain(stored string) string
	// SealAuditName encrypts a name on its way INTO an append-only audit table,
	// under the audit DEK rather than the master key. Both callers (the capability
	// bridge and the service-secrets fetch) hold no key of their own, and both
	// write a name that would otherwise sit in cleartext beside the encrypted
	// inventory it describes. See audit_name_crypto.go for why the DEK exists at
	// all: append-only rows cannot be rewritten by a key rotation.
	SealAuditName(ctx context.Context, plain string) string
}

// SCOPE BOUNDARY, DERIVED RATHER THAN LISTED.
//
// This used to be a prose paragraph naming the two encrypted things that are
// deliberately outside the exit, introduced with the words "so the boundary is a
// decision rather than an oversight". It had already rotted when it shipped: it
// named alert_channels.config and the smtp_password setting and missed
// vault_entries.custom_fields, which is AES-encrypted at rest exactly like the
// value, can hold operator-designated secret material, and was written into a
// response body with no destination, no chooser, no receipt and no entry in
// theExitList.
//
// A list of what is out of scope is exactly the kind of claim that rots, and a
// rotted one reads as coverage. So the list is theEncryptedFieldLedger in
// encrypted_field_ledger.go, and TestEveryEncryptedFieldIsClassified derives the
// REAL set from the module's AST (every decryptColumnOrLog field literal, every
// columncrypto decrypt site, every OpenEntrySecret, every DecryptInstanceConfig)
// and fails in both directions. A NEW encrypted field has to be CLASSIFIED
// rather than forgotten, and a classification of something that no longer exists
// fails too.
//
// Two fields are classified as going through the exit: encrypted_value, which is
// what this whole construction is about, and custom_fields, which is now routed
// through VaultHandler.customFieldsForCaller.
