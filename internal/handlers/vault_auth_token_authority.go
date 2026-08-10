package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// THE AUTH_TOKEN QUESTION, ASKED WHERE SOMEBODY IS LOOKING.
//
// A forgejo_secret target names another vault entry by NAME in auth_token, and
// that entry's secret becomes the bearer token of the delivery. Round 7 made
// that bearer leave through the exit, asked about ITS OWN owner, which is the
// round-6 kill: an accepted viewer may USE a team secret and may not choose
// where it goes.
//
// It did not make the WRITE gate ask the same thing. VaultHandler.UpdateTargets
// validates the shape of a forgejo target and never looks at auth_token at all,
// so the ordinary team configuration
//
//	Alice owns app-key, Bob owns the shared CI token, Alice wires app-key's
//	rotation to push into Forgejo using Bob's token
//
// is accepted, reported as saved, rendered as a live target, and then dropped at
// the NEXT rotation. Which is weeks later, unattended, immediately after the
// credential has been rolled at the provider, so the consumer is left holding a
// dead key and the only trace is a rotation_partial alert.
//
// Round 5 named that failure mode (accept, report saved, silently never deliver)
// as the worst of the three possible ones and fixed it once, for the admin case.
// This is the same defect with the argument changed, which is this codebase's
// recurring shape: the fix lands on one of two twins.
//
// So the question lives here, once, and BOTH halves call it:
//
//	the write     UpdateTargets, before it stores anything -> 403, naming the
//	              entry and the missing right, while an operator is looking.
//	the boot      AuditCrossOwnerAuthTokenTargets, over the rows an existing
//	              instance already has -> an activity row per entry, so a
//	              deploy names what will break instead of the next rotation
//	              discovering it.
//
// It deliberately does NOT re-implement the rule. It resolves the referenced
// entry the way delivery resolves it and asks mayConfigureDelivery, which is the
// same call secretexit's Authority makes. Two copies of one rule is round 5.

// authTokenRefusal explains why a forgejo target's auth_token cannot be spent by
// the principal who configured it. The zero value means "no objection".
type authTokenRefusal struct {
	// TargetLabel is the operator's own label for the target, for the message.
	TargetLabel string
	// AuthToken is the entry NAME the target references.
	AuthToken string
	// Reason is the refusal, phrased for the person who has to fix it.
	Reason string
}

func (r authTokenRefusal) empty() bool { return r.Reason == "" }

// checkAuthTokenAuthority answers "may configuredBy spend the entry named by
// this target's auth_token as a bearer token?".
//
// The answer is the delivery gate's answer, obtained the delivery gate's way:
// resolve the reference as the configuring identity (resolveVaultReferenceFor,
// which is scoped to what they can CURRENTLY reach), then ask
// mayConfigureDelivery about the entry it resolved to. That second question is
// the one the exit asks, and asking it here is what stops the two halves from
// disagreeing.
//
// A target with no auth_token, or one that is not a forgejo_secret, has nothing
// to answer for.
func (h *VaultHandler) checkAuthTokenAuthority(ctx context.Context, t RotationTarget) authTokenRefusal {
	if t.Type != "forgejo_secret" || strings.TrimSpace(t.AuthToken) == "" {
		return authTokenRefusal{}
	}
	label := t.Label
	if label == "" {
		label = t.Instance
	}
	refuse := func(reason string) authTokenRefusal {
		return authTokenRefusal{TargetLabel: label, AuthToken: t.AuthToken, Reason: reason}
	}
	if strings.TrimSpace(t.ConfiguredBy) == "" {
		// Also not refused here. targetStillAuthorized already refuses an
		// unattributed target at delivery, with its own message telling the owner
		// to re-save it, and UpdateTargets stamps ConfiguredBy on every write it
		// performs, so this shape can only arrive from an older binary or a
		// restored backup. Refusing it at the write would report a problem the
		// write itself has just fixed.
		return authTokenRefusal{}
	}

	// Resolve exactly as delivery does.
	//
	// A reference that does not resolve AT ALL (no such entry yet, an ambiguous
	// name, one the configurer cannot reach) is deliberately NOT refused here.
	// That case fails at delivery today and failed at delivery before this round,
	// so refusing it at the write would be a second behaviour change riding along
	// with the fix: an operator who wires the target before creating the token,
	// which the panel lets them do in either order, would suddenly be blocked.
	// The scope of this gate is exactly the case the exit newly refuses.
	pt, err := h.resolveVaultReferenceFor(ctx, t.AuthToken, t.ConfiguredBy)
	if err != nil {
		return authTokenRefusal{}
	}
	pt.Wipe()

	// The entry the reference landed on is the one whose owner has to have said
	// yes. Origin carries it, which is the same argument the exit uses and the
	// same argument round 6 got wrong.
	referenced := pt.Origin().EntryID
	if referenced == "" {
		return authTokenRefusal{}
	}
	if !h.mayConfigureDelivery(ctx, t.ConfiguredBy, referenced) {
		return refuse(fmt.Sprintf("the vault entry %q belongs to somebody else. Being able to USE a "+
			"shared secret is not the right to choose where it is sent, and a forgejo_secret target "+
			"sends it: its value becomes the Authorization header of this delivery. That takes the "+
			"secret's owner or an instance admin. Use a token you own, or ask its owner to configure "+
			"this target", t.AuthToken))
	}
	return authTokenRefusal{}
}

// AuditCrossOwnerAuthTokenTargets is the MIGRATION half, run once at boot.
//
// The write gate only covers writes made after the deploy. An existing instance
// has forgejo targets configured months ago under the old rule, and every one of
// them stops delivering at its next rotation. Establishing that at boot, by
// name, is the difference between "a deploy told us what would break" and "a
// credential rolled at 03:00 and the consumer got nothing".
//
// It CHANGES NOTHING. It reads, reports and returns; the rows stay exactly as
// they are, so an operator decides whether to re-point the target at a token
// they own or to have the owner configure it. Silently rewriting somebody's
// delivery configuration at boot would be a worse cure than the disease.
//
// The returned lines are also what the test asserts on, so the report and the
// guard cannot describe different things.
func (h *VaultHandler) AuditCrossOwnerAuthTokenTargets(ctx context.Context) []string {
	rows, err := h.queries.ListVaultEntriesForMetaBackfill(ctx)
	if err != nil {
		slog.Error("vault: could not scan rotation targets for cross-owner auth_token references",
			"error", err)
		return nil
	}
	// Two reports of the same findings, differing only in whether the referenced
	// entry NAME is sealed.
	//
	// report goes to the container log and to the caller; sealedReport goes to
	// activity_log, which is a column in the database file this product exists to
	// make useless when stolen. Sealing one string for both surfaces would have
	// put enc:v1: blobs in the operator's log at the moment they are reading it
	// to fix a delivery that is about to fail, which is the mistake
	// rotateOneEntry documents at its EntryNamePlain call.
	var report, sealedReport []string
	for _, row := range rows {
		raw := strings.TrimSpace(row.RotationTargets.String)
		if raw == "" {
			continue
		}
		for _, t := range ParseRotationTargets(h.decryptColumnOrLog(raw, "[]", vaultFieldRotationTargets)) {
			refusal := h.checkAuthTokenAuthority(ctx, t)
			if refusal.empty() {
				continue
			}
			const lineFmt = "entry %s: delivery target %q references the vault entry %q, which " +
				"its configurer may not spend, so this delivery will FAIL at the next rotation. %s"
			report = append(report, fmt.Sprintf(lineFmt,
				row.ID, refusal.TargetLabel, refusal.AuthToken, refusal.Reason))
			sealedReport = append(sealedReport, fmt.Sprintf(lineFmt,
				row.ID, refusal.TargetLabel, h.sealSecretName(ctx, refusal.AuthToken), refusal.Reason))
		}
	}
	if len(report) > 0 {
		slog.Error("vault: rotation delivery targets that will fail at their next rotation",
			"count", len(report))
		for _, line := range report {
			slog.Error("vault: " + line)
		}
		LogActivity(h.queries, nil, "vault.targets_need_reconfiguration",
			fmt.Sprintf("%d rotation delivery target(s) reference a vault entry their configurer may "+
				"not send. They will fail at the next rotation: %s",
				len(sealedReport), strings.Join(sealedReport, "; ")))
	}
	return report
}
