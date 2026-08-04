package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/secretexit"
)

// RotationTarget defines where a rotated key should be delivered.
//
// Trustissues supports three target types: "webhook" (HMAC-signed POST of the
// new value to a user-configured URL), "forgejo_secret" (update an Actions
// secret on a Forgejo/Gitea repository), and "notify" (fire the notification
// channels only, no value delivery). The control-plane target types dockyard
// carried (env_var, file_write, reload_endpoint) are deliberately not ported:
// they require a managed-server agent fleet that this standalone product does
// not have.
type RotationTarget struct {
	Type string `json:"type"` // "webhook", "forgejo_secret", "notify"

	// forgejo_secret target
	Instance   string `json:"instance,omitempty"`
	Repo       string `json:"repo,omitempty"`
	SecretName string `json:"secret_name,omitempty"`
	AuthToken  string `json:"auth_token,omitempty"` // vault entry name for the Forgejo token

	// webhook target
	WebhookURL    string `json:"webhook_url,omitempty"`
	WebhookSecret string `json:"webhook_secret,omitempty"` // HMAC secret for signing

	// Label for display
	Label string `json:"label,omitempty"`

	// ConfiguredBy is the user id that last wrote this target. AuthToken names
	// another vault entry, and it MUST be resolved against the identity that
	// CONFIGURED the target, never against the entry's owner: on a shared
	// collection entry any editor can add a target, so resolving as the owner
	// lets that editor name one of the owner's unrelated personal secrets and
	// have it delivered to a destination the editor controls. UpdateTargets
	// stamps this server-side on every write and overwrites whatever the client
	// sent, so it cannot be forged.
	ConfiguredBy string `json:"configured_by,omitempty"`
}

// targetTransmitsSecret reports whether this target type actually carries the
// secret VALUE off the box. webhook POSTs it as new_value; forgejo_secret writes
// it into a repository secret. notify sends a channel message about the
// rotation and never includes the value, and an unknown type sends nothing at
// all (DeliverRotatedKey fails it), so neither is a delivery destination.
func targetTransmitsSecret(t RotationTarget) bool {
	return t.Type == "webhook" || t.Type == "forgejo_secret"
}

// DeliveryResult records the outcome of delivering a key to a target.
type DeliveryResult struct {
	Target  RotationTarget `json:"target"`
	Success bool           `json:"success"`
	Error   string         `json:"error,omitempty"`
}

// ParseRotationTargets parses the rotation_targets JSON column. It always
// returns a non-nil slice so callers that marshal the result straight into a
// JSON response (GET /api/vault/{id}/targets) emit `[]` for an entry with no
// targets, never `null`.
func ParseRotationTargets(raw string) []RotationTarget {
	targets := make([]RotationTarget, 0)
	if raw != "" && raw != "[]" {
		_ = json.Unmarshal([]byte(raw), &targets)
	}
	return targets
}

// DeliverRotatedKey pushes a new key value to all configured targets for a vault entry.
// Returns results for each target. Failures are logged but don't block other targets.
//
// oldValue is the pre-rotation value. None of the remaining target types
// consume it (only the cut reload_endpoint grace flow did), but the parameter
// is kept so callers ported from dockyard, which always have it in hand, need
// no signature change.
//
// userID is the ENTRY OWNER and is used for logging context only. Vault
// references inside a target (forgejo_secret's auth_token) resolve as
// target.ConfiguredBy instead; see the RotationTarget doc comment for why.
func DeliverRotatedKey(ctx context.Context, queries *db.Queries, vault *VaultHandler, entryID string, entryName string, oldValue secretexit.Plaintext, newValue secretexit.Plaintext, targets []RotationTarget, userID string) []DeliveryResult {
	results := make([]DeliveryResult, 0, len(targets))

	// The provider pin, at delivery. An entry an admin wired into the AI gateway
	// is only ever sent to that provider, so it has no delivery targets at all:
	// deliverToWebhook POSTs the fresh secret to a URL somebody configured, which
	// is the same "who chooses where this goes" question the capability proxy
	// asks. UpdateTargets refuses to store one; this refuses to deliver one that
	// is already stored (older binary, restored backup, a row written before the
	// pin existed). A read error denies: an unreadable pin must not open a door.
	var pin egressPin
	var pinErr error
	if queries == nil {
		// No handle, no way to ask. Same posture as targetStillAuthorized's
		// vault == nil branch: refuse to deliver rather than deliver unverified.
		pinErr = errors.New("no database handle")
	} else {
		pin, pinErr = providerPinFor(ctx, queries, entryID)
	}
	pinRefusal := ""
	switch {
	case pinErr != nil:
		pinRefusal = "delivery target skipped: the entry's AI provider binding could not be read"
		slog.Error("vault delivery: provider pin unreadable, refusing delivery", "entry", entryName, "error", pinErr)
	case pin.pinned():
		pinRefusal = fmt.Sprintf("delivery target skipped: this secret is the instance's AI provider key (%s) "+
			"and is only ever sent to the provider", pin.describe())
	}

	for _, target := range targets {
		var err error
		if pinRefusal != "" && targetTransmitsSecret(target) {
			results = append(results, DeliveryResult{Target: target, Success: false, Error: pinRefusal})
			slog.Error("vault delivery: target refused by the provider pin",
				"type", target.Type, "entry", entryName, "configured_by", target.ConfiguredBy)
			continue
		}
		// Every target must still be traceable to someone who currently has
		// write on this entry, checked at DELIVERY rather than only at write.
		//
		// A collection editor can set targets on an entry they do not own, and
		// removing them from the collection deletes only the membership row. The
		// stored rotation_targets survived, and delivery never looked at who put
		// them there (only forgejo_secret consulted ConfiguredBy, and only to
		// resolve its auth_token). So an offboarded editor's webhook kept
		// receiving the plaintext secret, and the rotation performed to revoke
		// their access was the very thing that handed them the new value.
		//
		// Refusing here, rather than only purging on removal, is what makes this
		// authoritative: it also covers targets planted before any purge existed.
		// A refusal is a delivery FAILURE, not a silent skip, so summarizeDelivery
		// marks the rotation partial and dispatchRotationAlert fires; a quiet skip
		// would hide exactly the offboarding gap this is here to surface.
		switch target.Type {
		case "forgejo_secret", "webhook":
			// Gate the types that actually transmit the secret. An unknown or
			// retired type already fails below and never sends anything, so
			// checking it here would only obscure that error.
			if authErr := targetStillAuthorized(ctx, vault, entryID, target); authErr != nil {
				results = append(results, DeliveryResult{Target: target, Success: false, Error: authErr.Error()})
				slog.Error("vault delivery: target refused, configurer no longer has write on the entry",
					"type", target.Type, "entry", entryName, "configured_by", target.ConfiguredBy)
				continue
			}
			if target.Type == "forgejo_secret" {
				err = deliverToForgejoSecret(ctx, vault, target, newValue, userID)
			} else {
				err = deliverToWebhook(ctx, target, entryName, newValue)
			}
		case "notify":
			// Notification is handled separately by the caller via ChannelDispatcher
			continue
		default:
			err = fmt.Errorf("unknown target type: %s", target.Type)
		}

		result := DeliveryResult{Target: target, Success: err == nil}
		if err != nil {
			// summarizeDelivery folds result.Error into last_rotation_error,
			// which the API returns, the browser renders verbatim, AND
			// dispatchRotationAlert ships to notification channels off-box. Two
			// different leaks have to be closed here:
			//
			//   - a transport failure is a *url.Error whose Error() embeds the
			//     full target URL (internal IPs for an SSRF-blocked webhook,
			//     plus any query/userinfo). redactUpstreamError rewrites it.
			//   - a non-2xx used to be built with fmt.Errorf including up to
			//     200 bytes of the raw upstream body, which redactUpstreamError
			//     does NOT touch (it only matches *url.Error), so the body went
			//     straight through. Those sites now return upstreamHTTPError,
			//     whose Error() is structural and whose body is slog-only.
			//
			// The unredacted cause stays in the slog line below.
			result.Error = redactUpstreamError(err)
			slog.Error("vault delivery: target failed",
				"type", target.Type,
				"entry", entryName,
				"error", err)
		} else {
			slog.Info("vault delivery: target succeeded",
				"type", target.Type,
				"entry", entryName,
				"label", target.Label)
		}
		results = append(results, result)
	}

	return results
}

// targetStillAuthorized reports whether the user who configured this target may
// still write the entry, i.e. whether they would still be allowed to set it up
// today. It is the offboarding gate for rotation delivery.
//
// An empty ConfiguredBy is refused outright. Targets predate the field, so an
// unattributed one cannot be shown to belong to anyone with current access, and
// a rotation must not ship a live secret to an address nobody can vouch for.
// The owner can re-save the target to stamp their id and re-enable it.
func targetStillAuthorized(ctx context.Context, vault *VaultHandler, entryID string, target RotationTarget) error {
	if vault == nil || entryID == "" {
		// No way to check. Fail closed rather than deliver unverified.
		return fmt.Errorf("delivery target could not be authorized (no entry context); re-save the target to re-enable it")
	}
	if target.ConfiguredBy == "" {
		return fmt.Errorf("delivery target has no recorded configurer; re-save it in the rotation panel to re-enable delivery")
	}
	// Account status first, so a disabled or deleted configurer produces an
	// accurate reason. entryAccessFor now refuses them too, but it would report
	// "no longer has write access", which sends the operator looking at
	// collection membership instead of at the account they just disabled.
	u, uErr := vault.queries.GetUserByID(ctx, target.ConfiguredBy)
	if uErr != nil {
		return fmt.Errorf("delivery target skipped: the user who configured it no longer exists")
	}
	if u.Disabled != 0 {
		return fmt.Errorf("delivery target skipped: the user who configured it (%s) is disabled", u.Email)
	}
	// THE EGRESS QUESTION USED TO BE ASKED HERE TOO, AND IS NOT ANY MORE.
	//
	// Round 5 put `mayConfigureDelivery(ctx, target.ConfiguredBy, entryID)` at
	// this line. Round 7 deleted it, and this comment is the record of why.
	//
	// It was the same call the exit now makes, about the same entry, with one
	// difference that only ever made it weaker: it asked about entryID, the entry
	// being ROTATED, while the exit asks about the entry the SECRET CAME FROM.
	// For a webhook those are the same row. For a forgejo_secret target they are
	// not, and the gap between them is the whole round-6 break: the auth_token
	// secret belongs to another entry entirely, and this check never looked at it.
	//
	// Two copies of one rule is also what round 5 cost. Leaving a duplicate here
	// would put the identical question in two places again, and the only thing
	// that can come of that is the two disagreeing.
	//
	// What stays is what is NOT the egress question: the account-status rows
	// above, which give the operator an accurate reason ("the user who configured
	// it is disabled") instead of sending them to look at collection membership.
	// grantFor row 2 refuses a disabled account everything, so the exit would
	// refuse these too; it would just say something less useful.
	//
	// See secret_exit_authority.go and secretexit.Exit.
	return nil
}

// summarizeDelivery inspects delivery results and returns a rotation status
// ("success" only if every target delivered, otherwise "partial") plus a
// human summary naming the failed targets for last_rotation_error. This is
// what makes a rotation that didn't reach a consumer VISIBLE instead of
// silently logged as success.
func summarizeDelivery(results []DeliveryResult) (status, summary string) {
	var failures []string
	for _, r := range results {
		if !r.Success {
			label := r.Target.Label
			if label == "" {
				label = r.Target.Type
			}
			failures = append(failures, label+": "+r.Error)
		}
	}
	if len(failures) == 0 {
		return "success", ""
	}
	return "partial", fmt.Sprintf("%d/%d delivery targets failed: %s", len(failures), len(results), strings.Join(failures, "; "))
}

// dispatchRotationAlert fires a notification to configured channels when a
// rotation's value was stored but one or more targets failed to apply, or the
// old key could not be revoked.
//
// A var, not a plain func, so the rotation matrix can record whether an alert was
// actually dispatched. That matters here specifically: the manual path recorded a
// failed revoke and then overwrote it with success AND never alarmed, so a test
// that only checks the database would have passed on two of the three symptoms.
// Same idiom and same justification as providerHTTP.
var dispatchRotationAlert = dispatchRotationAlertReal

func dispatchRotationAlertReal(ctx context.Context, queries *db.Queries, decrypter alerts.ConfigDecrypter, entryName, detail string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("vault rotation: alert dispatch panicked", "recover", r)
		}
	}()
	alerts.NewChannelDispatcher(ctx, queries, decrypter).Dispatch(
		alerts.EventRotationPartial, "", "",
		map[string]string{"secret": entryName, "detail": detail},
	)
}

// deliverToForgejoSecret updates an Actions secret on a Forgejo/Gitea repository.
//
// THIS IS THE ROUND-6 PATH. It carries TWO secrets to the same host: the rotated
// value of the entry being delivered, in the body, and ANOTHER entry's personal
// access token, in the Authorization header. The second one is the break:
// auth_token names an entry by NAME, and an accepted vault_only VIEWER of a
// shared collection may USE the team's secret, so a viewer put this target on
// their OWN entry, named the team's secret, rotated their own entry, and the
// team secret left as a bearer token to a host they chose.
//
// Both secrets now leave through secretexit.Exit, each asked about ITS OWN
// owner. For the body that is the entry being rotated, whose delivery targets
// this configurer was entitled to set. For the header it is the REFERENCED
// entry, and the configurer has to hold the widening right on that one.
func deliverToForgejoSecret(ctx context.Context, vault *VaultHandler, target RotationTarget, newValue secretexit.Plaintext, userID string) error {
	if target.Instance == "" || target.Repo == "" || target.SecretName == "" {
		return fmt.Errorf("instance, repo, and secret_name are required for forgejo_secret target")
	}

	// Get the auth token for this Forgejo instance from the vault
	authToken := target.AuthToken
	if authToken == "" {
		return fmt.Errorf("auth_token (vault entry name for Forgejo access) is required")
	}

	// Resolve the auth token as the user who CONFIGURED this target, never as
	// the entry owner. The resolve is gated on entryAccessFor for that identity,
	// so it reaches only what they can CURRENTLY read: the raw (name, user_id)
	// query matched on the creator column, which let a removed collection member
	// name a shared secret here and have its post-rotation plaintext delivered to
	// a host they control. Targets written before ConfiguredBy existed carry no
	// identity and are refused rather than falling back to the owner.
	//
	// That gate answers "may they REACH this secret". It never answered "may
	// they send it HERE", and a viewer can reach a team secret by design. The
	// exit below is the second question.
	if target.ConfiguredBy == "" {
		return fmt.Errorf("target has no recorded configuring user; re-save this entry's rotation targets to authorize the auth_token lookup")
	}

	// Resolve the auth token, scoped to what the configuring user can still reach.
	tokenPlaintext, err := vault.resolveVaultReferenceFor(ctx, authToken, target.ConfiguredBy)
	if err != nil {
		slog.Error("vault delivery: auth_token resolve failed",
			"auth_token", authToken,
			"configured_by", target.ConfiguredBy,
			"entry_owner", userID,
			"error", err)
		return fmt.Errorf("resolve Forgejo auth token %q from the configuring user's vault: %w", authToken, err)
	}
	defer tokenPlaintext.Wipe()

	host := hostFromRawURL(target.Instance)

	// EXIT 1: the REFERENCED entry's token, as the bearer. Its owner is asked
	// whether the principal who configured this target may choose where THAT
	// entry's secret goes. The round-6 viewer could not.
	ctx, bearer, err := secretexit.ExitString(ctx, tokenPlaintext,
		secretexit.ToHost("this forgejo_secret delivery target's auth_token",
			secretexit.ChosenBy(target.ConfiguredBy), host))
	if err != nil {
		return err
	}

	// EXIT 2: the rotated value itself, in the body, asked about its own entry.
	ctx, pushed, err := secretexit.ExitString(ctx, newValue,
		secretexit.ToHost("this forgejo_secret delivery target",
			secretexit.ChosenBy(target.ConfiguredBy), host))
	if err != nil {
		return err
	}

	// PUT /api/v1/repos/{owner}/{repo}/actions/secrets/{secretname}
	payload, _ := json.Marshal(map[string]string{"data": pushed})
	url := strings.TrimRight(target.Instance, "/") + "/api/v1/repos/" + target.Repo + "/actions/secrets/" + target.SecretName

	// ctx carries BOTH receipts, so providerDo refuses unless the host it is
	// actually sending to is the one both owners authorised. There is no
	// default and no way to state a destination without an owner having said
	// yes to it. See internal/secretexit.
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+bearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := providerDo(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		return newUpstreamHTTPError(resp.StatusCode, body)
	}

	return nil
}

// deliverToWebhook POSTs the new key to a webhook URL with HMAC-SHA256 signing.
func deliverToWebhook(ctx context.Context, target RotationTarget, entryName string, newValue secretexit.Plaintext) error {
	if target.WebhookURL == "" {
		return fmt.Errorf("webhook_url is required")
	}

	// THE ONE EXIT. The destination was chosen by whoever configured this
	// target, so the OWNER of the secret is asked whether that principal may
	// choose where it goes.
	ctx, value, err := secretexit.ExitString(ctx, newValue,
		secretexit.ToHost("this webhook delivery target",
			secretexit.ChosenBy(target.ConfiguredBy), hostFromRawURL(target.WebhookURL)))
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]string{
		"event":      "vault.key_rotated",
		"entry_name": entryName,
		"new_value":  value,
		"rotated_at": time.Now().UTC().Format(time.RFC3339),
	})

	req, err := http.NewRequestWithContext(ctx, "POST", target.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Trustissues-Vault/1.0")

	// HMAC-SHA256 signature if secret is provided
	if target.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(target.WebhookSecret))
		mac.Write(payload)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Vault-Signature", "sha256="+sig)
	}

	resp, err := providerDo(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return newUpstreamHTTPError(resp.StatusCode, body)
	}

	return nil
}

// NOTE: UpdateTargets (PUT /api/vault/{id}/targets) lives in vault.go with
// the other per-entry HTTP handlers. Its validation switch must accept
// exactly the three types this file implements delivery for: webhook,
// forgejo_secret, notify. TestUpdateTargetsValidationSetMatchesDelivery in
// vault_targets_test.go guards that contract.

// rotationTargetIdentity keys a rotation target by WHERE it delivers, so an
// unchanged row can be recognised across a save and keep its original
// ConfiguredBy.
//
// Deliberately excludes the label and any secret material: renaming a target is
// not a change of destination and must not re-attribute it, while changing where
// it points is a new target and must be stamped to whoever made that change.
func rotationTargetIdentity(t RotationTarget) string {
	switch t.Type {
	case "webhook":
		return "webhook|" + t.WebhookURL
	case "forgejo_secret":
		return "forgejo|" + t.Instance + "|" + t.Repo + "|" + t.SecretName
	default:
		return t.Type + "|" + t.Label
	}
}

// rotationTargetAttribution keys a target by everything that decides WHOSE
// authority the delivery runs under, so an unchanged row keeps its original
// ConfiguredBy and a changed one is stamped to whoever changed it.
//
// It is the destination PLUS auth_token, and the auth_token half is the reason
// this is a second function rather than a reuse of rotationTargetIdentity.
// deliverToForgejoSecret resolves auth_token against ConfiguredBy, so preserving
// the attribution across an auth_token edit let an editor point somebody else's
// identity at a different one of their secrets and have it spent as the bearer
// token for the delivery. Changing which credential is spent is a new decision
// and belongs to whoever made it.
//
// It deliberately still excludes the label and the webhook HMAC secret: renaming
// a target or rotating its signing key changes neither the destination nor the
// identity that authorizes it, and re-attributing on those would let an
// unrelated save launder a departed member's target back to life, which is the
// bug the preservation rule exists to prevent.
func rotationTargetAttribution(t RotationTarget) string {
	return rotationTargetIdentity(t) + "|auth=" + t.AuthToken
}
