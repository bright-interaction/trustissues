package handlers

import (
	"errors"
	"net/http"
	"strconv"
)

// The operator surface for master-key rotation.
//
// Two endpoints and a Settings tab, not just an env var and a restart.
//
// The choice is deliberate. A rotation happens for one of two reasons: policy,
// or a suspected key compromise. In the second case the operator is under time
// pressure, is possibly not the person who deployed the instance, and needs to
// know three things immediately: which key this store is actually on, whether
// anything is unreadable, and what to do next. An env var plus a restart answers
// none of those, and a boot-only flag has the additional problem that its output
// is a log line in a container someone has to know how to reach.
//
// So the primary path is GET (status, always available, no configuration
// required) plus POST (run the sweep), surfaced in Settings -> Encryption. The
// status is shown whether or not a rotation is in flight, which is what makes
// this discoverable without documentation: an operator who changed the key
// naively sees "N values open under no key you have loaded" the next time they
// open Settings, instead of finding out when a teammate reports blank fields.
//
// TRUSTISSUES_VAULT_KEY_REKEY_ON_BOOT remains for headless deploys where nobody
// logs in. It runs the same code path.

// VaultKeyStatus handles GET /api/admin/vault-key.
//
// Read-only. Safe to poll, and deliberately callable when no rotation is
// configured, because "everything is on the current key" is exactly the
// reassurance an operator wants after finishing one.
func (h *VaultHandler) VaultKeyStatus(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	rep, err := h.RekeyStatus(r.Context())
	if err != nil {
		logError(r, "vault_key: status scan failed", "error", err)
		writeInternalError(w, r, "could not read encryption status")
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// VaultKeyRekey handles POST /api/admin/vault-key/rekey.
//
// Status codes carry meaning the operator acts on:
//
//	200 the store is now entirely on the current key (including the no-op case)
//	409 a sweep is already running, or something is unreadable and nothing was
//	    written. Both are states where retrying blindly is wrong.
//	500 the sweep could not complete; the transaction was rolled back
//
// The 409 for a blocked sweep is not a stylistic choice. A blocked sweep means
// the store holds ciphertext that no configured key opens, and the single worst
// thing an operator can do at that moment is assume the rotation succeeded and
// delete the old key. The response body names how many values and which
// table/column they are in, without ever including a value.
func (h *VaultHandler) VaultKeyRekey(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)

	rep, err := h.RekeyVault(r.Context())
	switch {
	case errors.Is(err, ErrRekeyInProgress):
		writeConflict(w, r, "a re-encrypt sweep is already running")
		return
	case errors.Is(err, ErrRekeyBlocked):
		LogActivityFromRequest(h.queries, r, "vault.rekey_blocked", rep.Error)
		writeJSON(w, http.StatusConflict, rep)
		return
	case errors.Is(err, ErrRekeyNoPreviousKey):
		writeBadRequest(w, r, "TRUSTISSUES_VAULT_KEY_PREVIOUS is not set, so there is no previous key to convert from")
		return
	case err != nil:
		logError(r, "vault_key: rekey failed", "error", err)
		LogActivityFromRequest(h.queries, r, "vault.rekey_failed", "re-encrypt sweep rolled back")
		writeInternalError(w, r, "re-encrypt sweep failed and was rolled back; nothing changed")
		return
	}

	// Audited as a distinct action, not folded into a generic settings change.
	// "Who re-keyed this vault and when" is a question an incident review will
	// ask, and activity_log has append-only triggers so the answer cannot be
	// quietly removed later.
	LogActivityFromRequest(h.queries, r, "vault.rekey",
		"re-encrypted "+strconv.Itoa(rep.RowsConverted)+" row(s) under vault key "+rep.CurrentKeyFingerprint)
	writeJSON(w, http.StatusOK, rep)
}
