package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/columncrypto"
	"github.com/bright-interaction/trustissues/internal/db"
)

// The wire-format guard.
//
// TestRekeyCoversEveryKeyedColumn and TestRekeySurfacesAreAllReachableFromTheScanner
// are INVENTORY guards: is this column registered, and does a scanner reach it.
// Both answered yes for notification_channels.config while the sweep was feeding
// base64 TEXT to AES-GCM and writing raw bytes into a base64 column. The column
// was registered. It was scanned. It was also completely broken, and shipping
// it would have destroyed every webhook URL and bot token in the store.
//
// An inventory guard structurally cannot see that, because the defect is not
// "which surfaces exist" but "what shape are the bytes". So this file states the
// ON-DISK CONTRACT of every crypto family as a pair of directions:
//
//	the sweep's READER must accept what the production WRITER produces
//	the production READER must accept what the sweep's WRITER produces
//
// Both directions matter and the second one is the dangerous half: patching only
// the reader makes the sweep run happily and leaves ciphertext the product
// cannot parse, after the original has already been re-encrypted away.
//
// The closures below call the REAL functions on both sides (h.EncryptValue,
// h.encryptColumn, columncrypto.EncryptString, alerts.ChannelDispatcher,
// h.classifyEntryValue, h.urlBlindIndexCandidates, ...), not copies of them, so
// this cannot drift into asserting a private theory of the format.

const (
	formatSampleSecret = "wire-format-sample-value"
	formatSampleURL    = "https://api.example.com/v1/tokens"
	// The channel sample is a real webhook config aimed at a private address, so
	// the production reader (which lives in another package behind an unexported
	// decrypt) can be exercised through the only door it has: a send that the
	// SSRF dial guard refuses by name. See seedChannelHost.
	formatSampleChannel = seedChannel
)

// formatScope is a blind-index scope. Any stable value works; the index is
// scope-keyed, so the read and write sides simply have to agree.
var formatScope = bidxScope("format-guard-user", sql.NullString{})

// wireFormat is one crypto family's on-disk contract.
//
// stored is the column value as it sits in the database (raw bytes are carried
// as a string, which is lossless in Go). nonce is the sibling nonce column for
// the two families that keep it out of band, nil for the self-contained ones.
type wireFormat struct {
	// Sample is the plaintext round-tripped through the contract.
	Sample string
	// Writer and Reader name the PRODUCTION call sites, so the next person can
	// check these closures against the real thing instead of trusting them.
	Writer, Reader string

	// ProductionWrite stores Sample exactly the way the product stores it.
	ProductionWrite func(h *VaultHandler) (stored string, nonce []byte, err error)
	// ProductionRead reads a stored value back the way the product reads it.
	ProductionRead func(h *VaultHandler, stored string, nonce []byte) (string, error)

	// SweepRead is the classification the scanner performs on a stored value.
	SweepRead func(h *VaultHandler, stored string, nonce []byte) (string, keyAge)
	// SweepWrite is the replacement the planner computes for a plaintext.
	SweepWrite func(h *VaultHandler, plain string) (stored string, nonce []byte, err error)
}

var wireFormats = map[rekeyFamily]wireFormat{
	familyVaultValue: {
		Sample: formatSampleSecret,
		Writer: "VaultHandler.EncryptValue, raw bytes into a BLOB (vault.go Create)",
		Reader: "VaultHandler.OpenEntrySecret (vault.go Unlock), through the opaque type",
		ProductionWrite: func(h *VaultHandler) (string, []byte, error) {
			ct, nonce, err := h.EncryptValue([]byte(formatSampleSecret))
			return string(ct), nonce, err
		},
		// This family's plaintext is a secretexit.Plaintext and has no accessor,
		// so both closures assert with EqualsString and hand the SAMPLE back on a
		// match, exactly the way familyBlindIndex and familyRawGCM already do for
		// readers that cannot return the value either. The contract being checked
		// is unchanged: the sweep must read what production wrote, and production
		// must read what the sweep wrote.
		ProductionRead: func(h *VaultHandler, stored string, nonce []byte) (string, error) {
			pt, err := h.openForTest([]byte(stored), nonce)
			if err != nil {
				return "", err
			}
			defer pt.Wipe()
			if !pt.EqualsString(formatSampleSecret) {
				return "", fmt.Errorf("the opened value is not the sample (len %d)", pt.Len())
			}
			return formatSampleSecret, nil
		},
		SweepRead: func(h *VaultHandler, stored string, nonce []byte) (string, keyAge) {
			pt, age := h.classifyEntryValue([]byte(stored), nonce, 2,
				entryOrigin("wire-format-guard", "wire-format-guard"))
			defer pt.Wipe()
			if !pt.EqualsString(formatSampleSecret) {
				return "", age
			}
			return formatSampleSecret, age
		},
		SweepWrite: func(h *VaultHandler, plain string) (string, []byte, error) {
			ct, nonce, err := h.encrypt([]byte(plain))
			return string(ct), nonce, err
		},
	},

	familyVaultColumn: {
		Sample: formatSampleURL,
		Writer: "VaultHandler.encryptColumn, \"enc:v1:\" text (vault.go encryptMetaColumns)",
		Reader: "VaultHandler.decryptColumn (vault.go vaultMetaFrom*Row), for the declared url field",
		ProductionWrite: func(h *VaultHandler) (string, []byte, error) {
			out, err := h.encryptColumn(formatSampleURL)
			return out, nil, err
		},
		ProductionRead: func(h *VaultHandler, stored string, _ []byte) (string, error) {
			return h.decryptColumn(stored, vaultFieldURL)
		},
		SweepRead: func(h *VaultHandler, stored string, _ []byte) (string, keyAge) {
			return h.classifyVaultColumn(stored, vaultFieldURL)
		},
		SweepWrite: func(h *VaultHandler, plain string) (string, []byte, error) {
			out, err := h.encryptColumn(plain)
			return out, nil, err
		},
	},

	familyColumnCrypto: {
		Sample: seedSMTP,
		Writer: "columncrypto.EncryptString, \"tienc:v1:\" text (settings.go, auth.go)",
		Reader: "resolveSMTPPassword (smtp_password.go); decryptTOTPSecret (auth.go) reads the same shape",
		ProductionWrite: func(h *VaultHandler) (string, []byte, error) {
			out, err := columncrypto.EncryptString(seedSMTP, h.keySource)
			return out, nil, err
		},
		ProductionRead: func(h *VaultHandler, stored string, _ []byte) (string, error) {
			return resolveSMTPPassword(stored, h.keySource, previousSourceOf(h))
		},
		SweepRead: func(h *VaultHandler, stored string, _ []byte) (string, keyAge) {
			return h.classifyColumnCrypto(stored, vaultFieldSMTPPassword)
		},
		SweepWrite: func(h *VaultHandler, plain string) (string, []byte, error) {
			out, err := columncrypto.EncryptString(plain, h.keySource)
			return out, nil, err
		},
	},

	// The family that was broken. Its writer base64-encodes and its reader
	// base64-decodes, in a different package, and nothing but this pairing says
	// so.
	familyRawGCM: {
		Sample: formatSampleChannel,
		Writer: "notifications.go Create: base64(EncryptValue) into a TEXT column",
		Reader: "internal/alerts.decryptConfig: base64 decode, then DecryptValue",
		ProductionWrite: func(h *VaultHandler) (string, []byte, error) {
			// Byte-for-byte what notifications.go writes.
			ct, nonce, err := h.EncryptValue([]byte(formatSampleChannel))
			return base64.StdEncoding.EncodeToString(ct), nonce, err
		},
		ProductionRead: func(h *VaultHandler, stored string, nonce []byte) (string, error) {
			// The genuine reader, in its own package, driven through the only
			// entry point it exposes. A refusal naming the sample's host proves
			// the config came out intact; AES-GCM authenticates the whole blob,
			// so the rest of the JSON came with it.
			row := db.GetNotificationChannelRow{
				ID: "wire-format-guard", Name: "wire-format-guard", Type: "webhook",
				Config: stored, ConfigNonce: nonce,
				EncryptionVersion: sql.NullInt64{Int64: 2, Valid: true},
				Events:            alerts.EventTest,
			}
			// queries is nil deliberately: DispatchTest never touches the
			// database, so this exercises the decrypt and send path alone.
			err := alerts.NewChannelDispatcher(context.Background(), nil, h).DispatchTest(row)
			if err == nil {
				return "", fmt.Errorf("the guarded send to %s succeeded, so this assertion proves nothing", seedChannelHost)
			}
			if strings.Contains(err.Error(), seedChannelHost) {
				return formatSampleChannel, nil
			}
			return "", err
		},
		SweepRead: func(h *VaultHandler, stored string, nonce []byte) (string, keyAge) {
			raw, err := decodeRawGCMColumn(stored)
			if err != nil {
				return "", keyAgeUnknown
			}
			pt, age := h.classifyInstanceConfig(raw, nonce, 2)
			return string(pt), age
		},
		SweepWrite: func(h *VaultHandler, plain string) (string, []byte, error) {
			ct, nonce, err := h.encrypt([]byte(plain))
			return encodeRawGCMColumn(ct), nonce, err
		},
	},

	// Not ciphertext: an HMAC. "Reading" it is an equality lookup, so the
	// production reader is the candidate set autofill queries with.
	familyBlindIndex: {
		Sample: formatSampleURL,
		Writer: "VaultHandler.urlBlindIndex (vault.go Create/Update, vault_import.go)",
		Reader: "VaultHandler.urlBlindIndexCandidates, queried by Match (vault.go)",
		ProductionWrite: func(h *VaultHandler) (string, []byte, error) {
			return h.urlBlindIndex(formatScope, formatSampleURL), nil, nil
		},
		ProductionRead: func(h *VaultHandler, stored string, _ []byte) (string, error) {
			for _, candidate := range h.urlBlindIndexCandidates(formatScope, formatSampleURL) {
				if candidate == stored {
					return formatSampleURL, nil
				}
			}
			return "", fmt.Errorf("no index the autofill reader looks up matches the stored one, " +
				"so this entry would silently vanish from autofill with no error anywhere")
		},
		SweepRead: func(h *VaultHandler, stored string, _ []byte) (string, keyAge) {
			want := h.urlBlindIndex(formatScope, formatSampleURL)
			return formatSampleURL, h.classifyBlindIndex(stored, want, formatScope, formatSampleURL)
		},
		SweepWrite: func(h *VaultHandler, plain string) (string, []byte, error) {
			return h.urlBlindIndex(formatScope, plain), nil, nil
		},
	},
}

// TestEveryRekeyFamilyMatchesItsProductionWireFormat is the guard described at
// the top of this file.
func TestEveryRekeyFamilyMatchesItsProductionWireFormat(t *testing.T) {
	dbConn, queries := newRekeyDB(t)
	h := rekeyHandler(dbConn, queries, rekeyNewKey, "")

	for family, wf := range wireFormats {
		t.Run(string(family), func(t *testing.T) {
			// Direction 1: the SWEEP must understand what PRODUCTION wrote.
			//
			// This is the half that made the feature inert: the sweep classified
			// every real channel config as "opens under no configured key", so it
			// refused any store that had ever created one and the status page told
			// the operator to restore a key they never lost.
			stored, nonce, err := wf.ProductionWrite(h)
			if err != nil {
				t.Fatalf("production writer (%s) failed: %v", wf.Writer, err)
			}
			if stored == "" {
				t.Fatalf("production writer (%s) stored nothing; this contract is vacuous", wf.Writer)
			}
			gotPlain, age := wf.SweepRead(h, stored, nonce)
			if age != keyAgeCurrent {
				t.Fatalf(`the sweep does not understand what production writes for family %q.

  production writer: %s
  sweep classified it as: %v (want keyAgeCurrent)

The sweep will report this surface as unreadable on every real store, refuse
with ErrRekeyBlocked, and tell the operator to restore a key nothing is missing.`,
					family, wf.Writer, age)
			}
			if gotPlain != wf.Sample {
				t.Fatalf("family %q: the sweep read %q back from a production write of %q",
					family, gotPlain, wf.Sample)
			}

			// Direction 2: PRODUCTION must understand what the SWEEP wrote.
			//
			// The dangerous half. A sweep that reads correctly and writes a shape
			// the product cannot parse has already re-encrypted the original away,
			// so the damage is irreversible rather than merely blocking.
			swept, sweptNonce, err := wf.SweepWrite(h, wf.Sample)
			if err != nil {
				t.Fatalf("family %q: the sweep could not encode a replacement: %v", family, err)
			}
			readBack, err := wf.ProductionRead(h, swept, sweptNonce)
			if err != nil {
				t.Fatalf(`the product cannot read what the sweep writes for family %q.

  sweep wrote a value the reader rejects: %v
  production reader: %s

This is the irreversible direction: the sweep has already re-encrypted the
original under the new key, so whatever it just stored is the only copy.`,
					family, err, wf.Reader)
			}
			if readBack != wf.Sample {
				t.Fatalf("family %q: production read %q back from a sweep write of %q",
					family, readBack, wf.Sample)
			}
		})
	}
}

// TestEveryRegisteredFamilyHasAWireFormatContract keeps the table above honest.
//
// A new crypto family is exactly the moment this guard has to exist and exactly
// the moment nobody remembers it, so registering a surface in a family with no
// contract fails here rather than on a production store.
func TestEveryRegisteredFamilyHasAWireFormatContract(t *testing.T) {
	inUse := map[rekeyFamily]bool{}
	for _, s := range rekeySurfaces {
		inUse[s.Family] = true
	}
	if len(inUse) == 0 {
		t.Fatal("ABORT: no families found in rekeySurfaces; this guard is matching nothing")
	}

	for family := range inUse {
		wf, ok := wireFormats[family]
		if !ok {
			t.Errorf(`family %q is registered in rekeySurfaces but has no wire-format contract.

Add one to wireFormats in this file naming the PRODUCTION writer and the
PRODUCTION reader for that family, and wiring the closures to the real
functions. Without it, nothing checks that the sweep's idea of the byte layout
matches the product's, and the inventory guards cannot see the difference: they
only ask whether a column is registered and scanned.`, family)
			continue
		}
		if wf.Writer == "" || wf.Reader == "" {
			t.Errorf("family %q has a contract that does not name its production writer and reader", family)
		}
	}
	for family := range wireFormats {
		if !inUse[family] {
			t.Errorf("wireFormats has a contract for family %q, which no registered surface uses; "+
				"drop it so this table keeps meaning something", family)
		}
	}
}
