//go:build rehearsal

// Production-rehearsal probe. NOT part of the shipped test suite: it only builds
// under -tags rehearsal, and it exists to answer one question against a COPY of
// the live vault, namely whether every row that opened before still opens after.
//
// It never prints a plaintext. Names and values leave this file only as the
// first 12 hex characters of their SHA-256, which is enough to compare a row
// against itself across two runs and nothing else.
package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/bright-interaction/trustissues/internal/config"
	"github.com/bright-interaction/trustissues/internal/database"
	"github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/secretexit"
	"github.com/bright-interaction/trustissues/internal/vaultfield"
)

func fp(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])[:12]
}

type colState struct {
	Stored string `json:"stored"`
	Opens  bool   `json:"opens"`
	SHA    string `json:"sha"`
	Err    string `json:"err,omitempty"`
}

type rowState struct {
	ID          string   `json:"id"`
	UserID      string   `json:"user_id"`
	EncVersion  int      `json:"enc_version"`
	ValueOpens  bool     `json:"value_opens"`
	ValueLen    int      `json:"value_len"`
	ValueSHA    string   `json:"value_sha"`
	ValueErr    string   `json:"value_err,omitempty"`
	CipherSHA   string   `json:"cipher_sha"`
	Name        colState `json:"name"`
	NameBidx    string   `json:"name_bidx_stored_sha"`
	WantBidx    string   `json:"name_bidx_want_sha"`
	BidxMatches bool     `json:"name_bidx_matches"`
	URL         colState `json:"url"`
	Username    colState `json:"username"`
	Notes       colState `json:"notes"`
	Category    colState `json:"category"`
}

func classify(h *VaultHandler, stored string, f vaultfield.Field) colState {
	cs := colState{}
	switch {
	case stored == "":
		cs.Stored = "empty"
		cs.Opens = true
		cs.SHA = fp(nil)
		return cs
	case len(stored) > len(vaultColumnEncPrefix) && stored[:len(vaultColumnEncPrefix)] == vaultColumnEncPrefix:
		cs.Stored = "sealed"
	default:
		cs.Stored = "cleartext"
	}
	plain, err := h.decryptColumn(stored, f)
	if err != nil {
		cs.Err = err.Error()
		return cs
	}
	cs.Opens = true
	cs.SHA = fp([]byte(plain))
	return cs
}

// TestRehearsalProbe dumps the readable state of every vault_entries row in the
// database named by TI_REHEARSE_DB, as JSON, on stdout.
func TestRehearsalProbe(t *testing.T) {
	dir := os.Getenv("TI_REHEARSE_DIR")
	if dir == "" {
		t.Skip("TI_REHEARSE_DIR not set")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	conn, err := database.Connect(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	q := db.New(conn)
	h := NewVaultHandler(conn, q, cfg)

	rows, err := conn.Query(`SELECT id, user_id, name, encrypted_value, nonce,
	  COALESCE(encryption_version,2), name_bidx, COALESCE(url,''), COALESCE(username,''),
	  COALESCE(notes,''), COALESCE(category,'') FROM vault_entries ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var out []rowState
	for rows.Next() {
		var r rowState
		var ct, nonce []byte
		var name, bidx, url, username, notes, category string
		if err := rows.Scan(&r.ID, &r.UserID, &name, &ct, &nonce, &r.EncVersion, &bidx,
			&url, &username, &notes, &category); err != nil {
			t.Fatalf("scan: %v", err)
		}
		r.CipherSHA = fp(append(append([]byte{}, ct...), nonce...))

		pt, _, verr := h.openEntrySecretWithKeyAge(ct, nonce, r.EncVersion, entryOrigin(r.ID, "rehearsal"))
		if verr != nil {
			r.ValueErr = verr.Error()
		} else {
			r.ValueOpens = true
			r.ValueLen = pt.Len()
			_, b, xerr := secretexit.Exit(context.Background(), pt,
				secretexit.ToNowhere("rehearsal fingerprint"))
			if xerr != nil {
				r.ValueErr = "exit: " + xerr.Error()
			} else {
				r.ValueSHA = fp(b)
			}
		}

		r.Name = classify(h, name, vaultFieldName)
		r.NameBidx = fp([]byte(bidx))
		if bidx == "" {
			r.NameBidx = "EMPTY"
		}
		if r.Name.Opens {
			plain, _ := h.decryptColumn(name, vaultFieldName)
			want := h.nameBlindIndex(r.UserID, plain)
			if want == "" {
				r.WantBidx = "EMPTY"
			} else {
				r.WantBidx = fp([]byte(want))
			}
			r.BidxMatches = want == bidx
		}
		r.URL = classify(h, url, vaultFieldURL)
		r.Username = classify(h, username, vaultFieldUsername)
		r.Notes = classify(h, notes, vaultFieldNotes)
		r.Category = classify(h, category, vaultFieldCategory)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	buf, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println("REHEARSAL_PROBE_BEGIN")
	fmt.Println(string(buf))
	fmt.Println("REHEARSAL_PROBE_END")
}

// TestRehearsalPlantHostileFixture writes the pre-fix-import collision shape into
// the COPY named by TI_REHEARSE_DIR: one row whose name is already sealed and
// indexed, a second row carrying the SAME name in cleartext with an empty index
// (what the unfixed ImportConfirm left behind), and a third cleartext row with a
// name of its own that must still be sealed after the second one is refused.
//
// It also records whether SQLite will accept the literal "two cleartext rows with
// the same name" state at all, which is the question the fixture's shape answers.
func TestRehearsalPlantHostileFixture(t *testing.T) {
	dir := os.Getenv("TI_REHEARSE_PLANT")
	if dir == "" {
		t.Skip("TI_REHEARSE_PLANT not set")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	conn, err := database.Connect(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	h := NewVaultHandler(conn, db.New(conn), cfg)

	var user string
	var ct, nonce []byte
	if err := conn.QueryRow(`SELECT user_id, encrypted_value, nonce FROM vault_entries
	  ORDER BY id LIMIT 1`).Scan(&user, &ct, &nonce); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	const collide = "ZZ-REHEARSE-COLLIDE"
	const victim = "ZZ-REHEARSE-VICTIM"

	sealed, err := h.encryptColumn(collide)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	ins := func(id, name, bidx, url string) error {
		_, err := conn.Exec(`INSERT INTO vault_entries
		  (id, user_id, name, encrypted_value, nonce, encryption_version, name_bidx, url, url_bidx,
		   secret_owner_user_id, category, notes, username)
		  VALUES (?,?,?,?,?,2,?,?,'',?,'','','')`,
			id, user, name, ct, nonce, bidx, url, user)
		return err
	}

	// H1 first, then the colliding H2, then H3: the backfill reads the table in
	// rowid order, so H3 lands AFTER the row that gets refused. That ordering is
	// the whole point, it is what proves the sweep did not stop.
	if err := ins("f1000000000000000000000000000001", sealed, h.nameBlindIndex(user, collide), ""); err != nil {
		t.Fatalf("H1: %v", err)
	}
	if err := ins("f2000000000000000000000000000002", collide, "", "https://collide.example.test/a"); err != nil {
		t.Fatalf("H2: %v", err)
	}
	if err := ins("f3000000000000000000000000000003", victim, "", "https://victim.example.test/b"); err != nil {
		t.Fatalf("H3: %v", err)
	}

	// The literal ask: a SECOND cleartext row with the same name for the same
	// user. Recorded, not fatal.
	dupErr := ins("f4000000000000000000000000000004", collide, "", "")
	fmt.Printf("REHEARSAL_PLANT user=%s h1_sealed_bidx_set h2_cleartext_bidx_empty h3_cleartext_bidx_empty "+
		"second_cleartext_dup_insert=%v\n", user, dupErr)
}
