package database

import (
	"context"
	"database/sql"
	"net/mail"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	querydb "github.com/bright-interaction/trustissues/internal/db"
	"github.com/bright-interaction/trustissues/internal/emailidentity"
	"github.com/pressly/goose/v3"
)

const canonicalEmailIdentityVersion = 46

func openBeforeCanonicalEmailMigration(t *testing.T, name string) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".db")
	conn, err := sql.Open("sqlite3", "file:"+path+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.UpTo(conn, "migrations", canonicalEmailIdentityVersion-1); err != nil {
		t.Fatalf("up to pre-canonical schema: %v", err)
	}
	return conn
}

func TestCanonicalEmailIdentityMigrationRewritesEveryIdentityRowWithoutMergingHistory(t *testing.T) {
	conn := openBeforeCanonicalEmailMigration(t, "canonicalize")

	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"unicode-user", "  ÜSER@EXÄMPLE.TEST ", "hash", "user")
	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"ascii-user", " Client@Example.COM ", "hash", "user")
	mustExec(t, conn,
		`INSERT INTO collections (id, name, created_by) VALUES (?, ?, ?)`,
		"canonical-collection", "Canonical", "unicode-user")
	mustExec(t, conn,
		`INSERT INTO invitations (id, code, code_hash, email, target_role, expires_at)
		 VALUES (?, ?, ?, ?, ?, datetime('now', '+1 day'))`,
		"mixed-invite", "sealed-code", "code-hash", " Client@Example.COM ", "vault_only")
	for _, email := range []string{" Client@Example.COM ", "client@example.com"} {
		mustExec(t, conn,
			`INSERT INTO login_attempts (email, ip_address, success, scope) VALUES (?, ?, 0, 'password_login')`,
			email, "203.0.113.8")
	}
	mustExec(t, conn,
		`INSERT INTO collection_invitations (collection_id, email, role, invited_by)
		 VALUES (?, ?, ?, ?)`,
		"canonical-collection", "  SEAT@EXÄMPLE.TEST ", "viewer", "unicode-user")

	if err := goose.UpTo(conn, "migrations", canonicalEmailIdentityVersion); err != nil {
		t.Fatalf("apply canonical identity migration: %v", err)
	}

	assertEmail := func(query, want string, args ...any) {
		t.Helper()
		var got string
		if err := conn.QueryRow(query, args...).Scan(&got); err != nil {
			t.Fatalf("read canonical email: %v", err)
		}
		if got != want {
			t.Fatalf("canonical email = %q, want %q", got, want)
		}
	}
	assertEmail(`SELECT email FROM users WHERE id = ?`, "üser@xn--exmple-cua.test", "unicode-user")
	assertEmail(`SELECT email FROM invitations WHERE id = ?`, "client@example.com", "mixed-invite")
	assertEmail(`SELECT email FROM collection_invitations WHERE collection_id = ?`, "seat@xn--exmple-cua.test", "canonical-collection")

	rows, err := conn.Query(`SELECT email FROM login_attempts ORDER BY id`)
	if err != nil {
		t.Fatalf("list login attempts: %v", err)
	}
	defer rows.Close()
	var attempts []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			t.Fatalf("scan login attempt: %v", err)
		}
		attempts = append(attempts, email)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate login attempts: %v", err)
	}
	if len(attempts) != 2 || attempts[0] != "client@example.com" || attempts[1] != "client@example.com" {
		t.Fatalf("login attempt history was lost or not canonicalized: %q", attempts)
	}

	// The permanent expression indexes catch case/space variants from a direct
	// SQL writer for ASCII addresses. Unicode safety comes from the Go migration
	// and request canonicalizer because SQLite lower() is ASCII-only.
	if _, err := conn.Exec(
		`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"ascii-variant", " CLIENT@EXAMPLE.COM ", "hash", "user",
	); err == nil {
		t.Fatal("canonical users index accepted an ASCII case/space duplicate")
	}
	mustExec(t, conn,
		`INSERT INTO collection_invitations (collection_id, email, role) VALUES (?, ?, ?)`,
		"canonical-collection", "one@example.com", "viewer")
	if _, err := conn.Exec(
		`INSERT INTO collection_invitations (collection_id, email, role) VALUES (?, ?, ?)`,
		"canonical-collection", " ONE@EXAMPLE.COM ", "editor",
	); err == nil {
		t.Fatal("canonical collection-seat index accepted an ASCII case/space duplicate")
	}

	if err := goose.DownTo(conn, "migrations", canonicalEmailIdentityVersion-1); err != nil {
		t.Fatalf("roll canonical migration back: %v", err)
	}
	if err := goose.UpTo(conn, "migrations", canonicalEmailIdentityVersion); err != nil {
		t.Fatalf("re-apply canonical migration: %v", err)
	}
}

func TestCanonicalEmailIdentityMigrationFailsAtomicallyOnUserCollision(t *testing.T) {
	for _, tc := range []struct {
		name   string
		emails []string
	}{
		{name: "ASCII", emails: []string{"Alice@Example.COM", " alice@example.com "}},
		{name: "Unicode", emails: []string{"Üser@Example.COM", " üser@example.com "}},
		{name: "Display_name", emails: []string{"Victim <victim@example.com>", "victim@example.com"}},
		{name: "Unicode_NFC", emails: []string{"Üser@example.com", "U\u0308ser@example.com"}},
		{name: "IDNA_U-label_A-label", emails: []string{"User@bücher.example", "user@xn--bcher-kva.example"}},
		{name: "Terminal_root_dot", emails: []string{"Root@example.com.", "root@example.com"}},
		{name: "Quoted_embedded_at", emails: []string{`"Foo@Bar"@example.com`, `"foo@bar"@EXAMPLE.COM`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := openBeforeCanonicalEmailMigration(t, "user-collision-"+strings.ToLower(tc.name))
			for i, email := range tc.emails {
				mustExec(t, conn,
					`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
					"collision-user-"+string(rune('a'+i)), email, "hash", "user")
			}
			mustExec(t, conn,
				`INSERT INTO invitations (id, code, code_hash, email, target_role, expires_at)
				 VALUES ('unchanged-invite', 'sealed', 'collision-hash', ' INVITE@EXAMPLE.COM ', 'user', datetime('now', '+1 day'))`)

			if err := goose.UpTo(conn, "migrations", canonicalEmailIdentityVersion); err == nil {
				t.Fatal("migration silently merged two existing users with one canonical identity")
			}

			var version int64
			var err error
			version, err = goose.GetDBVersion(conn)
			if err != nil {
				t.Fatalf("read goose version: %v", err)
			}
			if version != canonicalEmailIdentityVersion-1 {
				t.Fatalf("failed migration advanced schema to %d, want %d", version, canonicalEmailIdentityVersion-1)
			}
			rows, err := conn.Query(`SELECT email FROM users ORDER BY id`)
			if err != nil {
				t.Fatalf("read users after failure: %v", err)
			}
			var got []string
			for rows.Next() {
				var email string
				if err := rows.Scan(&email); err != nil {
					rows.Close()
					t.Fatalf("scan user after failure: %v", err)
				}
				got = append(got, email)
			}
			rows.Close()
			sort.Strings(got)
			want := append([]string(nil), tc.emails...)
			sort.Strings(want)
			if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("failed migration partially rewrote users: got %q want %q", got, want)
			}
			assertUnchanged := ""
			if err := conn.QueryRow(`SELECT email FROM invitations WHERE id='unchanged-invite'`).Scan(&assertUnchanged); err != nil {
				t.Fatalf("read invitation after failed migration: %v", err)
			}
			if assertUnchanged != " INVITE@EXAMPLE.COM " {
				t.Fatalf("failed migration partially rewrote another table: %q", assertUnchanged)
			}
		})
	}
}

func TestCanonicalEmailIdentityMigrationPreservesQuotedLocalPartForLoginLookup(t *testing.T) {
	conn := openBeforeCanonicalEmailMigration(t, "quoted-login")
	ctx := context.Background()

	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"quoted-user", `"Root@Client"@BÜCHER.DE.`, "surviving-hash", "user")
	mustExec(t, conn,
		`INSERT INTO login_attempts (email, ip_address, success, scope) VALUES (?, ?, 1, 'password_login')`,
		`Client <"ROOT@CLIENT"@xn--bcher-kva.de>`, "203.0.113.27")

	if err := goose.UpTo(conn, "migrations", canonicalEmailIdentityVersion); err != nil {
		t.Fatalf("apply canonical identity migration: %v", err)
	}

	const want = `"root@client"@xn--bcher-kva.de`
	var stored string
	if err := conn.QueryRow(`SELECT email FROM users WHERE id='quoted-user'`).Scan(&stored); err != nil {
		t.Fatalf("read migrated quoted identity: %v", err)
	}
	if stored != want {
		t.Fatalf("migrated quoted identity = %q, want %q", stored, want)
	}
	if _, err := mail.ParseAddress(stored); err != nil {
		t.Fatalf("migration stored an invalid quoted addr-spec %q: %v", stored, err)
	}

	lookup, err := emailidentity.CanonicalStrict(`Login <"ROOT@CLIENT"@bücher.de.>`)
	if err != nil {
		t.Fatalf("canonicalize login identity: %v", err)
	}
	user, err := querydb.New(conn).GetUserByEmail(ctx, lookup)
	if err != nil {
		t.Fatalf("valid migrated account no longer resolves at login lookup: %v", err)
	}
	if user.ID != "quoted-user" || user.PasswordHash != "surviving-hash" {
		t.Fatalf("migrated login lookup returned %+v", user)
	}

	var attempt string
	if err := conn.QueryRow(`SELECT email FROM login_attempts`).Scan(&attempt); err != nil {
		t.Fatalf("read migrated login attempt: %v", err)
	}
	if attempt != want {
		t.Fatalf("login attempt identity = %q, want %q", attempt, want)
	}
}

func TestCanonicalEmailIdentityMigrationRejectsInvalidIDNAAtomicallyWithRowContext(t *testing.T) {
	conn := openBeforeCanonicalEmailMigration(t, "invalid-idna")

	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"invalid-domain-user", "Person@-example.com", "hash", "user")
	mustExec(t, conn,
		`INSERT INTO invitations (id, code, code_hash, email, target_role, expires_at)
		 VALUES ('unchanged-invite', 'sealed', 'invalid-idna-hash', ' INVITE@EXAMPLE.COM ', 'user', datetime('now', '+1 day'))`)

	migrationErr := goose.UpTo(conn, "migrations", canonicalEmailIdentityVersion)
	if migrationErr == nil {
		t.Fatal("migration accepted an existing identity with an invalid IDNA domain")
	}
	for _, context := range []string{"users", "invalid-domain-user", "invalid email identity", "IDNA"} {
		if !strings.Contains(migrationErr.Error(), context) {
			t.Fatalf("migration error %q does not identify %q", migrationErr, context)
		}
	}

	version, err := goose.GetDBVersion(conn)
	if err != nil {
		t.Fatalf("read goose version: %v", err)
	}
	if version != canonicalEmailIdentityVersion-1 {
		t.Fatalf("failed migration advanced schema to %d, want %d", version, canonicalEmailIdentityVersion-1)
	}
	var userEmail, invitationEmail string
	if err := conn.QueryRow(`SELECT email FROM users WHERE id='invalid-domain-user'`).Scan(&userEmail); err != nil {
		t.Fatalf("read invalid user after failure: %v", err)
	}
	if err := conn.QueryRow(`SELECT email FROM invitations WHERE id='unchanged-invite'`).Scan(&invitationEmail); err != nil {
		t.Fatalf("read invitation after failure: %v", err)
	}
	if userEmail != "Person@-example.com" || invitationEmail != " INVITE@EXAMPLE.COM " {
		t.Fatalf("failed migration partially rewrote identities: user=%q invitation=%q", userEmail, invitationEmail)
	}
}

func TestCanonicalEmailIdentityMigrationFailsAtomicallyOnCollectionSeatCollision(t *testing.T) {
	conn := openBeforeCanonicalEmailMigration(t, "seat-collision")
	mustExec(t, conn,
		`INSERT INTO users (id, email, password_hash, role) VALUES ('seat-owner', 'owner@example.com', 'hash', 'user')`)
	mustExec(t, conn,
		`INSERT INTO collections (id, name, created_by) VALUES ('seat-coll', 'Seats', 'seat-owner')`)
	for _, seat := range []struct{ email, role string }{
		{email: "Client Contact <Client@Example.COM>", role: "viewer"},
		{email: " client@example.com ", role: "manager"},
	} {
		mustExec(t, conn,
			`INSERT INTO collection_invitations (collection_id, email, role, invited_by)
			 VALUES ('seat-coll', ?, ?, 'seat-owner')`, seat.email, seat.role)
	}
	mustExec(t, conn,
		`INSERT INTO login_attempts (email, ip_address, success, scope)
		 VALUES (' LOGIN@EXAMPLE.COM ', '203.0.113.9', 0, 'password_login')`)

	if err := goose.UpTo(conn, "migrations", canonicalEmailIdentityVersion); err == nil {
		t.Fatal("migration silently merged collection invitations with distinct roles")
	}

	var seats int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM collection_invitations WHERE collection_id='seat-coll'`).Scan(&seats); err != nil {
		t.Fatalf("count seats after failure: %v", err)
	}
	if seats != 2 {
		t.Fatalf("failed migration merged/deleted collection security state: %d seats", seats)
	}
	var attemptEmail string
	if err := conn.QueryRow(`SELECT email FROM login_attempts`).Scan(&attemptEmail); err != nil {
		t.Fatalf("read login attempt after failure: %v", err)
	}
	if attemptEmail != " LOGIN@EXAMPLE.COM " {
		t.Fatalf("failed migration partially rewrote login security state: %q", attemptEmail)
	}
}

func TestCanonicalEmailIdentityMigrationMaterializesMatchingSeatsWithoutOverwritingMemberships(t *testing.T) {
	conn := openBeforeCanonicalEmailMigration(t, "materialize-seats")
	ctx := context.Background()

	for _, user := range []struct {
		id    string
		email string
	}{
		{id: "seat-owner", email: "owner@example.com"},
		{id: "seat-user", email: " Mixed.Seat@Example.COM "},
	} {
		mustExec(t, conn,
			`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, 'hash', 'user')`,
			user.id, user.email)
	}
	for _, collection := range []string{"missing-membership", "accepted-membership", "pending-membership"} {
		mustExec(t, conn,
			`INSERT INTO collections (id, name, created_by) VALUES (?, ?, 'seat-owner')`,
			collection, collection)
		mustExec(t, conn,
			`INSERT INTO collection_invitations
			 (collection_id, email, role, invited_by, created_at)
			 VALUES (?, 'Mixed Seat <MIXED.SEAT@Example.COM>', 'viewer', 'seat-owner', '2026-01-02 03:04:05')`,
			collection)
	}
	// An accepted membership is authoritative even if an old seat says viewer
	// and names another inviter.
	mustExec(t, conn,
		`INSERT INTO collection_members
		 (collection_id, user_id, role, added_at, accepted_at, invited_by)
		 VALUES ('accepted-membership', 'seat-user', 'manager',
		         '2025-01-01 00:00:00', '2025-01-02 00:00:00', 'seat-user')`)
	// A pending membership is equally authoritative: migration repair must not
	// turn a stale seat into a role/inviter update.
	mustExec(t, conn,
		`INSERT INTO collection_members
		 (collection_id, user_id, role, added_at, accepted_at, invited_by)
		 VALUES ('pending-membership', 'seat-user', 'editor',
		         '2025-02-01 00:00:00', NULL, 'seat-user')`)

	if err := goose.UpTo(conn, "migrations", canonicalEmailIdentityVersion); err != nil {
		t.Fatalf("apply canonical identity migration: %v", err)
	}

	var canonicalUser, canonicalSeat string
	if err := conn.QueryRow(`SELECT email FROM users WHERE id='seat-user'`).Scan(&canonicalUser); err != nil {
		t.Fatalf("read canonical user: %v", err)
	}
	if err := conn.QueryRow(`SELECT email FROM collection_invitations WHERE collection_id='missing-membership'`).Scan(&canonicalSeat); err != nil {
		t.Fatalf("read canonical seat: %v", err)
	}
	if canonicalUser != "mixed.seat@example.com" || canonicalSeat != canonicalUser {
		t.Fatalf("canonical identities did not meet: user=%q seat=%q", canonicalUser, canonicalSeat)
	}

	type membershipState struct {
		role       string
		addedAt    string
		acceptedAt sql.NullString
		invitedBy  sql.NullString
	}
	readMembership := func(collection string) membershipState {
		t.Helper()
		var state membershipState
		if err := conn.QueryRow(`
			SELECT role, added_at, accepted_at, invited_by
			FROM collection_members
			WHERE collection_id = ? AND user_id = 'seat-user'`, collection,
		).Scan(&state.role, &state.addedAt, &state.acceptedAt, &state.invitedBy); err != nil {
			t.Fatalf("read %s membership: %v", collection, err)
		}
		return state
	}

	materialized := readMembership("missing-membership")
	if materialized.role != "viewer" || materialized.acceptedAt.Valid ||
		!materialized.invitedBy.Valid || materialized.invitedBy.String != "seat-owner" ||
		materialized.addedAt != "2026-01-02T03:04:05Z" && materialized.addedAt != "2026-01-02 03:04:05" {
		t.Fatalf("materialized membership did not preserve the seat: %+v", materialized)
	}

	accepted := readMembership("accepted-membership")
	if accepted.role != "manager" || !accepted.acceptedAt.Valid ||
		!accepted.invitedBy.Valid || accepted.invitedBy.String != "seat-user" {
		t.Fatalf("migration overwrote accepted membership: %+v", accepted)
	}
	pending := readMembership("pending-membership")
	if pending.role != "editor" || pending.acceptedAt.Valid ||
		!pending.invitedBy.Valid || pending.invitedBy.String != "seat-user" {
		t.Fatalf("migration overwrote pending membership: %+v", pending)
	}

	// The repaired row is not just present: it is the exact pending membership
	// consumed by the normal acceptance query.
	queries := querydb.New(conn)
	result, err := queries.AcceptCollectionInvite(ctx, querydb.AcceptCollectionInviteParams{
		CollectionID: "missing-membership", UserID: "seat-user",
	})
	if err != nil {
		t.Fatalf("accept materialized membership: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		t.Fatalf("accepted rows = %d, err=%v; want exactly one", rows, err)
	}
	claimed, err := queries.GetCollectionMembership(ctx, querydb.GetCollectionMembershipParams{
		CollectionID: "missing-membership", UserID: "seat-user",
	})
	if err != nil {
		t.Fatalf("read accepted materialized membership: %v", err)
	}
	if !claimed.AcceptedAt.Valid {
		t.Fatal("materialized membership remained unclaimable after acceptance")
	}
}
