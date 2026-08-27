package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/trustissues/internal/alerts"
	"github.com/bright-interaction/trustissues/internal/db"
	_ "github.com/mattn/go-sqlite3"
)

// The "Notify only" target must reach a real channel, through the real dispatcher.
//
// This exists because the FIRST guard for this fix was vacuous and an ablation proved
// it. rotation_contract_test.go swaps dispatchRotationSuccess for a recorder, so it
// asserts the rotation core calls the hook; gutting the real implementation behind that
// hook, and disabling the event, both passed it clean. The seam introduced for
// testability was exactly where the remaining bug could live.
//
// Same lesson this codebase keeps producing in new costumes: a guard cannot verify the
// thing it stubs. So this one drives dispatchRotationSuccessReal into a real SQLite
// database with the real notification_channels DDL and a real enabled channel.
//
// A slog channel rather than a webhook because ChannelDispatcher.client is package
// private (the alerts test swaps it from inside the package) and the SSRF guard refuses
// loopback. sendSlog needs no network, and delivery is what is under test, not egress.
func TestNotifyOnlyTargetActuallyReachesAChannel(t *testing.T) {
	q := newNotifyChannelDB(t, defaultChannelEvents)

	rec := &slogRecorder{done: make(chan string, 8)}
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dispatchRotationSuccessReal(context.Background(), q, nil,
		"entry-standard", "Prod DB password", "rotated, no delivery targets configured")

	select {
	case got := <-rec.done:
		if !strings.Contains(got, "Prod DB password") {
			t.Errorf("a notification was sent but not about the rotated secret: %s", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a rotation success reached NO notification channel.\n" +
			"'Notify only' transmits nothing by design, so the notification IS the whole " +
			"feature: the credential rotates, the predecessor is revoked, and the person who " +
			"asked to be told hears nothing while the log records a clean success.")
	}
}

// The default event set a new channel is created with must include the success event.
//
// Seeding with defaultChannelEvents verbatim above is deliberate: if that constant ever
// drops vault.rotation_succeeded, every channel an operator creates through the UI
// silently stops subscribing and the notify target is a no-op again, with nothing else
// in the suite noticing. This asserts the same constant is also accepted as valid, so
// the two lists cannot drift apart.
func TestSuccessEventIsSubscribedByDefaultAndValid(t *testing.T) {
	if !strings.Contains(defaultChannelEvents, alerts.EventRotationSucceeded) {
		t.Errorf("defaultChannelEvents (%q) does not include %q, so a new channel does not "+
			"subscribe and 'Notify only' notifies nobody", defaultChannelEvents, alerts.EventRotationSucceeded)
	}
	if !validChannelEvents[alerts.EventRotationSucceeded] {
		t.Errorf("%q is not an accepted channel event, so an operator cannot subscribe to it "+
			"even deliberately", alerts.EventRotationSucceeded)
	}
}

// slogRecorder captures the first record the slog channel emits.
type slogRecorder struct {
	mu   sync.Mutex
	done chan string
}

func (r *slogRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *slogRecorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *slogRecorder) WithGroup(string) slog.Handler            { return r }

func (r *slogRecorder) Handle(_ context.Context, rec slog.Record) error {
	var sb strings.Builder
	sb.WriteString(rec.Message)
	rec.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	line := sb.String()
	if !strings.Contains(line, "trustissues alert") {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case r.done <- line:
	default:
	}
	return nil
}

// newNotifyChannelDB builds a real database with one enabled slog channel.
func newNotifyChannelDB(t *testing.T, events string) *db.Queries {
	t.Helper()
	conn, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "notify.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ddl, err := os.ReadFile(filepath.Join("..", "database", "migrations", "00006_notification_channels.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	stmt := string(ddl)
	if i := strings.Index(stmt, "-- +goose Down"); i > 0 {
		stmt = stmt[:i]
	}
	for _, marker := range []string{"-- +goose Up", "-- +goose StatementBegin", "-- +goose StatementEnd"} {
		stmt = strings.ReplaceAll(stmt, marker, "")
	}
	if _, err := conn.Exec(stmt); err != nil {
		t.Fatalf("apply notification_channels DDL: %v", err)
	}
	if _, err := conn.Exec(
		`INSERT INTO notification_channels (id, name, type, config, events, enabled)
		 VALUES ('ch1', 'ops log', 'slog', '{}', ?, 1)`, events); err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	// Rotation notification dispatch now resolves the entry's collection policy
	// before releasing even its name to an external channel. Keep this delivery
	// fixture representative by providing a real standard-policy entry instead
	// of bypassing that fail-closed lookup with an empty ID.
	if _, err := conn.Exec(`
		CREATE TABLE collections (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			private_access_policy TEXT NOT NULL DEFAULT 'standard',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE vault_entries (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			secret_owner_user_id TEXT NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			encrypted_value BLOB NOT NULL DEFAULT X'',
			nonce BLOB NOT NULL DEFAULT X'',
			encryption_version INTEGER NOT NULL DEFAULT 2,
			collection_id TEXT,
			custom_fields TEXT NOT NULL DEFAULT '[]',
			destination_patterns TEXT NOT NULL DEFAULT '[]',
			provider TEXT,
			provider_meta TEXT,
			rotation_targets TEXT,
			rotation_log TEXT,
			last_rotated_at DATETIME,
			last_rotation_error TEXT,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO vault_entries (id, user_id, secret_owner_user_id, collection_id)
		VALUES ('entry-standard', 'fixture-user', 'fixture-user', NULL);
		INSERT INTO collections (id, private_access_policy)
		VALUES ('collection-sensitive', 'sensitive_private'),
		       ('collection-full', 'fully_private');
		INSERT INTO vault_entries (id, user_id, secret_owner_user_id, collection_id)
		VALUES ('entry-sensitive', 'fixture-user', 'fixture-user', 'collection-sensitive'),
		       ('entry-full', 'fixture-user', 'fixture-user', 'collection-full');
	`); err != nil {
		t.Fatalf("seed standard vault entry: %v", err)
	}

	q := db.New(conn)
	// Guard the fixture: with zero enabled channels every assertion above would
	// pass for the wrong reason.
	rows, err := q.ListEnabledNotificationChannels(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("ABORT: fixture has %d enabled channels (err=%v); the test would be vacuous",
			len(rows), err)
	}
	return q
}

func TestExternalNotificationMetadataHonoursCollectionPolicy(t *testing.T) {
	q := newNotifyChannelDB(t, defaultChannelEvents)
	ctx := context.Background()

	for _, tc := range []struct {
		entry string
		want  bool
	}{
		{entry: "entry-standard", want: true},
		{entry: "entry-sensitive", want: true},
		{entry: "entry-full", want: false},
		{entry: "missing-entry", want: false},
	} {
		if got := entryAllowsExternalNotificationMetadata(ctx, q, tc.entry); got != tc.want {
			t.Errorf("entryAllowsExternalNotificationMetadata(%q) = %v, want %v", tc.entry, got, tc.want)
		}
	}
}

// TestQueuedNotificationRechecksPolicyBeforeDelivery closes the asynchronous
// queue race: the entry is allowed when rotation decides to notify, then its
// collection becomes fully_private while Dispatch is still preparing the
// channel. The delivery goroutine must observe the promotion before emitting
// even the entry name.
func TestQueuedNotificationRechecksPolicyBeforeDelivery(t *testing.T) {
	q := newNotifyChannelDB(t, defaultChannelEvents)
	ctx := context.Background()
	if !entryAllowsExternalNotificationMetadata(ctx, q, "entry-sensitive") {
		t.Fatal("fixture entry must initially permit external metadata")
	}

	// Force Dispatch to pause after its caller's initial policy check but before
	// it creates the delivery goroutine. Channel config decryption is outside a
	// DB transaction, so the collection can be promoted while it is paused.
	if err := q.RekeyNotificationChannelConfig(ctx, db.RekeyNotificationChannelConfigParams{
		Config:            base64.StdEncoding.EncodeToString([]byte("blocked-fixture")),
		ConfigNonce:       []byte{1},
		EncryptionVersion: sql.NullInt64{Int64: 1, Valid: true},
		ID:                "ch1",
	}); err != nil {
		t.Fatalf("mark notification config encrypted: %v", err)
	}

	decryptEntered := make(chan struct{})
	releaseDecrypt := make(chan struct{})
	decrypter := &blockingNotificationDecrypter{
		entered: decryptEntered,
		release: releaseDecrypt,
	}

	logs := &notificationRaceLogRecorder{
		suppressed: make(chan struct{}, 1),
		delivered:  make(chan string, 1),
	}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(logs))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	dispatchReturned := make(chan struct{})
	go func() {
		defer close(dispatchReturned)
		dispatchRotationSuccessReal(ctx, q, decrypter,
			"entry-sensitive", "Client signing key", "rotated successfully")
	}()

	select {
	case <-decryptEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch never reached the controlled pre-delivery boundary")
	}

	if _, err := q.Handle().ExecContext(ctx,
		`UPDATE collections SET private_access_policy = 'fully_private' WHERE id = 'collection-sensitive'`); err != nil {
		t.Fatalf("promote collection while notification is queued: %v", err)
	}
	if entryAllowsExternalNotificationMetadata(ctx, q, "entry-sensitive") {
		t.Fatal("promotion did not take effect; the race assertion would be vacuous")
	}
	close(releaseDecrypt)

	select {
	case payload := <-logs.delivered:
		t.Fatalf("queued notification leaked after fully_private promotion: %s", payload)
	case <-logs.suppressed:
	case <-time.After(5 * time.Second):
		t.Fatal("queued notification neither delivered nor reported policy suppression")
	}

	select {
	case <-dispatchReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not return after releasing channel preparation")
	}
	select {
	case payload := <-logs.delivered:
		t.Fatalf("queued notification leaked after suppression: %s", payload)
	default:
	}
}

type blockingNotificationDecrypter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (d *blockingNotificationDecrypter) DecryptInstanceConfig(_ []byte, _ []byte, _ int) ([]byte, error) {
	d.once.Do(func() { close(d.entered) })
	<-d.release
	return []byte("{}"), nil
}

type notificationRaceLogRecorder struct {
	suppressed chan struct{}
	delivered  chan string
}

func (r *notificationRaceLogRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *notificationRaceLogRecorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *notificationRaceLogRecorder) WithGroup(string) slog.Handler            { return r }

func (r *notificationRaceLogRecorder) Handle(_ context.Context, rec slog.Record) error {
	switch rec.Message {
	case "channel dispatcher: notification suppressed by delivery policy":
		select {
		case r.suppressed <- struct{}{}:
		default:
		}
	case "trustissues alert":
		var line strings.Builder
		line.WriteString(rec.Message)
		rec.Attrs(func(attr slog.Attr) bool {
			line.WriteString(" " + attr.Key + "=" + attr.Value.String())
			return true
		})
		select {
		case r.delivered <- line.String():
		default:
		}
	}
	return nil
}
