-- +goose Up
-- +goose StatementBegin
-- An optional private-network connector can enforce additional ingress rules
-- per shared vault. Existing deployments and rows remain reachable exactly as
-- before: standard is both the schema default and the migration value applied
-- to every pre-existing collection.
--
-- Keeping the vocabulary closed in SQLite matters because enforcement reads
-- this column as an authorization input. A typo or an out-of-band write must
-- fail rather than produce a fourth, ambiguously handled access mode.
ALTER TABLE collections
  ADD COLUMN private_access_policy TEXT NOT NULL DEFAULT 'standard'
  CHECK (private_access_policy IN ('standard', 'sensitive_private', 'fully_private'));

-- Activity and capability rows deliberately outlive the collection/entry that
-- produced them. Once a fully-private collection has ever existed, those
-- global audit readers must remain private forever; checking only the current
-- collections would reopen old names after a downgrade or delete. This latch
-- is monotonic and is maintained by SQLite so every writer (including native
-- restore and future maintenance code) gets the same behavior atomically.
INSERT INTO settings (key, value, updated_at)
SELECT 'private_access_audit_ever_fully_private', '1', CURRENT_TIMESTAMP
WHERE EXISTS (
  SELECT 1 FROM collections WHERE private_access_policy = 'fully_private'
)
ON CONFLICT(key) DO UPDATE SET value = '1', updated_at = CURRENT_TIMESTAMP;

CREATE TRIGGER collections_private_access_audit_latch_insert
AFTER INSERT ON collections
WHEN NEW.private_access_policy = 'fully_private'
BEGIN
  INSERT INTO settings (key, value, updated_at)
  VALUES ('private_access_audit_ever_fully_private', '1', CURRENT_TIMESTAMP)
  ON CONFLICT(key) DO UPDATE SET value = '1', updated_at = CURRENT_TIMESTAMP;
END;

CREATE TRIGGER collections_private_access_audit_latch_update
AFTER UPDATE OF private_access_policy ON collections
WHEN NEW.private_access_policy = 'fully_private'
BEGIN
  INSERT INTO settings (key, value, updated_at)
  VALUES ('private_access_audit_ever_fully_private', '1', CURRENT_TIMESTAMP)
  ON CONFLICT(key) DO UPDATE SET value = '1', updated_at = CURRENT_TIMESTAMP;
END;

CREATE TRIGGER private_access_audit_latch_no_delete
BEFORE DELETE ON settings
WHEN OLD.key = 'private_access_audit_ever_fully_private' AND OLD.value = '1'
BEGIN
  SELECT RAISE(ABORT, 'private access audit latch is monotonic');
END;

CREATE TRIGGER private_access_audit_latch_no_downgrade
BEFORE UPDATE OF value ON settings
WHEN OLD.key = 'private_access_audit_ever_fully_private'
  AND OLD.value = '1'
  AND NEW.value <> '1'
BEGIN
  SELECT RAISE(ABORT, 'private access audit latch is monotonic');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS private_access_audit_latch_no_downgrade;
DROP TRIGGER IF EXISTS private_access_audit_latch_no_delete;
DROP TRIGGER IF EXISTS collections_private_access_audit_latch_update;
DROP TRIGGER IF EXISTS collections_private_access_audit_latch_insert;
DELETE FROM settings WHERE key = 'private_access_audit_ever_fully_private';
ALTER TABLE collections DROP COLUMN private_access_policy;
-- +goose StatementEnd
