# Backup and restore

Trustissues stores login credentials, API keys, and TOTP seeds. A backup you
cannot restore, or a key you cannot pair with your backup, is the same as no
backup. Read this whole page once before you rely on it.

Two rules sit above everything else on this page:

1. **Take WAL-safe snapshots.** The database runs in SQLite WAL mode. A plain
   `cp` of `trustissues.db` while the server runs can copy a torn or stale file
   because recent commits live in the `-wal` sidecar until a checkpoint. Always
   use the online backup below, never a naive copy.
2. **Store the backup and `TRUSTISSUES_VAULT_KEY` in separate places.** The
   backup is AES-256-GCM ciphertext and is safe at rest without the key. That is
   the whole point. If the backup and the key ever sit together, you have thrown
   the encryption away. Losing the key makes every backup permanently
   unreadable, with no reset and no recovery.

## What is in a backup, and what protects it

A backup is the single SQLite database file. Inside it:

- Secret values, TOTP seeds, notification configs, and rotation targets are
  AES-256-GCM ciphertext (key derived from `TRUSTISSUES_VAULT_KEY`).
- Entry metadata (name, URL, username) is encrypted at rest as well; URL lookups
  go through a keyed blind index, so a stolen file does not reveal which sites
  the team has entries for, only that some equal-URL entries exist.
- Account password hashes are Argon2id. They are one-way and key-independent, so
  a restore under a different vault key still lets people log in, but every
  secret comes back as `[decryption error]`.

So the file is useless to a thief who does not also have the vault key. That is
exactly why the key lives somewhere else.

## Taking a backup

Use the helper script (WAL-safe, writes the snapshot mode 0600):

```bash
TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/backup.sh /secure/backups
```

It runs SQLite's online backup API under the hood:

```bash
sqlite3 "$TRUSTISSUES_DATA_DIR/trustissues.db" \
  ".backup '/secure/backups/trustissues-$(date -u +%Y%m%dT%H%M%SZ).db'"
chmod 600 /secure/backups/trustissues-*.db
```

`.backup` produces a consistent single-file snapshot while the server keeps
running. `VACUUM INTO '<dest>'` is an equally valid WAL-safe alternative and also
compacts the file. Do not improvise with `cp`, `rsync`, or a volume tar of a live
database.

### Docker Compose deploy

The data lives in the named volume, mounted at `/app/data` in the container. Run
the same backup inside the container:

```bash
docker compose exec trustissues \
  sqlite3 /app/data/trustissues.db ".backup '/app/data/backup.db'"
docker compose cp trustissues:/app/data/backup.db \
  "/secure/backups/trustissues-$(date -u +%Y%m%dT%H%M%SZ).db"
docker compose exec trustissues rm -f /app/data/backup.db
chmod 600 /secure/backups/trustissues-*.db
```

Alternatively stop the container first (`docker compose stop`), then tar the
volume: with the writer stopped the on-disk file is consistent. The online
backup is preferred because it needs no downtime.

### Optional: encrypt the whole file for off-site storage

The secret columns are already ciphertext, but the file still contains the
schema and Argon2 hashes. If you ship backups to third-party storage, wrap the
snapshot with `age` or `gpg` for defense in depth, and keep that wrapping key
distinct from the vault key too:

```bash
age -r age1... -o trustissues-YYYY.db.age trustissues-YYYY.db && rm trustissues-YYYY.db
```

## Storing the vault key

Keep `TRUSTISSUES_VAULT_KEY` in a password manager or secret store that is
physically and logically separate from wherever the database backups live.

- Not in the same object-storage bucket as the backups.
- Not in the same repo, the same `.env` you also archive, or the same disk image.
- Back it up once, deliberately. It never changes on its own, and there is no
  rotation path in this build (see `../DEFERRED.md`), so a single safe copy is
  enough. Guard it like a root password.

If you only ever remember one sentence from this page: the backup and the key
must never be recoverable from the same place.

## Restoring

1. Provision the host with the **same** `TRUSTISSUES_VAULT_KEY` the backup was
   taken under. Retrieve it from your separate key store. Without it the restore
   is pointless: every secret returns `[decryption error]` and no tool can
   recover the plaintext.
2. Stop Trustissues if it is running.
3. Put the snapshot in place as `trustissues.db` in the data directory, and
   remove any stale WAL sidecars so SQLite opens the restored file cleanly:

   ```bash
   cp /secure/backups/trustissues-YYYYMMDDT...Z.db "$TRUSTISSUES_DATA_DIR/trustissues.db"
   rm -f "$TRUSTISSUES_DATA_DIR/trustissues.db-wal" \
         "$TRUSTISSUES_DATA_DIR/trustissues.db-shm"
   chmod 600 "$TRUSTISSUES_DATA_DIR/trustissues.db"
   ```

   For the Compose deploy, copy the file into the volume (`docker compose cp
   ./trustissues.db trustissues:/app/data/trustissues.db`) while the container is
   stopped.
4. Start the server with the same key and the same `TRUSTISSUES_DATA_DIR`.
   Embedded migrations run automatically and bring an older schema forward.
5. **Verify before you trust it.** Log in, unlock the vault, and reveal at least
   one secret. If it comes back in cleartext, the key and the backup match. If it
   comes back `[decryption error]`, you restored under the wrong key. Stop, do
   not overwrite your good backup, and find the correct key.

## What a restore does not fix

- A wrong or lost vault key. There is no partial recovery: one wrong key means
  every secret is gone. This is by design (server-side crypto with the key held
  only in the environment).
- Tampering you did not notice before the backup. Restore gives you the state as
  of the snapshot, nothing more.

Automated and scheduled backups, and a built-in `trustissues backup` subcommand,
are deferred to a later phase (see `../DEFERRED.md`). Until then, run the script
above from cron or a systemd timer and rotate old snapshots yourself.
