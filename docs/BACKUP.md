# Backup and restore

Trustissues stores login credentials, API keys, and TOTP seeds. A backup you
cannot restore, or a key you cannot pair with your backup, is the same as no
backup. Read this whole page once before you rely on it.

Three rules sit above everything else on this page:

1. **Take WAL-safe snapshots.** The database runs in SQLite WAL mode. A plain
   `cp` of `trustissues.db` while the server runs can copy a torn or stale file
   because recent commits live in the `-wal` sidecar until a checkpoint. Always
   use the live WAL-safe `VACUUM INTO` snapshot below, never a naive copy.
2. **Store the backup and `TRUSTISSUES_VAULT_KEY` in separate places.** The
   secret payloads are AES-256-GCM ciphertext, but the file still contains
   sensitive identity/audit metadata and password hashes. Encrypt the whole
   snapshot before it leaves a trusted host, and never store either wrapping
   key or the vault key beside it. Losing the vault key makes the encrypted
   payloads permanently unreadable, with no reset and no recovery.
3. **Do not keep the backups on the database's own disk.** See
   [Where the backups go](#where-the-backups-go). The shipped Compose deploy
   makes this the easy mistake, and it is the difference between surviving a
   lost volume and losing the vault and every copy of it at once.

## What is in a backup, and what protects it

A backup is the single SQLite database file. Inside it:

- Secret values, TOTP seeds, notification configs, and rotation targets are
  AES-256-GCM ciphertext (key derived from `TRUSTISSUES_VAULT_KEY`).
- Entry metadata (name, URL, username) is encrypted at rest as well; URL lookups
  go through a keyed blind index, so a stolen file does not reveal which sites
  the team has entries for, only that some equal-URL entries exist.
- Account password hashes are Argon2id, one-way and key-independent. Normal
  startup still requires the vault key/keyring that opens the encrypted store;
  the boot gate refuses a mismatched key before users can log in.
- Account identifiers, recent login-attempt email/IP data, and portions of the
  append-only activity trail (including IP address and user agent) are plaintext
  operational metadata. Password hashes also permit offline guessing attempts.

Without the vault key, a thief cannot directly open the encrypted secret
payloads. They can still learn operational metadata and attack password hashes,
so the database is a sensitive backup, not a public ciphertext blob. Key
separation limits the worst-case impact; whole-file encryption protects the
remaining contents.

## Taking a backup

Use the helper script (WAL-safe, writes the snapshot mode 0600):

```bash
TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/backup.sh /secure/backups
```

The destination can come from the environment instead of the command line,
which is how the systemd unit configures itself:

```bash
TRUSTISSUES_DATA_DIR=/opt/trustissues/data \
TRUSTISSUES_BACKUP_DIR=/secure/backups ./scripts/backup.sh
```

An explicit argument still wins over `TRUSTISSUES_BACKUP_DIR`.

That path is the **bare-metal** layout. On the Docker Compose deploy the data
lives in the named volume `trustissues_trustissues_data`, mounted at `/app/data`
in the container (host source
`/var/lib/docker/volumes/trustissues_trustissues_data/_data`, root-only). Running
this script host-side against that path needs root and a host `sqlite3`; the
in-container command in the next section is the normal route.

It runs `VACUUM INTO` under the hood:

```bash
sqlite3 "$TRUSTISSUES_DATA_DIR/trustissues.db" \
  "VACUUM INTO '/secure/backups/trustissues-$(date -u +%Y%m%dT%H%M%SZ).db'"
chmod 600 /secure/backups/trustissues-*.db
```

This produces a consistent single-file snapshot while the server keeps running.
Do not improvise with `cp`, `rsync`, or a volume tar of a live database.

**Use `VACUUM INTO`, not `.backup`.** These were described here as
interchangeable and they are not. Both are WAL-safe, but `.backup` drives the
online backup API, which copies the database *page by page* including pages on
the freelist. SQLite does not zero what it frees, so a deleted row's bytes and
the pre-`UPDATE` bytes of a rewritten row sit in those free pages verbatim, and
`.backup` copies them faithfully into the snapshot. On a fixture whose rows were
deleted and whose survivors were re-encrypted, the `.backup` snapshot held 1176
greppable copies of the cleartext; `VACUUM INTO` held zero, because it rebuilds
the file from the live tables instead of copying pages.

That matters most for exactly the data this product encrypts. Migration 00040
sealed vault entry names at rest by rewriting every row, which *freed* the old
cleartext rather than overwriting it. Snapshots are the artifact that leaves the
host, and `THREAT-MODEL.md` treats off-host storage as less trusted than the
host, so a snapshot carrying cleartext in its freelist cancels the sealing it was
supposed to be protected by.

`VACUUM INTO` costs nothing to switch to: it also needs no downtime and takes no
write lock (it runs in a read transaction), the output is smaller than the
source, and it needs SQLite 3.27+ (2019). It is not the same thing as a bare
`VACUUM`, which rebuilds the *live* file in place and does block writers; see
[Compacting the live database](#compacting-the-live-database).

### Docker Compose deploy

The data lives in the named volume, mounted at `/app/data` in the container. Run
the same backup inside the container:

```bash
docker compose exec trustissues \
  sqlite3 /app/data/trustissues.db "VACUUM INTO '/app/data/backup.db'"
docker compose cp trustissues:/app/data/backup.db \
  "/secure/backups/trustissues-$(date -u +%Y%m%dT%H%M%SZ).db"
docker compose exec trustissues rm -f /app/data/backup.db
chmod 600 /secure/backups/trustissues-*.db
```

(`VACUUM INTO` here for the same reason as above, and note it refuses to write to
a path that already exists: if a previous run died before the `rm -f`, clear
`/app/data/backup.db` first.)

Alternatively stop the container first (`docker compose stop`), then tar the
volume: with the writer stopped the on-disk file is consistent. The live
`VACUUM INTO` snapshot is preferred because it needs no downtime and does not
copy freelist residue.

### Encrypt the whole file before off-site storage

The secret columns are already ciphertext, but the file still contains account
and audit metadata, the schema, and Argon2 hashes. Before shipping a backup to
third-party or off-host storage, wrap the snapshot with `age` or `gpg`, and keep
that wrapping key distinct from the vault key too:

```bash
age -r age1... -o trustissues-YYYY.db.age trustissues-YYYY.db && rm trustissues-YYYY.db
```

Note that `scripts/prune-backups.sh` will not touch a file wrapped like this:
retention only ever deletes files named exactly
`trustissues-YYYYMMDDTHHMMSSZ.db`. If you wrap snapshots for off-site storage,
you are responsible for expiring the wrapped copies.

## Compacting the live database

**This is a one-time operator action on any database that predates migration
00040, and nothing runs it for you.**

Switching backups to `VACUUM INTO` makes every *new snapshot* clean, and the
server now opens the database with `PRAGMA secure_delete=ON` so that pages are
zeroed *as they are freed* from that point on. Neither of those touches bytes
that were already free when they shipped. `secure_delete` is forward-looking by
definition, and a snapshot being clean says nothing about the file it was taken
from. On an instance that has been running since before 00040, the live
`trustissues.db` still holds pre-encryption vault entry names in its free pages
until something rebuilds the file.

Rebuilding it is `VACUUM`, and unlike `VACUUM INTO` it is a real production
operation:

- it takes a write lock and blocks writers for the whole rebuild,
- it needs roughly **2x the database size** in free space, because SQLite builds
  the new file before dropping the old one,
- it cannot run inside a transaction.

So it ships as a script you run deliberately, in a window, rather than as
something the server does at boot. **Do not put it on a timer.**

```bash
# 1. See what is there. This is the DEFAULT: it reports and changes nothing.
TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/compact-db.sh

# 2. Take a snapshot first.
TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/backup.sh /secure/backups

# 3. Stop the writer. Strongly recommended, not enforced: a VACUUM against a
#    running server works, it just blocks every write until it finishes.
systemctl stop trustissues        # or: docker compose stop

# 4. Rebuild.
TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/compact-db.sh --yes

# 5. Start it again, then reveal one secret in the UI. That is the only thing
#    that proves the vault key still decrypts what came out the other side.
systemctl start trustissues
```

The dry run prints the database size, the journal mode, the free space
available against the free space required, and the size of the freelist, which
is the residue measured rather than guessed:

```
free pages:    71 x 4096B = 284.0 KB of unreachable old content (read immutable)
```

The trailing note says how that number was obtained, and it is worth
understanding, because this line used to lie. Reading the freelist of a WAL
database is not a read-only operation: WAL keeps its index in a `-shm` sidecar,
a read-only connection cannot create one, and the sidecar is gone as soon as
nothing has the database open -- which is precisely what step 3 above tells you
to arrange. The probe therefore failed on a stopped server, the failure was
swallowed, and the line read `0 x 4096B = 0 B` followed by "the freelist is
already empty, so there is no residue to destroy" on databases that were full
of it. The page size was real, which is what made the zero convincing.

It now tries a read-only open, falls back to an immutable one (which needs no
`-shm`, and is only used when there is no `-wal` sidecar whose contents it would
have to ignore), and **fails loudly rather than reporting a zero it did not
measure**. If you see

```
error: could not read the page counters out of /opt/trustissues/data/trustissues.db.
```

the database has a `-wal` but no `-shm`, i.e. the writer did not shut down
cleanly. Start the server once and stop it again, then re-run.

The script checkpoints the WAL before and after the rebuild. Both matter: in WAL
mode a committed page lives in the `-wal` sidecar until a checkpoint, those
frames are page images, and a frame written before 00040 can still hold a
cleartext name. The post-`VACUUM` checkpoint truncates the sidecar to zero
length so the rebuild is not undone by the file sitting next to it. If it warns
that a checkpoint did not complete, a clean shutdown also checkpoints; stop the
server and run it again.

Two things the compaction does **not** do, and the script says so on the way
out:

- **Snapshots taken before it still contain the cleartext.** They were page
  copies of the old file. Expire them with `scripts/prune-backups.sh`, and if
  they were replicated off-host, expire them there too. Nothing here can reach
  them.
- **The freed bytes are unlinked, not shredded, at the filesystem layer.** On a
  normal disk that is the end of it. If your threat model includes someone
  imaging the raw block device, that is a full-disk-encryption question and this
  script is not the answer to it.

## Where the backups go

`backup.sh` **refuses** a destination that is the live data directory itself. A
snapshot named `trustissues-<stamp>.db` never collides with `trustissues.db`, so
it looks harmless, but retention pruning would then be an automated `rm` running
inside the directory that holds the only live copy of the vault.

`prune-backups.sh` refuses it too, and that is the copy of the check that
matters, because it is the script that does the deleting. It refuses when the
directory you pass is `TRUSTISSUES_DATA_DIR`, and also when the directory simply
holds a file named `trustissues.db`, which covers a hand-run invocation with no
environment set. Both comparisons use physical paths, so reaching the data
directory through a symlink is not a way around either script.

It **warns**, and continues, when the destination is merely on the same
filesystem as the database:

```
warning: /opt/trustissues/data/backups is on the same filesystem as the database (/dev/sda1).
         A full disk or a lost volume takes the database AND every backup
         of it at once. Point TRUSTISSUES_BACKUP_DIR at separate storage.
```

Take that warning seriously. **Today the shipped Compose deploy puts the
database in the named volume `trustissues_trustissues_data` and offers no second
volume**, so the obvious destination is a subdirectory of the same volume. That
arrangement survives "I deleted a row" and nothing else: one full disk, one
corrupt filesystem, one `docker volume rm` destroys the database and every
snapshot of it in the same instant. It also means the backups inherit the
database's fate during a host loss, which is the scenario this whole document
exists for.

Point `TRUSTISSUES_BACKUP_DIR` at a separate disk, a mounted NAS, or a directory
you replicate off the box, and treat the on-box copy as the fast-restore tier
only. Neither the scripts nor the units replicate anything off the host; that is
still yours to arrange.

The backup directory should be mode `0700` and owned by the user the schedule
runs as (root, for the shipped units). `deploy/systemd/install.sh` creates it
that way. The snapshots themselves are written `0600`.

## Scheduling it

Two supported ways. Both run the same scripts.

### systemd (preferred)

```bash
sudo ./deploy/systemd/install.sh
sudo $EDITOR /etc/trustissues/backup.env      # data dir, backup dir, SMTP
sudo ./deploy/systemd/install.sh --test-alert # prove alerting BEFORE you need it
sudo systemctl start trustissues-backup.service
sudo systemctl start trustissues-restore-drill.service
systemctl list-timers 'trustissues-*'
```

What that installs:

| file | what it is |
|------|------------|
| `trustissues-backup.service` | one-shot: `backup.sh --prune` |
| `trustissues-backup.timer` | daily 03:20 UTC, `RandomizedDelaySec=20m`, `Persistent=true` |
| `trustissues-restore-drill.service` | one-shot: `restore-drill.sh` |
| `trustissues-restore-drill.timer` | Mondays 04:10 UTC, same jitter and persistence |
| `trustissues-backup-alert@.service` | templated alerter, started by `OnFailure=` on both |
| `/etc/trustissues/backup.env` | the one config file all of the above read, mode 0600 |

`install.sh` copies the scripts to `/opt/trustissues/scripts/` and the alerter to
`/opt/trustissues/deploy/systemd/`, which is where the units look for them. Set
`TRUSTISSUES_INSTALL_DIR` to change that. `--uninstall` removes the units and
leaves your configuration and your snapshots alone.

Retention is opted into on the `ExecStart=` line (`backup.sh --prune`), not with
`Environment=TRUSTISSUES_BACKUP_PRUNE=1`. systemd lets an `EnvironmentFile=`
override an `Environment=`, so while it was a variable, one
`TRUSTISSUES_BACKUP_PRUNE=0` in `backup.env` switched retention off on the only
path that fills the disk and nothing failed. Setting that variable in
`backup.env` does not affect the scheduled run either way; the flag wins.

`./deploy/systemd/install.sh --root DIR` rehearses the whole install into a
throwaway tree instead of `/`, needs no root, starts nothing, and is what
`scripts/test-backup-restore.sh` runs on every suite run. Use it if you want to
see what the installer would do before you let it near `/etc`.

`Persistent=true` matters: a backup missed because the box was off runs at the
next boot instead of silently not existing.

Both units run as **root** and read the data directory directly from the host.
On the Compose deploy that means `TRUSTISSUES_DATA_DIR` is the volume's host
path, `/var/lib/docker/volumes/trustissues_trustissues_data/_data`, which is
root-only, and the host needs `sqlite3` installed. **The units do not run
anything inside the container.** If you would rather back up from inside the
container, keep using the `docker compose exec` recipe above and schedule that
yourself; the timer does not do it for you.

The sandbox on both units sets `ProtectHome=read-only`, so the backup
destination must not be under `/home` or `/root`. `install.sh` warns if you
pick one.

### cron (fallback)

For hosts without systemd. `install.sh` refuses to run there, so the file
placement it would have done is the first two commands here:

```bash
# the cron jobs use absolute paths, so put the scripts where they expect them
sudo install -d -m 0755 /opt/trustissues/scripts /opt/trustissues/deploy/systemd
sudo install -m 0755 scripts/backup.sh scripts/restore.sh scripts/prune-backups.sh \
        scripts/restore-drill.sh scripts/snapshot-lib.sh /opt/trustissues/scripts/
sudo install -m 0755 deploy/systemd/trustissues-backup-alert.sh \
        /opt/trustissues/deploy/systemd/

sudo install -m 0600 -D deploy/systemd/backup.env.example /etc/trustissues/backup.env
sudo $EDITOR /etc/trustissues/backup.env
sudo install -d -m 0700 /var/backups/trustissues      # or wherever you pointed it
sudo install -m 0644 deploy/cron/trustissues-backup.cron /etc/cron.d/trustissues-backup
```

`snapshot-lib.sh` is not optional: `prune-backups.sh` and `restore-drill.sh`
source it for snapshot-name parsing and both refuse to start without it. If you
change the paths, change them in `/etc/cron.d/trustissues-backup` too.

That ships both jobs, at the same times as the timers. Read the comments in the
file before changing it: cron's `PATH` usually does not include `sqlite3`, cron
only mails you output if the box runs an MTA (most do not, which is why every
line ends in an explicit `|| trustissues-backup-alert.sh`), and a `%` inside a
cron command means a newline.

The cron path has no journal, so it points `TRUSTISSUES_ALERT_LOG` at the log
file it redirects into and the alerter quotes that instead.

## Retention

`scripts/prune-backups.sh` keeps:

- the newest snapshot of each of the last **N distinct UTC days**
  (`TRUSTISSUES_BACKUP_KEEP_DAILY`, default 7), and
- the newest snapshot of each of the last **M distinct 7-day blocks**
  (`TRUSTISSUES_BACKUP_KEEP_WEEKLY`, default 4).

The two policies are independent and overlap freely, so the defaults hold about
ten files: a week at daily granularity plus a month of coarser history, for
roughly ten times the size of the database.

The blocks are 7-day periods counted from the Unix epoch, so they run Thursday
to Wednesday. They are **not** ISO calendar weeks. Snapshot times are read from
the file name, never from the mtime, so a snapshot copied off the box or pulled
back from cold storage still ages from the moment it was taken.

```bash
./scripts/prune-backups.sh --dry-run /secure/backups     # show, delete nothing
TRUSTISSUES_BACKUP_KEEP_DAILY=14 ./scripts/prune-backups.sh /secure/backups
```

Run automatically after each scheduled backup, because the unit runs
`backup.sh --prune`. A **hand-run** `backup.sh` never prunes unless you pass
`--prune` (or set `TRUSTISSUES_BACKUP_PRUNE=1`); it prints a one-line reminder
instead. The flag beats the variable in both directions, so `--no-prune` also
works on a host whose `backup.env` turns retention on. This is deliberate:
the hand-run script is what you reach for right before doing something
frightening, and it should not delete history as a side effect.

What it refuses and what it protects:

- Only files named exactly `trustissues-YYYYMMDDTHHMMSSZ.db` are candidates.
  Your notes, `.age`-wrapped copies and unrelated `.db` files are invisible to
  it.
- `KEEP_DAILY=0` together with `KEEP_WEEKLY=0` is refused rather than obeyed. So
  is a non-numeric value. A blank value falls back to the default.
- The newest snapshot is never deleted, whatever the policy arithmetic says.
- Stale `trustissues-*.db.part` files older than a day are removed. Those are
  partial copies left behind when a backup was SIGKILLed, they can be as large
  as the whole database, and no retention rule would ever match them. A `.part`
  from the last 24 hours is left alone in case a backup is in flight.

If you raise the backup frequency in the timer, raise these numbers in the same
change. An hourly timer with `KEEP_DAILY=7` keeps seven files and throws away
161 a week.

## Failure alerting

Both units carry `OnFailure=trustissues-backup-alert@%n.service`, which emails
the failed unit's name, a likely cause, and the last 40 journal lines.

Three details that are not optional, because each of them has silently disabled
alerting on this estate before:

- `OnFailure=` lives in `[Unit]`. In `[Service]` systemd logs
  `Unknown key name 'OnFailure' in section 'Service', ignoring` and drops it,
  and nothing else ever tells you.
- The unit named by `OnFailure=` has to exist. `install.sh` resolves every
  `OnFailure=` target to a file before enabling anything, and
  `scripts/test-backup-restore.sh` asserts both of these.
- It belongs on the **service**, not on the timer. `OnFailure=` on a `.timer`
  fires when the timer itself fails to start, which is not what a failed backup
  does: a backup that exits 2 fails `trustissues-backup.service` and leaves the
  timer active and green. `install.sh` used to demand `OnFailure=` on the timers
  too and aborted the whole install over it; it now requires instead that every
  timer triggers a unit which carries one.
- Use **port 587 with STARTTLS**, not 465. The alerter passes `--ssl-reqd` so
  587 is still encrypted. Several providers block outbound 465, and a send to
  `smtps://host:465` does not error, it **hangs**, which looks exactly like the
  alerter doing nothing. The send is wrapped in `timeout 60` so that becomes a
  logged failure inside a minute either way.

The alerter never exits non-zero, so a broken alerter cannot make systemd page
about the pager. It also exits quietly when `/etc/trustissues/backup.env` is
missing or any required value is blank, which means **an empty `SMTP_PASS` is
the same as no alerting at all**. Send yourself a test:

```bash
sudo ./deploy/systemd/install.sh --test-alert
```

Failures are also appended to `/var/log/trustissues-backup-failures.log`
regardless of whether the mail got out.

## Proving it restores: the drill

A backup nobody has restored is a hypothesis. Everything else on this page
checks that a file was *written*. `scripts/restore-drill.sh` checks that it can
be *read back*:

```bash
TRUSTISSUES_DATA_DIR=/opt/trustissues/data \
  ./scripts/restore-drill.sh /secure/backups
```

It takes the newest snapshot by the timestamp in its name and:

1. fails if that snapshot is older than `TRUSTISSUES_DRILL_MAX_AGE_HOURS`
   (default 48, `0` disables). This is what catches a timer that quietly stopped
   weeks ago, which no other check on this page can see. The value must be
   **digits only**: `48h` or `two` is refused with exit 2, not ignored. It used
   to be ignored, and `[ 5000 -gt 48h ]` is simply false, so a one-character typo
   in this file skipped the freshness check and the drill printed `DRILL PASSED`
   on a snapshot of any age.
   A snapshot stamped in the **future** also fails here, for the same reason: it
   sorts newest forever, its age is negative, and it would hide every real
   snapshot from the check while retention protects it from ever being pruned.
2. runs the real `scripts/restore.sh` into a fresh `mktemp -d`, so the drill
   exercises the actual restore code rather than a `cp`. To be exact about which
   half: the drill always drives the **native** branch (`restore.sh <snapshot>`
   into a directory), never `restore.sh --compose`, because a drill must not go
   near the running deploy's volume. On the Compose deploy the weekly drill
   therefore proves the snapshot restores and the rows survive, and does **not**
   prove the container-side steps of your real restore. Those (`docker compose
   create` on a fresh host, the chown, the writability check) are covered by
   `scripts/test-backup-restore.sh` against a throwaway compose project on any
   machine with docker. It refuses to proceed
   if that directory is anywhere inside the live data directory (compared by
   physical path, so a symlink is not a way around it). If `TRUSTISSUES_DATA_DIR`
   is set but does not resolve to a directory, the drill stops with exit 2 and
   says so, rather than reporting a containment refusal that never happened.
3. asserts on the restored copy: `PRAGMA integrity_check` is `ok`, the table
   count matches the snapshot, the `vault_entries` row count matches, no
   `-wal`/`-shm` sidecars were left behind, and the file is mode `0600`.
4. checks a **canary row** survived the round trip, in this priority order:
   - `TRUSTISSUES_DRILL_CANARY_SQL` plus `TRUSTISSUES_DRILL_CANARY_EXPECT`, if
     you set them,
   - otherwise the oldest entry in the **live** vault, read `-readonly` (oldest,
     because anything newer than the snapshot legitimately will not be in it),
   - otherwise the oldest entry in the snapshot itself,
   - and if the vault is empty, a schema-only check, named as such in the output.

   The output always says which one ran.

Exit codes: `0` passed, `1` the drill FAILED, `2` it could not run (no
`sqlite3`, no such directory). The throwaway copy is deleted on exit unless you
set `TRUSTISSUES_DRILL_KEEP=1`.

The drill never writes to the live database and never starts the server.

## Storing the vault key

Keep `TRUSTISSUES_VAULT_KEY` in a password manager or secret store that is
physically and logically separate from wherever the database backups live.

- Not in the same object-storage bucket as the backups.
- Not in the same repo, the same `.env` you also archive, or the same disk image.
- Back it up once, deliberately. It never changes on its own. If you DO rotate it
  (see "Rotating the vault key" in `../SECURITY.md`), keep the old key in the
  live process until the re-encrypt sweep reports the store fully current. Then
  remove it from the live process, but retain it offline, mapped to every
  pre-sweep snapshot, until those snapshots expire. A snapshot taken while the
  sweep is in flight can contain rows under both keys and must be restored with
  the full current+previous keyring. Guard every retained key like a root
  password; expire snapshots and their retired keys together.

If you only ever remember one sentence from this page: the backup and the key
must never be recoverable from the same place.

## Restoring

1. Provision the host with the keyring the snapshot was taken under. A snapshot
   outside a rotation normally needs its matching `TRUSTISSUES_VAULT_KEY`; a
   snapshot taken during a rotation can require both that current key and
   `TRUSTISSUES_VAULT_KEY_PREVIOUS`. Retrieve them from your separate key store.
   Without the matching key material, normal startup refuses and no tool can
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

   Or use the helper, which does all of step 3 in one command and refuses if the
   service is still running:

   ```bash
   TRUSTISSUES_DATA_DIR=/opt/trustissues/data ./scripts/restore.sh /secure/backups/trustissues-....db
   ```

   **Docker Compose.** The data is inside a named volume, so the sidecars cannot
   be removed with `docker compose exec`: that needs a RUNNING container, and
   starting it is exactly what makes SQLite recover the OLD tail over your
   restored file. Use a one-shot container instead, or the helper:

   ```bash
   docker compose stop trustissues
   ./scripts/restore.sh --compose /secure/backups/trustissues-....db
   docker compose up -d trustissues
   ```

   The equivalent by hand, if you prefer:

   ```bash
   docker compose stop trustissues
   docker compose cp ./trustissues.db trustissues:/app/data/trustissues.db
   # --user 0 is required: `docker compose cp` writes the file as root, while the
   # service runs as the unprivileged `trustissues` user. Without the chown the
   # app starts and then crash-loops on its first write.
   docker compose run --rm --no-deps --user 0 --entrypoint sh trustissues -c \
     'rm -f /app/data/trustissues.db-wal /app/data/trustissues.db-shm \
      && chown trustissues:trustissues /app/data/trustissues.db \
      && chmod 600 /app/data/trustissues.db'
   # Confirm the service user can write it before starting:
   docker compose run --rm --no-deps --entrypoint sh trustissues -c 'test -w /app/data/trustissues.db'
   docker compose up -d trustissues
   ```

   Do NOT `docker compose up` or `exec` before the sidecars are gone.
4. Start the server with the same key and the same `TRUSTISSUES_DATA_DIR`.
   Embedded migrations run automatically and bring an older schema forward.
5. **Verify before you trust it.** Log in, unlock the vault, and reveal at least
   one secret. If startup refuses its key check, stop, do not overwrite the good
   snapshot, and recover the matching key/keyring. Do not use
   `TRUSTISSUES_ALLOW_KEY_MISMATCH=1`: that explicit destructive escape hatch can
   boot into unreadable data and is not a restore procedure.

## What a restore does not fix

- A lost vault key. There is no partial recovery once the matching key material
  is actually gone. Merely configuring the wrong key is reversible: normal boot
  refuses, and putting the correct key/keyring back restores access.
- Tampering you did not notice before the backup. Restore gives you the state as
  of the snapshot, nothing more.

## What is still manual

Being exact about this, because the point of the schedule is that you can stop
thinking about it, and anything not on the list below you still have to do.

- **Off-host copies.** Nothing here replicates a snapshot off the machine. The
  timer, the retention policy and the drill all operate on one directory on one
  host. Arrange your own `restic`, `rclone`, `rsync` or object-storage job, and
  point it at `TRUSTISSUES_BACKUP_DIR`.
- **The vault key.** It is not in any snapshot and must not be in
  `/etc/trustissues/backup.env`. Back it up once, deliberately, somewhere the
  snapshots are not.
- **Backing up from inside the container.** The units run `sqlite3` on the host
  against the volume's `_data` path. The `docker compose exec` recipe above
  still works, but nothing schedules it for you.
- **A `trustissues backup` subcommand.** Still deferred (`../DEFERRED.md`
  section (d)). The scripts need `sqlite3` on `PATH`; the server binary does not
  take the snapshot itself.
- **Verifying a restore under the real vault key.** The drill proves the file
  restores and the rows are there. It cannot prove the ciphertext decrypts,
  because it never has the key. Only starting the server against a restored
  database and revealing one secret proves that, which is step 5 of
  [Restoring](#restoring).
- **Watching the drill itself.** The chain is one link long. A dead backup timer
  is caught by the drill (the freshness check); a dead *drill* timer is caught by
  nothing, because a timer that never fires produces no failure and no mail. It
  looks identical to a quiet month. Put `systemctl list-timers 'trustissues-*'`
  in whatever you already read weekly, or have your monitoring alert on the
  absence of the drill's journal line, and check `NEXT`/`LAST` after any host
  upgrade.

## Testing this yourself

`scripts/test-backup-restore.sh` runs every guard on this page against real
SQLite files in a temp directory: truncated snapshots, foreign databases,
corrupted-in-place snapshots, retention keeping exactly the right files, a drill
against a stale snapshot, and the systemd traps (`OnFailure=` section, the alert
unit existing, the alerter's timeout and TLS). It also **runs the installer**
(`install.sh --root <tempdir>`) and asserts it completes, enables both timers and
seeds the config, because the version of it that refused its own `.timer` file
was caught by nothing until somebody ran it. It needs `sqlite3` and nothing else,
and it never touches a real deployment.

Where docker is available it additionally drives `restore.sh --compose` against a
throwaway compose project with a real named volume and a real unprivileged image
user: a fresh-host restore with no container yet, a re-restore over a stale WAL,
and the refusal when the service user cannot write the restored file. Without
docker those cases are reported as `SKIP` in the summary, and the summary says
how many, because a green run that quietly proved less is the failure mode this
whole page is about.

```bash
./scripts/test-backup-restore.sh
```
