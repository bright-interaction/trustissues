# Deferred to Phase 2

These are known, deliberately-scoped-out items. Each is safe to defer for a
single-team v1 because the trust boundary is small (one team, one trusted
operator, no cross-tenant isolation to enforce) and because a documented
operator procedure or an existing control covers the gap in the meantime. None
of them weakens the at-rest encryption or the auth model that ships today.

Each entry lists the design for when it is picked up. See `THREAT-MODEL.md`
(residual risks R1..R7) and the `notes/` hardening records for the evidence
behind these.

---

## (a) Master-key (VAULT_KEY) rotation path

**SHIPPED.** Kept here as the record of what was built and where it deviated
from this design. Operator procedure: `SECURITY.md`, "Rotating the vault key".
Code: `internal/handlers/vault_rekey.go` (registry + sweep),
`vault_rekey_api.go` (endpoints), `Settings -> Encryption` in the frontend.

What landed against the four design points:

1. **Done.** `TRUSTISSUES_VAULT_KEY_PREVIOUS` is optional and read-only: every
   decrypt path tries the current key then the previous one
   (`columncrypto.DecryptStringAny`, `VaultHandler.previous`), and no encrypt
   path ever touches it. That asymmetry means ordinary edits converge the store
   on the current key by themselves and the sweep only has to finish the rows
   nobody touched. The boot gate (`VerifyVaultKey`) accepts the ring too, which
   is what makes rotation reachable at all: without it the first boot after a
   key change is refused before the operator can run anything.
2. **Done, and wider than this list.** The sweep covers sixteen surfaces, not
   the six named here. The three the original list missed are the ones worth
   remembering: `vault_entries.custom_fields` (explicitly allowed to hold secret
   values), `invitations.code`, and `url_bidx` / `alias_url_bidx`. The blind
   indexes are the sharpest omission, because they are HMACs rather than
   ciphertext: a stale one does not fail to decrypt, it stops matching, so
   browser autofill silently returns nothing with no error anywhere. Autofill
   now also looks up under both keys while a rotation is configured, so the
   window is covered even before the sweep runs.
   Conversely, `capability` and `service-identity` secrets turned out NOT to be
   surfaces: the capability signing key is HKDF-derived and signs 5-minute
   in-memory tokens (a rotation just invalidates in-flight ones), and both
   `service_identities.key_hash` and `api_keys.key_hash` are one-way hashes with
   no plaintext to re-seal.
3. **Deliberately NOT done.** No per-row key id was added. Trial decryption
   under the keyring answers "which key opens this row" authoritatively, and a
   stored key id would be a second source of truth that can disagree with the
   bytes it describes. Every recent data-loss bug here has that shape (a
   declared property nothing enforces; a boot probe that understood one of three
   crypto families; a version filter that excluded the rows it was meant to
   check). Resumability is preserved without it: "needs conversion" is
   recomputed from the data on every run, so the sweep is idempotent and a
   crashed one is fixed by running it again.
4. **Done.** The sweep plans every replacement in memory first, refuses outright
   if any marked ciphertext opens under neither key (`ErrRekeyBlocked`, nothing
   written), writes inside one transaction, then re-scans INSIDE that
   transaction and rolls back unless every surface reports current. That
   re-scan is what turns "the sweep says it covered everything" into "the sweep
   proved it", and it is the thing that would catch a future surface someone
   registers but forgets to convert.

**Prerequisite: was already satisfied.** `columncrypto` grew the `tienc:v1:`
marker and `IsEncrypted` before this work, so plaintext detection is structural.
The sweep still refuses to touch unmarked values it cannot open, and it tries
BOTH keys on unmarked legacy ciphertext, because classifying old-key ciphertext
as plaintext is exactly what produces the irreversible `Enc_new(Enc_old(v))`.

**The guards.** `vault_rekey_coverage_test.go` walks the real migrated schema and
fails when any column is neither a registered keyed surface nor an explicit
entry in `notKeyedColumns` with a stated reason. Adding an encrypted column
without deciding how it rotates does not compile past CI. A second test asserts
every registered surface is actually reached by a scanner, so a surface cannot
sit in the operator's status page reporting zero rows and reading as clean.

Both of those are INVENTORY guards, and inventory was not enough. They both
answered yes for `notification_channels.config` while the sweep was handing
base64 text to AES-GCM (so it refused every store that had ever created a
channel) and writing raw bytes into a base64 column (which would have destroyed
every webhook URL and bot token, after the original had been re-encrypted away).
The column was registered. It was scanned. It was also completely broken.

So `vault_rekey_format_test.go` states each crypto family's on-disk format as a
pair and asserts both directions: the sweep's reader must accept what the
production writer produces, and the production reader must accept what the
sweep's writer produces. The closures call the real functions on both sides,
including the notification reader in `internal/alerts`, so the guard cannot drift
into asserting a private theory of the format. A new family without a contract
fails the test.

`vault_rotation_callsites_test.go` closes the other half: the dual-key helpers
each had a unit test and every one of their CALL SITES was untested, so all four
could be reverted to single-key with the suite still green. It drives `Match`,
`Login` with 2FA, the SMTP test button and the invitation mailer against a
mid-rotation store, and adds source-level guards so a new call site cannot pass
the current key alone or look an entry up under a single blind index.

## (b) Append-only / tamper-evident audit tables

**Today.** `activity_log` has append-only triggers that ABORT any UPDATE or
DELETE. The two tables that record automated agent / service secret access,
`capability_log` and `service_secret_audit`, have no such triggers, so a raw
`sqlite3` session can `DELETE FROM capability_log` freely. The most sensitive
trail (which agent used which secret to which destination) is erasable.

**Design when built.** Add `_no_update` / `_no_delete` BEFORE triggers to both
tables, copying the pattern already in `00003_activity_log.sql`. This is a
migration-only change, no application code.

**Why safe to defer.** Erasing these rows requires direct filesystem + SQLite
access to the database, which in this deployment means the trusted operator or
root on the host. That actor already controls the vault key and can decrypt
everything, so tamper-evidence against them is a hardening nicety, not a
boundary that protects the team from an outside attacker. It matters most once
there is more than one privileged operator, which is a Phase 2 (teams / RBAC)
concern.

## (c) In-product capability_log read endpoint

**Today.** Nothing reads `FROM capability_log`. Human actions are viewable
(`GET /api/activity`) and per-identity fetches are viewable
(`GET /api/service-identities/{id}/audit`), but agent secret-usage is only
reachable through the sqlite CLI.

**Design when built.** Add an admin-only `GET /api/capability/log` (filter by
identity, secret name, destination, time range) and surface it in the admin UI
next to the activity log. The rows already carry everything needed and never
store the secret value, so this is a read handler plus a query, no schema change.
Pair it with (b) so what the endpoint shows cannot be quietly deleted.

**Why safe to defer.** For a single team the capability trail already exists and
is complete; it is just not convenient to read. An admin who needs it can query
the database directly. In-product visibility becomes important when non-technical
teammates need to audit agent secret usage without shell access.

## (d) Automated / scheduled backups

**Mostly SHIPPED.** Scheduling, retention and a restore drill are in the tree.
What remains deferred is narrower than this entry used to describe, so the two
halves are separated below.

**What ships now.**

- `deploy/systemd/`: a backup service + daily timer, a restore-drill service +
  weekly timer, a templated failure alerter, one `backup.env` for all of them,
  and an `install.sh` that installs, verifies the `OnFailure=` chain resolves to
  a real unit, and can fire a test alert. `install.sh --root DIR` rehearses the
  whole install into a throwaway tree, which is how the suite executes it: the
  version that demanded `OnFailure=` on the `.timer` units aborted every real
  install and no test noticed, because nothing ever ran the installer.
- `deploy/cron/trustissues-backup.cron`: the same two jobs for hosts without
  systemd, each with explicit failure alerting because cron's own reporting
  needs an MTA nobody has.
- `scripts/prune-backups.sh`: keep N daily / M weekly (defaults 7 and 4), refuse
  a keep-nothing or non-numeric policy, refuse to run inside the live data
  directory at all, clean stale `.part` files.
- `scripts/restore-drill.sh`: restore the newest snapshot through the real
  `restore.sh` into a throwaway directory, fail on a stale (or future-stamped)
  snapshot, refuse a non-numeric freshness limit rather than ignoring it, and
  check a named row survived the round trip.
- `scripts/backup.sh`: destination configurable via `TRUSTISSUES_BACKUP_DIR`,
  refuses to write into the live data directory (physical paths, so a symlink is
  not a way around it), warns when the backups share a filesystem with the
  database.
- `scripts/restore.sh --compose`: driven end to end by the suite against a real
  docker daemon (a throwaway compose project, a real named volume, a real
  unprivileged image user), covering the fresh-host `docker compose create`, the
  chown that keeps the app from crash-looping on its first write, and the refusal
  when the service user cannot write what was restored. Those cases SKIP loudly
  on a machine without docker and the summary line says how many skipped.
- Every one of those behaviours has a case in `scripts/test-backup-restore.sh`
  that has been watched to fail without it, with one deliberate exception:
  `prune-backups.sh`'s "the newest snapshot is never a deletion candidate" guard
  is belt-and-braces on top of the bucket arithmetic, so it only fires when that
  arithmetic is already wrong. Deleting the guard keeps the suite green, which is
  the honest state of it. The ablation specs are in
  `scripts/ablations/backups.json`, runnable with `scripts/ablate.py`.

**Still deferred: the in-process `trustissues backup` subcommand.** The scripts
shell out to the `sqlite3` CLI, so a host without it cannot take a backup and
the failure surfaces at 03:20 rather than at install time. A `trustissues backup
<path>` subcommand calling the online backup API in-process would remove that
dependency and let the server report success to a notification channel directly,
which the shell path cannot do.

**Still deferred: off-host replication.** The timer, the retention policy and
the drill all operate on one directory on one host. Copying snapshots off the
box is left to the operator's own `restic` / `rclone` / object-storage job.
`docs/BACKUP.md` says so explicitly rather than implying the schedule covers it.

**Also not covered: backing up from inside the container.** The units run
`sqlite3` on the host against the Compose volume's `_data` path. The documented
`docker compose exec` route still works but nothing schedules it.

**Why the remainder is safe to defer.** All three are convenience or reach, not
correctness. The correctness-critical parts (a WAL-safe snapshot, verified
before it is kept, key separation, a retention policy that cannot delete the
newest copy, and a drill that proves the newest snapshot actually restores) are
scripted, scheduled, alerted on, and tested.

## (e) Per-secret reveal granularity in the audit

**Today.** `POST /api/vault/unlock` decrypts and returns all of the user's
secrets and logs one `vault.unlocked` event with no entry list. You can prove a
user unlocked (and therefore received everything) but not which specific secret
they viewed or copied.

**Design when built.** If a per-entry reveal / copy action is added to the UI and
API, log it per entry (`vault.entry_revealed` with the entry id) so the audit can
answer "who viewed secret X." This is deferred together with the reveal feature
itself; adding the log without the granular endpoint would record nothing new.

**Why safe to defer.** For one team the current grain ("this user unlocked their
vault at this time") is a reasonable accountability level, and the coarse event
does not over- or under-claim. Finer grain only pays off with a per-entry reveal
UX, which is a product decision, not a security gap in the current design.

## (f) Preserving audit actor attribution after user deletion

**Today.** `activity_log.user_id` is `ON DELETE SET NULL`. Deleting a user nulls
the actor on all of that user's past rows, and `auth.login` events carry no
embedded actor id, so history for a deleted user reads as "(system)." Vault
events already embed the actor in their `detail`, so they survive; auth events do
not.

**Design when built.** Denormalize actor email + id into every audit row at write
time (uniformly, the way vault events already do), so deletion cannot erase the
"who." Alternatively, block hard-deleting a user who has audit history and offer
a deactivate / anonymize path instead. The append-only triggers already prevent
editing rows, so the only leak is the FK null-out on delete.

**Why safe to defer.** User deletion is rare on a single team and is performed by
the trusted admin, who knows who they just removed. The historical record is
degraded (actor becomes "(system)") but not falsified, and no row is destroyed.
Faithful post-deletion attribution matters most for compliance / multi-admin
setups, which arrive with the Phase 2 teams work.

## (g) AI gateway + MCP: streaming, connector OAuth, unstructured-PII coverage

Shipped in the AI-boundary phases: the AI gateway (server-side provider-key
injection + Shield tokenization), a remote HTTP MCP (list_secrets + use_secret),
and the operator UI. Three follow-ups are intentionally deferred:

1. **Streaming.** The gateway is non-streaming in v1: Shield markers can span SSE
   chunks, so a streamed response cannot be reliably tokenized/resolved. Design:
   buffer-and-resolve per SSE event, or pass streaming through only when Shield
   is off. Until then `"stream": true` is rejected.
2. **MCP connector OAuth.** The MCP + gateway authenticate with a per-user
   API key sent as `X-API-Key`. Some hosted connectors prefer OAuth or a bearer
   token. Add an OAuth authorization-server surface (or bearer acceptance) so
   any connector UI can complete a standard flow.
3. **Unstructured-PII coverage.** Shield's gateway/MCP path uses the regex safety
   net, which catches structured PII (email, phone, personnummer, IBAN) but not
   arbitrary names/companies (those need the struct-tag path, which suits typed
   tool responses, not free-form prompts). Consider an NER pass for free-form
   prompt bodies if name-level tokenization is required.

**Why safe to defer.** The core guarantee (credentials never reach the AI or the
human; structured PII tokenized before egress; single-use destination-bound
capability tokens) holds today. These three widen coverage and connector
ergonomics, they do not change the security floor.

## Encrypt `vault_entries.name` behind a blind index

**Status:** designed, not implemented. Found in the round-6 audit (2026-07-28),
confirmed against production.

`name` is the one entry column still stored in cleartext. Every sibling
(url, alias_url, username, category, notes) goes through `encryptMetaColumns`.
THREAT-MODEL.md used to claim `name` was encrypted too; that claim has been
corrected rather than left standing, so the docs and the code now agree.

**Why it is deferred rather than done.** The column is load-bearing in four
places at once, and getting any of them wrong loses or hides secrets:

1. `UNIQUE(user_id, name)` is the duplicate-name guard the Create handler
   depends on (it matches on `"UNIQUE constraint"` in the error string). SQLite
   cannot alter a constraint in place, so this needs the 12-step table rebuild
   on the table that holds every secret.
2. Five queries `ORDER BY name`. Ciphertext does not sort, so those move to
   app-side sorting, which also affects any future pagination.
3. `ResolveVaultReference` and the capability by-name lookup match on `name = ?`.
   Both would move to `name_bidx = ?`. The round-5 ambiguity refusal
   (`errAmbiguousSecretName`) must keep working, which it does since a blind
   index is deterministic.
4. The same string is mirrored into `activity_log.detail`, `capability_log.secret_name`
   and `service_identities.allowed_secrets`. `activity_log` has append-only
   triggers, so history cannot be rewritten: future writes must log the entry id
   and let the UI resolve the name, and existing rows stay as they are.

**The design, when it is picked up.** Add `name_bidx TEXT NOT NULL DEFAULT ''`,
reusing `urlBlindIndex` and its `bidxScope(userID, collectionID)` so the index
cannot be correlated across users or collections. Writers: `vault.go` Create and
Update, `vault_import.go`. Readers: the six mappers that already call
`decryptColumnOrLog`. Swap `UNIQUE(user_id, name)` for `UNIQUE(user_id, name_bidx)`.
Backfill via the existing `BackfillMetadataAtRest` pattern using
`encryptColumnIfNeeded` (storage-side only, never on client input).

**Interim guidance:** a leaked backup reveals the inventory, not the secrets.
This is stated plainly in THREAT-MODEL.md so nobody plans around a guarantee the
product does not offer.
