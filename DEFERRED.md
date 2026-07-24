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

**Today.** There is no dual-key read and no re-encrypt routine. Changing
`TRUSTISSUES_VAULT_KEY` in place orphans all data (proven: a reboot of the same
data dir under a new key returns `[decryption error]` for every secret). The
only supported rotation is the manual export / re-import in `SECURITY.md`.

**Design when built.**
1. Add an optional `TRUSTISSUES_VAULT_KEY_PREVIOUS`. Decryption tries the current
   key, then the previous key (dual-key read), so a restored or half-rotated
   store keeps working.
2. Run a re-encrypt sweep (boot flag or admin-triggered) across **every** keyed
   surface in one transaction: `vault_entries.encrypted_value`, `provider_meta`,
   `rotation_targets`, `users.totp_secret`, notification-channel configs, and
   capability / service-identity secrets. Miss one column and that data is
   orphaned, so the sweep must be exhaustive and list-driven.
3. Stamp a per-row key id / version so a partial sweep is resumable and a row's
   key is self-describing.
4. Preflight: verify every row re-encrypts under the new key before committing;
   abort the whole transaction on any failure.

**Prerequisite (do this first).** `columncrypto.EncryptString` emits bare base64
with no structural marker, so "is this plaintext?" is answered by "did decrypt
throw." That is what lets the boot TOTP migration double-encrypt a seed on a key
mismatch (`Enc_B(Enc_A(seed))`), which is irreversible. Add an `enc:` prefix so
plaintext detection is structural, and only ever treat unprefixed values as
plaintext, before any rotation sweep can be trusted.

**Why safe to defer.** A single trusted operator can rotate with the documented
export / re-import during a short maintenance window. Rotation is rare
(suspected compromise or policy), not a routine operation, so a manual procedure
is acceptable for v1. The real risk is an *accidental* naive rotation, and that
is mitigated with loud warnings in `.env.example`, the compose file,
`README.md`, and `THREAT-MODEL.md`.

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

**Today.** Backups are manual: `scripts/backup.sh` plus the procedure in
`docs/BACKUP.md`. There is no built-in `trustissues backup` subcommand and no
scheduler.

**Design when built.** (1) A `trustissues backup <path>` subcommand that calls
the SQLite online backup API in-process (no external `sqlite3` dependency),
writes 0600, and optionally prunes by age / count. (2) An optional internal
scheduler (or documented cron / systemd timer, which works today) that runs it on
an interval and reports success to a notification channel. Keep the
key-separation rule front and centre so an automated job never co-locates the
backup with the vault key.

**Why safe to defer.** Durability is achievable now with the shipped script run
from cron or a systemd timer, which is the standard way a self-hoster schedules
any job. The missing piece is convenience, not capability. The correctness-
critical part (WAL-safe snapshot + key separation) is already documented and
scripted.

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
