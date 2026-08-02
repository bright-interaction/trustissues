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

## (h) Scope-aware uniqueness for `vault_entries.name`

**Status:** designed, not implemented. The complete fix for the rename oracle
found in the cross-client isolation pass (2026-08-02).

`UNIQUE(user_id, name)` is scoped to the entry's CREATOR, and a collection entry
keeps its creator's `user_id` forever. So the uniqueness question a rename asks
lands in a namespace the renamer usually cannot read, and the answer (409 versus
200) is an existence oracle over another user's private vault. The shipped fix
routes around it: only the creator or an instance admin renames normally, and a
collection MANAGER may rename an entry whose creator has left the collection by
ADOPTING it, which moves the uniqueness question into the manager's own
namespace. Nothing consults a namespace the caller cannot see.

**What complete looks like:** drop the table-level `UNIQUE(user_id, name)` and
replace it with two partial indexes,

    CREATE UNIQUE INDEX ... ON vault_entries(user_id, name) WHERE collection_id IS NULL;
    CREATE UNIQUE INDEX ... ON vault_entries(collection_id, name) WHERE collection_id IS NOT NULL;

so a shared entry's name is unique within its COLLECTION, which is exactly the
namespace every member can already see. Then any editor could rename, with honest
duplicate feedback, and adoption would not be needed.

**Why it is deferred.** SQLite cannot drop a table-level UNIQUE without the
12-step table rebuild, and `vault_entries` is the table every secret lives in.
The rebuild runs `DROP TABLE`, which with `_foreign_keys=on` (how the app opens
the database) fires `capability_grants`' `ON DELETE CASCADE` and wipes every
agent grant. `PRAGMA foreign_keys` cannot be toggled inside the transaction goose
wraps a migration in, and toggling it from a pooled `*sql.DB` outside one is not
reliably the same connection the DDL runs on (the pool is 10 connections).

**The judgment, restated 2026-08-02.** This is NOT load-bearing for security any
more, and that is why it stays deferred a second time rather than being rushed.
The oracle is closed at the handler: no caller can drive a uniqueness check
against a namespace they cannot read, proven by five subtests that each redden
under ablation. What is left is ergonomics (adoption, and its cost to the
departed creator's recovery read) and a data model that says "unique per
creator" where "unique per collection" is meant. Weighed against that: the fix
rewrites the table holding every secret, and a half-correct rebuild loses them.
It deserves its own pass with a restore test, not a corner of a security round.

**What that pass needs, so it does not start from scratch.**

1. The FK cascade is avoidable without touching `PRAGMA foreign_keys`. Inside the
   single migration transaction: `CREATE TABLE capability_grants_backup AS SELECT
   * FROM capability_grants` first, do the rebuild, then re-insert from the
   backup (the ids are unchanged, so the FK is satisfiable again) and drop the
   backup. Any other table that gains an FK to `vault_entries` needs the same
   treatment, so the migration should assert the referrer list it knows about.
2. Existing data can VIOLATE the new collection-scoped index (two members can
   legitimately hold the same name in one collection today), so the migration
   needs a deterministic dedup pass before `CREATE UNIQUE INDEX`, or a deploy
   fails on data it created itself.
3. Test it with `goose.UpTo(previous)`, seed entries plus grants plus a duplicate
   pair, then `Up()`: assert no grant was lost, the duplicates were renamed
   predictably, and both partial indexes enforce what they claim.
4. The rename branch and its five subtests in `VaultHandler.Update` change shape
   when the constraint moves; treat that as part of the work, not fallout.

**Interim guidance:** the rule is stated in THREAT-MODEL.md and in the code
comment above the rename branch in `VaultHandler.Update`, including its cost
(adoption ends the departed creator's residual recovery read on that entry).

## (i) Rotation delivery targets are not held to the egress-widening right

**Status:** deliberate, named here because it is the one door the round-3 egress
work did NOT close in general.

Adding a rotation target is the same ACT as widening `destination_patterns`:
`deliverToWebhook` POSTs `{"new_value": <the secret>}` to a URL somebody named,
and `forgejo_secret` writes the value into a repository. Since 2026-08-02,
widening `destination_patterns` takes the entry's creator or an instance admin
(`mayDirectSecretEgress`). Configuring a delivery target still takes only
`manage`, so any accepted editor of the collection can add one to a secret they
did not deposit.

**The escalation that keeps it interesting.** A session-authenticated member can
already read a shared secret through `/api/vault/unlock` (their own password) and
through `POST /api/vault/{id}/rotate` (also password-gated), so for them this
adds nothing. An API-KEY-only caller (a stolen extension key) can do neither, but
CAN add a webhook target and then set `auto_rotate` with a short interval through
`PUT /api/vault/{id}`, neither of which asks for a password. The scheduler then
rotates and hands their endpoint a fresh, live provider credential.

**Why it is not closed in this pass.** Four earlier rounds looked directly at
"an editor configures a target on somebody else's shared entry" and hardened it
instead of forbidding it: `ConfiguredBy` is stamped server-side, an `auth_token`
resolves as the CONFIGURER rather than the entry owner, delivery re-checks that
the configurer still has write access, leaving a collection purges their targets,
and a stale panel cannot resurrect a purged one. Four guards encode that
behaviour as the intended one. Forbidding it is a change to how teams run shared
rotation, i.e. a product decision, and making it inside a security round would
have rewritten the premise of those four guards in the same commit that claims no
regressions.

**What IS closed.** The case this audit is about: an entry wired into the AI
gateway carries no secret-transmitting delivery target at all, refused at the
write (`UpdateTargets`) and at delivery (`DeliverRotatedKey`), so the operator's
provider key cannot be handed to a rotation webhook by anyone.

**Narrowed on 2026-08-02.** The other half of that escalation is now gone. It
needed TWO ungated fields: `auto_rotate` to make the scheduler act, and a
destination for it to act toward. `provider` and `provider_meta` were the second
one and were ungated, so the same API-key caller could point the entry at their
own Grafana or Zitadel instance and let the sweep deliver there, with no rotation
target involved at all. That now takes the widening right
(`authorityForEgressChange`). `auto_rotate` stays `manage`-gated and is
classified `egressTriggersDelivery` in `vaultEntryEgressClass`: it decides
WHETHER the secret moves, never WHERE, so on its own it can only trigger delivery
to destinations an authorised principal already chose.

**Design when picked up.** Gate a NEW secret-transmitting target (one whose
`rotationTargetIdentity` is not already stored) on `mayDirectSecretEgress`, the
same helper `destination_patterns` uses, and re-shape the four fixtures so the
configurer is a principal who may direct egress: the leaver/editor becomes the
entry's creator in the purge and stale-panel tests, and an admin configures the
target in the read-authz test so the removed creator is still harvesting somebody
else's HMAC secret. Consider requiring re-auth (the password `Rotate` already
asks for) instead, which closes the API-key path specifically while leaving the
team workflow alone.

## (j) A meta-derived provider's declared hosts come out of the same column a forged row would carry

**Status:** deliberate and bounded. Written down because the 2026-08-02 egress
work rests on it and a future reviewer will otherwise re-derive it from scratch.

`providerEgress` declares each adapter's reachable hosts as a function of the
entry's `provider_meta`. For a self-hosted or per-tenant provider that function
is meta-derived by necessity: grafana is `{instance}.grafana.net`, zitadel and
forgejo are whatever `instance` says, datadog is `api.{site}`. So the DERIVATION
gate (`providerDo`) cannot, on its own, tell a legitimate row from one somebody
forged: it compares the host on the wire against a declaration computed from the
same bytes, and the two agree either way.

That is not a hole in the derivation gate, it is what the derivation gate is for.
Its job is to catch an adapter that dials a host its declaration does not
mention, which is the round-4 shape (`site` became a host while datadog was
declared as a fixed vendor endpoint) and the round-5 shape (a provider added
later grows a `region` or `workspace` key nobody classified). Both are caught,
by `TestProviderRequestsStayInsideTheirDeclaredHosts`.

**What actually guards a forged row, per case:**

- **Written through the API.** The WRITE gate (`authorityForEgressChange`)
  refuses it. Adding a host takes the entry's creator or an instance admin.
- **The instance's AI provider key.** The PIN closes it completely, including a
  row written by an older binary, a restored backup or an import: the pin comes
  from an AdminOnly `ai_key_*` settings row joined to a compile-time host table,
  so nothing an entry editor can write contributes to it. Enforced at the write,
  at mint, at `/proxy`, at rotation-target write and delivery, and now at
  validate and both rotation paths (`providerEgressContextFor`).
- **Any other shared secret, row forged by direct database access.** Not
  guarded, and not guardable at this layer: a writer with `sqlite3` on the data
  directory can also read `encrypted_value` and, with the host key material, the
  secret itself. This is the R-series "operator with filesystem access" residual
  in `THREAT-MODEL.md`, not a new one.

**If it is ever wanted anyway,** the shape is an authorised-configuration
fingerprint: store an HMAC of `(provider, the declared host set)` under the vault
key when an authorised principal writes it, and refuse to spend a row whose
fingerprint does not verify. That upgrades "who wrote this row" from a
handler-level question to a durable one. It is real work (a migration, a
backfill decision for existing rows, and an answer for restores) and it buys
nothing against the API path, which the write gate already closes, so it is not
worth doing until there is a threat model where the database is writable and the
key is not.
