# Vault portability

Trustissues has two different ways to preserve data. They solve different
problems and must not be handled as if they were the same artifact.

| Artifact | Purpose | Contents | Normal protection |
|---|---|---|---|
| SQLite snapshot | Disaster recovery of one instance | Encrypted vault data plus users, authority, audit and operational state | Mode 0600, whole-file encryption off-host, vault key stored separately |
| Native vault export | Moving user-visible vault contents between Trustissues instances | **Plaintext** JSON containing every included password and secret custom field | Trusted device and endpoint, immediate whole-file encryption, shortest possible lifetime |

Use `docs/BACKUP.md` for disaster recovery. A native export is useful for
portability and an independent last-resort copy of vault contents, but it does
not replace a scheduled, restore-tested database backup.

## Exporting a vault

Unlock the Vault page, choose **Export**, and re-enter the current account
password. The server returns a `trustissues-vault-YYYYMMDD-HHMMSS.json` file
with `format: "trustissues-vault"` and `version: 1`.

Export is a bulk equivalent of Unlock, not an admin-only database dump. It
contains:

- the caller's personal entries;
- every entry in a collection whose invitation the caller has accepted,
  including for a viewer role; and
- descriptors only for collections referenced by those entries.

If a caller may reveal a shared entry, they may export it. A collection manager
cannot currently mark one entry non-exportable. Removing or disabling a member
revokes future access; it cannot recall a plaintext file they already exported.

The document carries user-authored portable fields: names, values, URLs,
usernames, categories, notes, supported rotation dates/intervals, provider
configuration safe for clients, custom fields and destination patterns. Source
IDs exist only to map references inside that document. They are not authority
and are never reused by an importer.

The export deliberately omits instance-local or operational state:

- owners, custodians, collection members, roles and invitations;
- rotation targets, rotation logs, errors and pending-revoke state;
- grants, service identities, API keys and AI-provider wiring;
- server-reserved provider metadata; and
- a custom capability injection specification.

The endpoint password-reauthenticates under the Unlock guess budget, verifies
current access again for every released secret, builds the complete document
before sending any attachment bytes, and refuses partial exports. It sets
`Cache-Control: no-store` and records a required `vault.exported` audit row. An
audit outage blocks the export.

Native v1 is one bounded interchange document: at most 5,000 accessible entries
and at most 10 MiB of JSON. Export checks the entry ceiling and a conservative
stored-size lower bound on one bounded database snapshot before bulk decryption,
then checks the final serialized size before the success audit or attachment
headers. It returns HTTP 413 instead of creating a file that this version's
importer cannot restore. The native upload routes
reserve an additional MiB for multipart framing and password re-authentication;
the 10 MiB limit applies to the JSON file itself. There is not yet a chunked
native format, so an account above either ceiling still requires the encrypted
SQLite disaster-recovery path described in `docs/BACKUP.md` until the vault is
reduced or chunked portability is implemented.

## Handling the plaintext file

The JSON is readable without `TRUSTISSUES_VAULT_KEY`. Anyone or anything that
can open it can read all included credentials.

- Export only over the trusted HTTPS endpoint and onto a trusted device with an
  encrypted local disk.
- Prefer a non-synced temporary download location. Browser download history,
  cloud sync, backup agents, antivirus, search indexing and temporary files can
  create extra copies.
- Never email it, commit it, paste it into a ticket/chat, or upload it to
  general-purpose storage unencrypted.
- Encrypt it immediately for any retention or transfer, for example:

  ```bash
  age -r age1... -o trustissues-vault.json.age trustissues-vault.json
  chmod 600 trustissues-vault.json.age
  ```

  Keep the `age`/GPG decryption key separate from the encrypted file.
- After a verified import, remove the plaintext copy and clear it from any sync
  or backup system that captured it. Ordinary deletion is not a promise of
  erasure on SSD, copy-on-write, synced or backed-up storage, so minimizing
  where the plaintext ever lands is more reliable than trying to erase every
  copy later.

## Importing a native export

Choose **Import** on the Vault page and select the `.json` export. Native import
has a server-side preview that reports entry/collection counts, name conflicts
and how many requested auto-rotation schedules will be disabled. The preview
returns no secret values. Confirmation requires the current account password
and re-uploads the same file for strict validation.

Native v1 import is deliberately fail-closed:

- the format/version and every JSON field are checked strictly;
- duplicate or dangling source IDs, malformed dates/metadata, invalid custom
  fields or destinations, withheld values, files over 10 MiB, and batches over
  5,000 entries are rejected;
- the whole document and every name conflict are checked before mutation;
- every write, including a required bounded audit row, happens in one
  transaction; one failure rolls back all entries and collections;
- all destination entries and collections receive fresh random IDs;
- every imported entry is encrypted through the normal always-seal path and
  gets blind indexes derived for its new scope; and
- client strings that happen to look like Trustissues ciphertext remain literal
  client strings, never a request to decrypt stored bytes.

Imported personal entries become the importer's entries. Each exported
collection becomes a new private collection, with only the importer as an
accepted manager; source memberships and roles are never recreated. Grouping is
preserved through a source-to-new collection map.

Auto-rotation is always disabled on import, even if the source requested it.
Rotation targets are not imported. Review provider credentials and destinations
before deliberately re-enabling a schedule: restoring an old timestamp and an
active schedule could otherwise rotate an upstream credential immediately.
Provider names and metadata for an adapter this instance does not recognize are
preserved for round-trip compatibility, but remain inert: no capability
injection or provider destination defaults are created until local support
exists and an operator reviews the entry.

Trustissues refuses target-vault and within-file name conflicts instead of
silently skipping or renaming secrets. Resolve the duplicate names in the
source/destination and preview again. Because the current uniqueness rule is
per importing user across personal and collection entries, a source document
that legitimately contains the same name in two scopes cannot round-trip with
those names unchanged until that schema rule is redesigned.

The successful operation records `vault.native_imported` with bounded counts
only. No entry names or values are placed in the audit detail.

## What “round trip” means

Exporting an imported vault again preserves supported user-authored content and
collection grouping. It does not reproduce the original database or authority:
IDs are fresh, ownership belongs to the importer, collections are private
copies, automations are inert, provider operational markers are gone, and
instance-local credentials/audit history never enter the interchange file.

That boundary is intentional. A portable password file must not also be a way
to mint identities, restore stale webhook destinations, revive a revoked API
key, or grant the importer somebody else's authority.
