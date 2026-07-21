package handlers

// Internal credential rotation: NOT PORTED.
//
// Dockyard's cred_rotation.go bridges vault rotation to a managed-server
// agent fleet: it queues `cred.rotate.*` commands in an agent_commands table,
// a host agent performs the work (ALTER USER on Postgres/MariaDB, CONFIG SET
// on Redis, restic key rotation, MinIO svcacct edit), and the server polls
// for the new password. The five `internal:*` providers in dockyard's
// registry are thin wrappers over that dispatch loop.
//
// Trustissues is a standalone, single-team product with no server agents, no
// agent_commands table, and no managed services, so none of that machinery
// can function here. The rotation engine keeps only providers that talk to
// external APIs directly (plus the local secret generators shared-secret and
// generated-key-32).
//
// If self-hosted database credential rotation is ever wanted, it needs a new
// design (direct DB connections from the trustissues process, not an agent
// fleet); do not resurrect the dockyard agent bridge.
