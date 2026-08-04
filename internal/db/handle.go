package db

// Hand-written, in the generated package on purpose. sqlc owns everything else
// here; this is one accessor sqlc has no template for.

// Handle returns the database handle this Queries was built on, which is either
// the pool or a caller's transaction.
//
// It exists for internal/vaultegress, the package that performs the writes which
// can move where a decrypted secret is sent. Those queries are generated into
// internal/vaultegress/internal/egressq so that no handler can name them, and
// that package needs a handle to run them on. It must be the SAME handle the
// caller is already using: a helper called between BeginTx and Commit that
// reached for the pool instead would write outside the transaction it thinks it
// is in.
//
// This grants nothing new. Every caller that holds a *Queries also holds the
// *sql.DB or *sql.Tx it was made from, so raw statement execution was always
// available; what is NOT available any more is a typed method on this type that
// writes a host-choosing column. That distinction is the point: hand-written SQL
// against those columns is caught by
// TestNoStatementOutsideTheEgressPackageWritesAHostChoosingColumn, which asks
// SQLite what a statement writes rather than pattern-matching its text.
func (q *Queries) Handle() DBTX { return q.db }
