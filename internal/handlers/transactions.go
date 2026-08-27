package handlers

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/bright-interaction/trustissues/internal/db"
)

// beginQueriesTx starts a transaction on the pool underlying queries and
// returns a query set pinned to it. Security gates and the reads/writes they
// authorize must use the returned query set; mixing it with the original one
// silently reintroduces the check/use race this helper exists to remove.
//
// Top-level handlers are built with db.New(*sql.DB). A query set already bound
// to *sql.Tx cannot start a nested transaction, so fail explicitly instead of
// falling back to the pool and escaping the caller's snapshot.
func beginQueriesTx(ctx context.Context, queries *db.Queries, opts *sql.TxOptions) (*sql.Tx, *db.Queries, error) {
	pool, ok := queries.Handle().(*sql.DB)
	if !ok {
		return nil, nil, fmt.Errorf("queries are not backed by a database pool")
	}
	tx, err := pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	return tx, queries.WithTx(tx), nil
}
