package patterns

import "testing"

// Parallel fixtures pick the first free order number under an advisory lock
// taken in a CTE of the same statement: the statement's snapshot is older
// than the lock wait, a number a neighbour took meanwhile looks free, and
// the insert fails on the unique index. A lock taken by its own statement
// first, or a SELECT locking per row by the keys it reads, is fine.
func TestAdvisoryLockInSameStatementAsGuardedRead(t *testing.T) {
	assertWanted(t, NewAdvisoryLockInSameStatementRule(), "package app\n\n"+
		"import \"context\"\n\n"+
		"type Tx interface {\n"+
		"	ExecContext(ctx context.Context, query string, args ...any) (any, error)\n"+
		"}\n\n"+
		"func Reserve(ctx context.Context, tx Tx, email string) error {\n"+
		"	const query = `\n"+
		"WITH locked AS (\n"+
		"    SELECT pg_advisory_xact_lock(4242) -- // want\n"+
		"), candidate AS (\n"+
		"    SELECT gs::text AS number\n"+
		"    FROM locked, generate_series(100000, 999999) AS gs\n"+
		"    WHERE NOT EXISTS (SELECT 1 FROM orders WHERE number = gs::text)\n"+
		"    ORDER BY gs\n"+
		"    LIMIT 1\n"+
		")\n"+
		"INSERT INTO orders (id, email, number)\n"+
		"SELECT gen_random_uuid(), $1, number FROM candidate`\n"+
		"	_, err := tx.ExecContext(ctx, query, email)\n"+
		"	return err\n"+
		"}\n\n"+
		"func ReserveLocked(ctx context.Context, tx Tx, email string) error {\n"+
		"	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(4242)`); err != nil {\n"+
		"		return err\n"+
		"	}\n"+
		"	_, err := tx.ExecContext(ctx, `INSERT INTO orders (id, email, number) SELECT gen_random_uuid(), $1, max(number) + 1 FROM orders`, email)\n"+
		"	return err\n"+
		"}\n\n"+
		"func LockRows(ctx context.Context, tx Tx, ids []string) error {\n"+
		"	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext(id::text)) FROM orders WHERE id = ANY($1)`, ids)\n"+
		"	return err\n"+
		"}\n")
}
