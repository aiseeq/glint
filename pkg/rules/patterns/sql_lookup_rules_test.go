package patterns

import (
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// moduleSQLRuleLines runs a file rule on one file of a module with its
// migrations.
func moduleSQLRuleLines(t *testing.T, rule interface {
	AnalyzeFile(*core.FileContext) []*core.Violation
}, files map[string]string, path string) []int {
	t.Helper()
	_, contexts := rulestest.Module(t, files)
	for _, ctx := range contexts {
		if ctx.RelPath != path {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, ctx.Path, ctx.Content, parser.ParseComments)
		require.NoError(t, err)
		ctx.SetGoAST(fset, file)
		return sqlRuleLines(t, rule, ctx)
	}
	t.Fatalf("no file %s in the module", path)
	return nil
}

// A filter by the members of an org compares the member's email with
// itself: the bare email binds to m, and every order passes.
func TestSQLColumnComparedWithItself(t *testing.T) {
	assert.Equal(t, []int{8, 13}, sqlFileRuleLines(t, NewSQLColumnComparedWithItselfRule(), "repo/orders.go", `package repo

import "fmt"

func (qb *builder) scope(org string) {
	qb.conditions = append(qb.conditions, fmt.Sprintf(
		"EXISTS (SELECT 1 FROM members m WHERE m.org_id = $%d AND "+
			"(m.email = email OR lower(m.email) = lower(email)))", qb.argNum))
	qb.conditions = append(qb.conditions, fmt.Sprintf(
		"EXISTS (SELECT 1 FROM members m WHERE m.org_id = $%d AND m.email = %s.email)", qb.argNum, qb.alias))
}

func List(db DB) { db.Query("SELECT o.id FROM orders o JOIN members m ON m.code = code") }
`))
}

// Unlinking by the row's own key clears its link to any batch; linking
// moves a row another batch holds.
func TestSQLLinkUpdateIgnoresParent(t *testing.T) {
	assert.Equal(t, []int{5, 11}, moduleSQLRuleLines(t, NewSQLLinkUpdateIgnoresParentRule(), map[string]string{
		"repo/migrations/001_init.up.sql": `CREATE TABLE batches (id UUID PRIMARY KEY);
CREATE TABLE entries (id UUID PRIMARY KEY, account_id TEXT, seq BIGINT, batch_id UUID, updated_at TIMESTAMPTZ);
CREATE TABLE users (id UUID PRIMARY KEY, chat_account_id TEXT, chat_id BIGINT);`,
		"repo/batches.go": `package repo

func (r *Repo) LinkEntry(ctx context.Context, batchID, account string, seq int64) error {
	_, err := r.db.ExecContext(ctx, ` + "`" + `UPDATE entries
		SET batch_id = $1, updated_at = NOW()
		WHERE account_id = $2 AND seq = $3` + "`" + `, batchID, account, seq)
	return err
}

func (r *Repo) UnlinkEntry(ctx context.Context, account string, seq int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE entries SET batch_id = NULL WHERE account_id = $1 AND seq = $2", account, seq)
	return err
}

func (r *Repo) UnlinkOwnEntry(ctx context.Context, batchID, account string, seq int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE entries SET batch_id = NULL WHERE account_id = $1 AND seq = $2 AND batch_id = $3", account, seq, batchID)
	return err
}

func (r *Repo) LinkFreeEntry(ctx context.Context, batchID string, id string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE entries SET batch_id = $1 WHERE id = $2 AND (batch_id IS NULL OR batch_id = $1)", batchID, id)
	return err
}

func (r *Repo) Reassign(ctx context.Context, batchID string, id string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE entries SET batch_id = $1 WHERE id = $2", batchID, id)
	return err
}

func (r *Repo) UnlinkChat(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET chat_account_id = NULL, chat_id = NULL WHERE id = $1", userID)
	return err
}
`,
	}, "repo/batches.go"))
}

const partialKeyMigration = `CREATE TABLE payments (id UUID PRIMARY KEY, order_id UUID, status TEXT NOT NULL);
CREATE UNIQUE INDEX payments_live_order ON payments (order_id) WHERE order_id IS NOT NULL AND status <> 'void';`

// A void payment and a live one share the order: Get by the order takes
// either.
func TestSQLPartialKeyReadWithoutPredicate(t *testing.T) {
	assert.Equal(t, []int{6}, moduleSQLRuleLines(t, NewSQLPartialKeyReadRule(), map[string]string{
		"storage/migrations/001_init.up.sql": partialKeyMigration,
		"storage/repo.go": `package storage

func Find(db DB, orderID string) {
	var p Payment
	db.GetContext(ctx, &p, ` + "`" + `SELECT * FROM payments
		WHERE order_id = $1
		FOR UPDATE` + "`" + `, orderID)
	db.GetContext(ctx, &p, "SELECT * FROM payments WHERE order_id = $1 AND status <> 'void'", orderID)
	db.SelectContext(ctx, &ps, "SELECT * FROM payments WHERE order_id = $1", orderID)
	db.GetContext(ctx, &p, "SELECT * FROM payments WHERE order_id = $1 ORDER BY id DESC LIMIT 1", orderID)
}
`,
	}, "storage/repo.go"))
}

const referencedMigration = `CREATE TABLE transactions (id UUID PRIMARY KEY, wallet TEXT, leg INT);
CREATE TABLE ledger_entries (id UUID PRIMARY KEY, chain_tx_id UUID);
CREATE TABLE notes (id UUID PRIMARY KEY, transaction_id UUID REFERENCES transactions(id));`

// Ledger entries keep the id of a transaction the resync deletes: no key
// stops it, nothing here checks.
func TestSQLDeleteReferencedWithoutKey(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": referencedMigration,
		"storage/repo.go": `package storage

func Replace(db DB, wallet string, legs []int64) {
	q, args, _ := sqlx.In(` + "`" + `DELETE FROM transactions
		WHERE wallet = ? AND leg NOT IN (?)` + "`" + `, wallet, legs)
	db.ExecContext(ctx, q, args...)
}

func ReplaceChecked(db DB, wallet string, legs []int64) {
	db.GetContext(ctx, &n, "SELECT count(*) FROM ledger_entries WHERE chain_tx_id = ANY($1)", ids)
	db.ExecContext(ctx, "DELETE FROM transactions WHERE wallet = $1", wallet)
}

func DropNotes(db DB, id string) { db.ExecContext(ctx, "DELETE FROM notes WHERE id = $1", id) }
`,
	}
	assert.Equal(t, []int{4}, moduleSQLRuleLines(t, NewSQLDeleteReferencedWithoutKeyRule(), files, "storage/repo.go"))
}

const externalKeyMigration = `CREATE TABLE transfers (
    id UUID PRIMARY KEY,
    provider_reference TEXT,
    partner_reference TEXT NOT NULL UNIQUE,
    carrier_ref TEXT,
    batch_reference TEXT,
    account_id UUID NOT NULL
);
CREATE UNIQUE INDEX ux_transfers_carrier_ref ON transfers (carrier_ref) WHERE carrier_ref <> '';`

// One transfer read by the provider's reference that no unique index covers
// takes either of two rows sharing it; a unique column, a partially unique
// one, a read of every row, a LIMIT and a lookup fixed by the id are left
// alone.
func TestExternalReferenceLookupWithoutUniqueIndex(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": externalKeyMigration,
		"storage/repo.go": `package storage

const transferColumns = "id, provider_reference, account_id"

func Find(db DB, ref string) {
	db.QueryRowContext(ctx, "SELECT " + transferColumns + " FROM transfers WHERE provider_reference = $1", ref)
	db.QueryRowContext(ctx, "SELECT id FROM transfers WHERE partner_reference = $1", ref)
	db.QueryRowContext(ctx, "SELECT id FROM transfers WHERE carrier_ref = $1", ref)
	db.QueryContext(ctx, "SELECT id FROM transfers WHERE batch_reference = $1", ref)
	db.QueryRowContext(ctx, "SELECT id FROM transfers WHERE batch_reference = $1 ORDER BY id LIMIT 1", ref)
	db.QueryRowContext(ctx, "SELECT id FROM transfers WHERE id = $1 AND provider_reference = $2", id, ref)
	db.GetContext(ctx, &t, ` + "`" + `SELECT id FROM transfers
		WHERE account_id = $1
		  AND batch_reference = $2` + "`" + `, account, ref)
}
`,
	}
	assert.Equal(t, []int{6, 14}, moduleSQLRuleLines(t, NewExternalReferenceLookupWithoutUniqueIndexRule(), files, "storage/repo.go"))
}
