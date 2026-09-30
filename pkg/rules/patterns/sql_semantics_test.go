package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func sqlFileRuleLines(t *testing.T, rule interface {
	AnalyzeFile(*core.FileContext) []*core.Violation
}, path, source string) []int {
	t.Helper()
	return violationLines(rule.AnalyzeFile(rulestest.GoFile(t, path, source)))
}

// A user with two wallets gets either address: which row LIMIT 1 takes
// without an order is up to the plan.
func TestSQLLimitWithoutOrder(t *testing.T) {
	assert.Equal(t, []int{6, 9}, sqlFileRuleLines(t, NewSQLLimitWithoutOrderRule(), "repo/deposits.go", `package repo

func List(db DB) {
	db.Query(`+"`"+`
		SELECT t.id,
		       COALESCE(t.to_address, (SELECT address FROM wallets WHERE user_id = t.user_id LIMIT 1)) AS address
		FROM transfers t
		ORDER BY t.created_at DESC`+"`"+`)
	db.Query("SELECT id FROM transfers WHERE user_id = $1 LIMIT $2 OFFSET $3")
	db.Query("SELECT id FROM transfers WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1")
	db.Query("SELECT id FROM jobs WHERE state = 'new' LIMIT 10 FOR UPDATE SKIP LOCKED")
}
`))
}

// Schema made by the running application: it depends on which code path ran
// first, and a migration can say otherwise.
func TestSQLRuntimeDDL(t *testing.T) {
	assert.Equal(t, []int{4, 5}, sqlFileRuleLines(t, NewSQLRuntimeDDLRule(), "repo/wallets.go", `package repo

func NextIndex(db DB) {
	db.Exec(`+"`"+`CREATE SEQUENCE IF NOT EXISTS address_index_seq START WITH 1`+"`"+`)
	db.Exec(fmt.Sprintf(`+"`"+`CREATE SEQUENCE IF NOT EXISTS other_seq START WITH %d`+"`"+`, start))
	db.Exec("CREATE TEMP TABLE batch (id UUID)")
	db.Exec("SELECT nextval('address_index_seq')")
}
`))
	assert.Empty(t, sqlFileRuleLines(t, NewSQLRuntimeDDLRule(), "db/migrations/0001_init.go", `package migrations

func Up(db DB) { db.Exec("CREATE TABLE a (id UUID)") }
`), "a migration")
}

// GROUP BY returns a row per group: QueryRow and Get read the first.
func TestSQLGroupBySingleRow(t *testing.T) {
	assert.Equal(t, []int{4, 9}, sqlFileRuleLines(t, NewSQLGroupBySingleRowRule(), "repo/metrics.go", `package repo

func Active(db DB, active *int) error {
	return db.GetContext(ctx, active, `+"`"+`SELECT COUNT(DISTINCT o.user_id) FROM orders o GROUP BY o.user_id HAVING SUM(o.amount) > 0`+"`"+`)
}

func Total(db DB) {
	query := "SELECT SUM(amount) FROM orders GROUP BY currency"
	db.QueryRowContext(ctx, query).Scan(&total)
	db.QueryRowContext(ctx, "SELECT user_id, SUM(amount) FROM orders WHERE user_id = $1 GROUP BY user_id", id)
	db.QueryContext(ctx, "SELECT currency, SUM(amount) FROM orders GROUP BY currency")
}
`))
}

// A fresh id never conflicts: the update never runs, every call inserts.
func TestSQLUpsertFreshKey(t *testing.T) {
	assert.Equal(t, []int{6, 10, 14}, sqlFileRuleLines(t, NewSQLUpsertFreshKeyRule(), "repo/transfers.go", `package repo

const upsert = "INSERT INTO transfers (id, tx_hash, status) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status"

func Save(db DB, hash, status string) {
	db.ExecContext(ctx, upsert, uuid.New(), hash, status)
	db.ExecContext(ctx, "INSERT INTO transfers (id, tx_hash, status) VALUES ($1, $2, $3) ON CONFLICT (tx_hash) DO UPDATE SET status = EXCLUDED.status",
		uuid.NewString(), hash, status)
	id := uuid.New().String()
	db.ExecContext(ctx, upsert,
		id, hash, status)
	db.ExecContext(ctx, upsert, existingID, hash, status)
	row := &Transfer{ID: uuid.New().String(), Hash: hash}
	db.ExecContext(ctx, upsert, row.ID, row.Hash, status)
}
`))
}
