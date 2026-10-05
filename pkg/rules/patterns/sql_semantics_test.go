package patterns

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// A date cut in the session's zone moves with the machine: the lookup of a
// row written on one machine misses it on another and writes it again.
func TestSQLSessionTimeZone(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": sqlSchemaMigration,
		"storage/db.go": `package storage

import "fmt"

func DSN(host, name string) string {
	return fmt.Sprintf("host=%s dbname=%s sslmode=disable", host, name)
}

var fields = []string{"name", "timezone"}
`,
		"storage/repo.go": `package storage

func Find(db DB, account string, day time.Time) {
	db.QueryRowContext(ctx, "SELECT id FROM positions WHERE account_id = $1 AND created_at::date = $2", account, day)
	db.QueryRowContext(ctx, "SELECT id FROM positions WHERE account_id = $1 AND created_at >= $2 AND created_at < $3", account, day, day.AddDate(0, 0, 1))
	db.QueryContext(ctx, "SELECT id FROM positions WHERE updated_at > CURRENT_DATE")
}
`,
	}
	assert.Equal(t, []int{4, 6}, sessionTimeZoneLines(t, files, "storage/repo.go"))
	assert.Equal(t, []int{6}, sessionTimeZoneLines(t, files, "storage/db.go"))

	files["storage/db.go"] = strings.Replace(files["storage/db.go"], "sslmode=disable", "sslmode=disable timezone=UTC", 1)
	assert.Empty(t, sessionTimeZoneLines(t, files, "storage/repo.go"))
	files["storage/db.go"] = strings.Replace(files["storage/db.go"], " timezone=UTC", "", 1) + `
func Params(config *pgx.ConnConfig) { config.RuntimeParams["timezone"] = "UTC" }
`
	assert.Empty(t, sessionTimeZoneLines(t, files, "storage/repo.go"))
	delete(files, "storage/db.go")
	assert.Empty(t, sessionTimeZoneLines(t, files, "storage/repo.go"), "the connection string comes from the environment")
}

// sessionTimeZoneLines loads files as a module, hands every file to the session
// time zone rule and returns the lines it reports in the file at path.
func sessionTimeZoneLines(t *testing.T, files map[string]string, path string) []int {
	t.Helper()
	_, contexts := rulestest.Module(t, files)
	rule := NewSQLSessionTimeZoneRule()
	for _, ctx := range contexts {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, ctx.Path, ctx.Content, parser.ParseComments)
		require.NoError(t, err)
		ctx.SetGoAST(fset, file)
	}
	rule.UseProjectFiles(contexts)
	for _, ctx := range contexts {
		if ctx.RelPath == path {
			return sqlRuleLines(t, rule, ctx)
		}
	}
	t.Fatal("no " + path)
	return nil
}

// A constant named as the table's column reads like the column: every row
// of the list shows the same amount.
func TestSQLConstantShadowsColumn(t *testing.T) {
	ctx := sqlSchemaProject(t, sqlSchemaMigration, `package storage

func (r *Repo) List(ctx context.Context, account string) {
	r.db.QueryContext(ctx, `+"`"+`
		SELECT p.id, 0 AS amount, p.created_at
		FROM positions p
		WHERE p.account_id = $1`+"`"+`, account)
	r.db.QueryContext(ctx, "SELECT p.id, '' AS kind, NULL AS amount FROM positions p")
	r.db.QueryContext(ctx, "SELECT p.id, 0 AS amount FROM positions p WHERE p.amount = 0")
}
`)
	assert.Equal(t, []int{5}, sqlRuleLines(t, NewSQLConstantShadowsColumnRule(), ctx))
}

// A test that creates a migrated table tests its own copy of the schema.
func TestSQLTestDDLDuplicatesMigration(t *testing.T) {
	ctx := rulestest.GoFile(t, "storage/repo_test.go", `package storage

func setup(db DB) {
	db.Exec(`+"`"+`CREATE TABLE IF NOT EXISTS positions (
		id UUID PRIMARY KEY,
		amount NUMERIC
	)`+"`"+`)
	db.Exec("CREATE TEMP TABLE accounts (id UUID)")
	db.Exec("CREATE TABLE fixtures (id INT)")
}
`)
	path := filepath.Join(ctx.ProjectRoot, "storage/migrations/001_init.up.sql")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(sqlSchemaMigration), 0o644))
	assert.Equal(t, []int{4}, sqlRuleLines(t, NewSQLTestDDLDuplicatesMigrationRule(), ctx))
}

// An update by id that matches no row succeeds having changed nothing; only
// the affected count tells the caller the row was not there.
func TestSQLMissingRowUnchecked(t *testing.T) {
	ctx := sqlSchemaProject(t, sqlSchemaMigration, `package storage

func (r *Repo) Update(ctx context.Context, p *Position) error {
	_, err := r.db.ExecContext(ctx, "UPDATE positions SET amount = $2 WHERE id = $1", p.ID, p.Amount)
	return err
}

func (r *Repo) Extend(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "UPDATE positions SET updated_at = now() WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		r.log.Warn("position not found", id)
	}
	return nil
}

func (r *Repo) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM positions WHERE id = $1", id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repo) Touch(ctx context.Context, account string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE positions SET updated_at = now() WHERE account_id = $1", account)
	return err
}

func (r *Repo) Close(ctx context.Context, id string) error {
	return r.db.QueryRowContext(ctx, "UPDATE positions SET amount = 0 WHERE id = $1 RETURNING id", id).Scan(&id)
}

func (r *Repo) Forget(ctx context.Context, id string) {
	r.db.ExecContext(ctx, "DELETE FROM positions WHERE id = $1", id)
}
`)
	assert.Equal(t, []int{4, 9}, sqlRuleLines(t, NewSQLMissingRowUncheckedRule(), ctx))
}

// An upsert whose DO UPDATE has a WHERE may change nothing: the caller that
// cannot tell runs its side effects (an auto-invest, a notification) for a
// webhook another request already applied.
func TestSQLMissingRowUncheckedConditionalUpsert(t *testing.T) {
	ctx := sqlSchemaProject(t, sqlSchemaMigration, `package storage

func (r *Repo) Upsert(ctx context.Context, p *Position) error {
	query := `+"`"+`INSERT INTO positions (id, account_id, amount, updated_at) VALUES ($1, $2, $3, now())
		ON CONFLICT (id) DO UPDATE SET amount = EXCLUDED.amount
		WHERE positions.amount != EXCLUDED.amount`+"`"+`
	_, err := r.db.ExecContext(ctx, query, p.ID, p.AccountID, p.Amount)
	return err
}

func (r *Repo) Save(ctx context.Context, p *Position) error {
	_, err := r.db.ExecContext(ctx, `+"`"+`INSERT INTO positions (id, account_id, amount, updated_at) VALUES ($1, $2, $3, now())
		ON CONFLICT (id) DO UPDATE SET amount = EXCLUDED.amount`+"`"+`, p.ID, p.AccountID, p.Amount)
	return err
}

func (r *Repo) Apply(ctx context.Context, p *Position) (bool, error) {
	result, err := r.db.ExecContext(ctx, `+"`"+`INSERT INTO positions (id, account_id, amount, updated_at) VALUES ($1, $2, $3, now())
		ON CONFLICT (id) DO UPDATE SET amount = EXCLUDED.amount WHERE positions.amount != EXCLUDED.amount`+"`"+`, p.ID, p.AccountID, p.Amount)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
`)
	assert.Equal(t, []int{7}, sqlRuleLines(t, NewSQLMissingRowUncheckedRule(), ctx))
}

// pgx returns the command tag: the count is read right in the condition.
func TestSQLMissingRowUncheckedTag(t *testing.T) {
	ctx := sqlSchemaProject(t, sqlSchemaMigration, `package storage

func (r *Repo) Claim(ctx context.Context, id string) (bool, error) {
	tag, err := r.pool.Exec(ctx, "UPDATE positions SET amount = 0 WHERE id = $1", id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *Repo) Reset(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, "UPDATE positions SET amount = 0 WHERE id = $1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}
`)
	assert.Empty(t, sqlRuleLines(t, NewSQLMissingRowUncheckedRule(), ctx))
}

// The query filters by a copy of the constant: a new system account added
// to the constants is still counted by it.
func TestSQLLiteralCopiesConstant(t *testing.T) {
	files := map[string]string{
		"accounts/system.go": `package accounts

const (
	SystemUserID  = "00000000-0000-0000-0000-000000000001"
	HoldingUserID = "00000000-0000-0000-0000-000000000002"
)
`,
		"stats/withdrawals.go": `package stats

func Totals(db DB) {
	db.Query(` + "`" + `SELECT SUM(amount) FROM withdrawals
		WHERE status = 'completed'
		  AND user_id NOT IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')` + "`" + `)
	db.Query("SELECT id FROM tenants WHERE id = '5f0c6b1e-6a53-4c43-9a5c-2d1f3e4b5a69'")
}
`,
	}
	_, contexts := rulestest.Module(t, files)
	for _, ctx := range contexts {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, ctx.Path, ctx.Content, parser.ParseComments)
		require.NoError(t, err)
		ctx.SetGoAST(fset, file)
	}
	rule := NewSQLLiteralCopiesConstantRule()
	rule.UseProjectFiles(contexts)
	var lines []int
	for _, ctx := range contexts {
		lines = append(lines, violationLines(rule.AnalyzeFile(ctx))...)
	}
	assert.Equal(t, []int{6, 6}, lines)
}

// Cohorts of one day burnt in plan order: a redemption takes another cohort
// when the plan changes.
func TestSQLLimitWithoutOrderDateOnlySort(t *testing.T) {
	_, contexts := rulestest.Module(t, map[string]string{
		"storage/migrations/001_init.up.sql": `CREATE TABLE cohorts (id UUID PRIMARY KEY, account_id UUID NOT NULL, event_date DATE NOT NULL, created_at TIMESTAMPTZ NOT NULL);`,
		"storage/repo.go": `package storage

func Cohorts(db DB, account string) {
	db.QueryContext(ctx, "SELECT * FROM cohorts WHERE account_id = $1 ORDER BY event_date ASC", account)
	db.QueryContext(ctx, "SELECT * FROM cohorts WHERE account_id = $1 ORDER BY event_date ASC, created_at ASC", account)
}
`,
	})
	for _, ctx := range contexts {
		if ctx.RelPath != "storage/repo.go" {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, ctx.Path, ctx.Content, parser.ParseComments)
		require.NoError(t, err)
		ctx.SetGoAST(fset, file)
		assert.Equal(t, []int{4}, sqlRuleLines(t, NewSQLLimitWithoutOrderRule(), ctx))
		return
	}
	t.Fatal("no storage/repo.go")
}
