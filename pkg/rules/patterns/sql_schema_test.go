package patterns

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const sqlSchemaMigration = `
CREATE TABLE accounts (id UUID PRIMARY KEY, email TEXT NOT NULL, note TEXT);
CREATE TABLE positions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    amount NUMERIC NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE ledger (id BIGSERIAL PRIMARY KEY, ref TEXT);
`

// sqlSchemaProject writes a project with the migration and the Go file and
// returns the file's context.
func sqlSchemaProject(t *testing.T, migration, source string) *core.FileContext {
	t.Helper()
	ctx := rulestest.GoFile(t, "storage/repo.go", source)
	path := filepath.Join(ctx.ProjectRoot, "storage/migrations/001_init.up.sql")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(migration), 0o644))
	return ctx
}

func sqlRuleLines(t *testing.T, rule interface {
	AnalyzeFile(*core.FileContext) []*core.Violation
}, ctx *core.FileContext) []int {
	t.Helper()
	lines := violationLines(rule.AnalyzeFile(ctx))
	slices.Sort(lines)
	return lines
}

// A query naming a column or a table the migrations never created fails on
// its first run; the line is the one with the name.
func TestSQLUnknownColumn(t *testing.T) {
	source := "package storage\n\n" +
		"import \"fmt\"\n\n" +
		"const exists = \"SELECT 1 FROM ledger WHERE chain_ref = $1\"\n\n" +
		"func stats(table string) []string {\n" +
		"\treturn []string{\n" +
		"\t\t`SELECT COUNT(*), COALESCE(SUM(amount), 0)\n" +
		"\t\t FROM positions\n" +
		"\t\t WHERE account_id = $1 AND status = 'active'`,\n" +
		"\t\t\"SELECT p.id, a.email \" +\n" +
		"\t\t\t\"FROM positions p JOIN accounts a ON a.id = p.account_id \" +\n" +
		"\t\t\t\"WHERE p.market_value > p.amount\",\n" +
		"\t\tfmt.Sprintf(\"SELECT id FROM accounts WHERE id IN (%s) AND nickname = $1\", table),\n" +
		"\t\t\"SELECT 1 FROM team_members WHERE account_id = $1\",\n" +
		"\t\t\"SELECT id, email FROM accounts WHERE note IS NULL\",\n" +
		"\t\t\"SELECT id FROM \" + table + \" WHERE missing = $1\",\n" +
		"\t\t\"select the option you want\",\n" +
		"\t}\n" +
		"}\n"
	ctx := sqlSchemaProject(t, sqlSchemaMigration, source)
	assert.Equal(t, []int{5, 11, 14, 15, 16}, sqlRuleLines(t, NewSQLUnknownColumnRule(), ctx))
}

// An INSERT listing its columns without a NOT NULL column that has no default
// fails on every run.
func TestSQLInsertMissingNotNull(t *testing.T) {
	source := "package storage\n\n" +
		"const insertPosition = `INSERT INTO positions (id, account_id, amount)\n" +
		"VALUES ($1, $2, $3)`\n\n" +
		"const insertFull = `INSERT INTO positions (account_id, amount, updated_at) VALUES ($1, $2, now())`\n"
	ctx := sqlSchemaProject(t, sqlSchemaMigration, source)
	assert.Equal(t, []int{3}, sqlRuleLines(t, NewSQLInsertMissingNotNullRule(), ctx))
}

// A migration that does not parse is reported on the migration: the schema
// rules checked nothing.
func TestSQLUnknownColumnReportsBrokenMigration(t *testing.T) {
	ctx := sqlSchemaProject(t, "CREATE TABLE accounts (id UUID", "package storage\n\nconst q = \"SELECT id FROM accounts\"\n")
	assert.Empty(t, NewSQLUnknownColumnRule().AnalyzeFile(ctx), "the Go file is not checked")
	migration := migrationContext(t, ctx, "storage/migrations/001_init.up.sql")
	for _, rule := range []interface {
		AnalyzeFile(*core.FileContext) []*core.Violation
	}{NewSQLUnknownColumnRule(), NewSQLInsertMissingNotNullRule()} {
		violations := rule.AnalyzeFile(migration)
		require.Len(t, violations, 1)
		assert.Equal(t, "storage/migrations/001_init.up.sql", violations[0].File)
		assert.Equal(t, core.SeverityCritical, violations[0].Severity)
	}
}

// migrationContext returns the context of a migration of the project of ctx.
func migrationContext(t *testing.T, ctx *core.FileContext, rel string) *core.FileContext {
	t.Helper()
	path := filepath.Join(ctx.ProjectRoot, rel)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	migration, err := core.NewFileContextChecked(path, ctx.ProjectRoot, content, core.DefaultConfig())
	require.NoError(t, err)
	return migration
}

// A temporary table the file creates is known to the statements beside it.
func TestSQLUnknownColumnTempTable(t *testing.T) {
	source := "package storage\n\n" +
		"const createStaging = `CREATE TEMP TABLE staging (id UUID, amount NUMERIC) ON COMMIT DROP`\n\n" +
		"const countStaging = `SELECT count(*), min(amount) FROM staging`\n\n" +
		"const countMissing = `SELECT count(*) FROM staging WHERE missing = $1`\n"
	ctx := sqlSchemaProject(t, sqlSchemaMigration, source)
	assert.Equal(t, []int{7}, sqlRuleLines(t, NewSQLUnknownColumnRule(), ctx))
}

// An ALTER of a table a later migration creates is reported on the migration:
// a fresh database fails there. Queries see the change.
func TestSQLUnknownColumnReportsAlterBeforeCreate(t *testing.T) {
	ctx := rulestest.GoFile(t, "storage/repo.go", "package storage\n\nconst q = \"SELECT id, category FROM conversations\"\n")
	for name, content := range map[string]string{
		"storage/migrations/001_categories.up.sql":    "\nALTER TABLE conversations ADD COLUMN category TEXT;\n",
		"storage/migrations/002_conversations.up.sql": "CREATE TABLE conversations (id UUID PRIMARY KEY);\n",
	} {
		path := filepath.Join(ctx.ProjectRoot, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	assert.Empty(t, NewSQLUnknownColumnRule().AnalyzeFile(ctx), "category is in the table")
	migration := migrationContext(t, ctx, "storage/migrations/001_categories.up.sql")
	violations := NewSQLUnknownColumnRule().AnalyzeFile(migration)
	require.Len(t, violations, 1)
	assert.Equal(t, "storage/migrations/001_categories.up.sql", violations[0].File)
	assert.Equal(t, 2, violations[0].Line)
	assert.Empty(t, NewSQLInsertMissingNotNullRule().AnalyzeFile(migration), "one rule reports the migration")
	assert.Empty(t, NewSQLUnknownColumnRule().AnalyzeFile(migrationContext(t, ctx, "storage/migrations/002_conversations.up.sql")))
}
