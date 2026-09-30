package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSchema(t *testing.T) *Schema {
	t.Helper()
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE accounts (id UUID PRIMARY KEY, email TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', note TEXT);
CREATE TABLE positions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    amount NUMERIC NOT NULL,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL,
    comment TEXT
);
CREATE TABLE ledger (id BIGSERIAL PRIMARY KEY, ref TEXT, account_id UUID NOT NULL);
CREATE VIEW account_summary AS SELECT id FROM accounts;
`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	return schema
}

func problemTexts(problems []Problem) []string {
	var texts []string
	for _, p := range problems {
		texts = append(texts, p.Kind+":"+p.Name)
	}
	return texts
}

func TestCheckQueryUnknownColumnsAndTables(t *testing.T) {
	schema := testSchema(t)
	cases := []struct {
		sql  string
		want []string
	}{
		{"SELECT COALESCE(SUM(market_value - amount), 0) FROM positions WHERE account_id = $1", []string{"unknown_column:market_value"}},
		{"SELECT 1 FROM ledger WHERE chain_ref = $1", []string{"unknown_column:chain_ref"}},
		{"SELECT COUNT(*) FROM positions WHERE account_id = $1 AND status = 'active'", []string{"unknown_column:status"}},
		{"SELECT p.id, p.plan_id FROM positions p JOIN accounts a ON a.id = p.account_id", []string{"unknown_column:plan_id"}},
		{"SELECT 1 FROM team_members gm JOIN accounts a ON a.id = gm.account_id", []string{"unknown_table:team_members"}},
		// Known names, aliases, output names, CTEs, subqueries, views, excluded.
		{"SELECT a.id, a.email AS mail FROM accounts a WHERE a.status = $1 ORDER BY mail", nil},
		{"SELECT status, COUNT(*) AS n FROM accounts GROUP BY status HAVING COUNT(*) > 1 ORDER BY n", nil},
		{"WITH recent AS (SELECT account_id, amount FROM positions) SELECT account_id, total FROM recent r JOIN (SELECT id, 1 AS total FROM accounts) s ON s.id = r.account_id", nil},
		{"SELECT id, anything FROM account_summary", nil},
		{"SELECT x FROM unnest($1::text[]) AS t(x)", nil},
		{"INSERT INTO accounts (id, email) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET email = excluded.email, note = EXCLUDED.note", nil},
		{"UPDATE positions SET amount = $1, updated_at = now() WHERE id = $2", nil},
		{"UPDATE positions SET market_value = $1 WHERE id = $2", []string{"unknown_column:market_value"}},
		{"DELETE FROM ledger l USING accounts a WHERE a.id = l.account_id AND a.email = $1", nil},
		{"SELECT id FROM pg_catalog.pg_tables", nil},
		{"SELECT table_name FROM information_schema.columns WHERE table_name = $1", nil},
		{"SELECT id FROM accounts WHERE id IN (SELECT account_id FROM positions WHERE amount > 0)", nil},
		// FOR UPDATE OF names an alias; migration tools keep their own table.
		{"SELECT b.id FROM accounts b JOIN positions p ON p.account_id = b.id WHERE b.id = $1 FOR UPDATE OF b, p", nil},
		{"SELECT version, dirty FROM schema_migrations LIMIT 1", nil},
		{"SELECT version_id FROM goose_db_version", nil},
		// DDL in the code is not checked.
		{"CREATE TEMP TABLE staging (id UUID, amount NUMERIC)", nil},
	}
	for _, c := range cases {
		problems, ok := schema.CheckQuery(c.sql)
		require.True(t, ok, c.sql)
		assert.Equal(t, c.want, problemTexts(problems), c.sql)
	}
}

// An INSERT that lists its columns and leaves out a NOT NULL column without a
// default fails on every run.
func TestCheckQueryInsertMissingNotNull(t *testing.T) {
	schema := testSchema(t)
	problems, ok := schema.CheckQuery("INSERT INTO positions (id, account_id, amount, opened_at) VALUES ($1, $2, $3, now())")
	require.True(t, ok)
	assert.Equal(t, []string{"missing_not_null:updated_at"}, problemTexts(problems))

	problems, ok = schema.CheckQuery("INSERT INTO positions (account_id, amount, updated_at) SELECT id, 0, now() FROM accounts")
	require.True(t, ok)
	assert.Empty(t, problems)

	problems, ok = schema.CheckQuery("INSERT INTO positions VALUES ($1, $2, $3, now(), now(), NULL)")
	require.True(t, ok)
	assert.Empty(t, problems, "no column list: every column is given")
}

// The offset of a problem points at the name in the query text.
func TestCheckQueryLocations(t *testing.T) {
	schema := testSchema(t)
	sql := "SELECT id\nFROM ledger\nWHERE chain_ref = $1"
	problems, ok := schema.CheckQuery(sql)
	require.True(t, ok)
	require.Len(t, problems, 1)
	assert.Equal(t, "chain_ref", sql[problems[0].Offset:problems[0].Offset+len("chain_ref")])
}

// Text that is not a whole statement is not checked.
func TestCheckQueryFragments(t *testing.T) {
	schema := testSchema(t)
	for _, sql := range []string{"WHERE id = $1", "SELECT id FROM %s WHERE", "hello world"} {
		_, ok := schema.CheckQuery(sql)
		assert.False(t, ok, sql)
	}
}

// The shape of a statement: the table it writes or reads and its columns, in
// order, with the offset of the last one.
func TestShape(t *testing.T) {
	schema := testSchema(t)
	shape, ok := schema.Shape("INSERT INTO positions (id, account_id, amount) VALUES ($1, $2, $3)")
	require.True(t, ok)
	assert.Equal(t, "insert", shape.Kind)
	assert.Equal(t, "positions", shape.Table)
	assert.Equal(t, []string{"id", "account_id", "amount"}, shape.Columns)

	sql := "SELECT p.id, p.account_id, COALESCE(p.comment, '') AS comment, amount\nFROM positions p WHERE p.id = $1"
	shape, ok = schema.Shape(sql)
	require.True(t, ok)
	assert.Equal(t, "select", shape.Kind)
	assert.Equal(t, "positions", shape.Table)
	assert.Equal(t, []string{"id", "account_id", "comment", "amount"}, shape.Columns)
	assert.Equal(t, "amount", sql[shape.LastOffset:shape.LastOffset+len("amount")])

	shape, ok = schema.Shape("UPDATE positions SET amount = $1, comment = NULL WHERE id = $2")
	require.True(t, ok)
	assert.Equal(t, "update", shape.Kind)
	assert.Equal(t, []string{"amount", "comment"}, shape.Columns)

	_, ok = schema.Shape("SELECT a.id, p.id FROM accounts a JOIN positions p ON p.account_id = a.id")
	assert.False(t, ok, "two tables")
	_, ok = schema.Shape("SELECT * FROM positions")
	assert.False(t, ok, "star")
}

func TestGeneratedDefaults(t *testing.T) {
	schema := testSchema(t)
	positions := schema.Table("positions")
	assert.True(t, positions.Column("id").GeneratedDefault)
	assert.True(t, positions.Column("opened_at").GeneratedDefault)
	assert.False(t, schema.Table("accounts").Column("status").GeneratedDefault, "a constant default")
	assert.True(t, schema.Table("ledger").Column("id").GeneratedDefault, "serial")
}
