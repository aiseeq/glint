package sqlschema

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeMigrations(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
}

// The schema at the last migration: tables and columns created, added,
// renamed and dropped in version order; NOT NULL and defaults as the last
// statement left them. Down migrations and test DDL are not the schema.
func TestLoadFollowsMigrationsInOrder(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"storage/migrations/000001_init.up.sql": `
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    nickname TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS orders (
    id BIGSERIAL,
    user_id UUID NOT NULL REFERENCES users(id),
    amount NUMERIC(20, 8) NOT NULL,
    note TEXT,
    PRIMARY KEY (id)
);
CREATE TABLE legacy (id INT);
-- a comment; with a semicolon
CREATE FUNCTION touch() RETURNS trigger AS $$ BEGIN NEW.updated_at = now(); RETURN NEW; END $$ LANGUAGE plpgsql;
`,
		"storage/migrations/000001_init.down.sql": `DROP TABLE orders; DROP TABLE users;`,
		"storage/migrations/000002_status.up.sql": `
ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'new', ADD COLUMN updated_at TIMESTAMPTZ NOT NULL;
ALTER TABLE orders ALTER COLUMN note SET NOT NULL;
ALTER TABLE users RENAME COLUMN nickname TO display_name;
ALTER TABLE orders DROP COLUMN amount;
ALTER TABLE orders ADD COLUMN amount_minor BIGINT;
ALTER TABLE orders ALTER COLUMN amount_minor SET DEFAULT 0;
DROP TABLE legacy;
ALTER TABLE users RENAME TO accounts;
CREATE VIEW active_accounts AS SELECT id, email FROM accounts;
`,
		"tests/migrations/000001_extra.up.sql": `CREATE TABLE only_in_tests (id INT);`,
	})

	schema, err := Load(root, nil)
	require.NoError(t, err)

	accounts := schema.Table("accounts")
	require.NotNil(t, accounts)
	assert.Equal(t, []string{"id", "email", "display_name", "created_at"}, accounts.Columns())
	assert.Nil(t, schema.Table("users"))
	assert.Nil(t, schema.Table("legacy"))
	assert.Nil(t, schema.Table("only_in_tests"))

	orders := schema.Table("orders")
	require.NotNil(t, orders)
	assert.Equal(t, []string{"id", "user_id", "note", "status", "updated_at", "amount_minor"}, orders.Columns())
	assert.True(t, orders.Column("id").NotNull, "primary key")
	assert.True(t, orders.Column("id").HasDefault, "serial")
	assert.True(t, orders.Column("note").NotNull)
	assert.False(t, orders.Column("note").HasDefault)
	assert.True(t, orders.Column("status").HasDefault)
	assert.True(t, orders.Column("updated_at").NotNull)
	assert.False(t, orders.Column("updated_at").HasDefault)
	assert.True(t, orders.Column("amount_minor").HasDefault)
	assert.False(t, orders.Column("amount_minor").NotNull)

	view := schema.Table("active_accounts")
	require.NotNil(t, view)
	assert.True(t, view.View)
}

// A migration that does not parse is an error of the analysis: a schema
// missing its tables would report every query against them.
func TestLoadReportsUnparsableMigration(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/000001_init.up.sql": `CREATE TABLE users (id UUID PRIMARY KEY`,
	})
	_, err := Load(root, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "000001_init.up.sql")
}

// A project without migrations has no schema to check against.
func TestLoadWithoutMigrations(t *testing.T) {
	schema, err := Load(t.TempDir(), nil)
	require.NoError(t, err)
	assert.Nil(t, schema)
}

// Configured directories replace the search.
func TestLoadConfiguredDirectories(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"db/schema/001_init.up.sql":       `CREATE TABLE a (id INT);`,
		"storage/migrations/001.up.sql":   `CREATE TABLE b (id INT);`,
		"db/schema/002_more.sql":          `CREATE TABLE c (id INT);`,
		"db/schema/002_more.down.sql":     `DROP TABLE c;`,
		"db/schema/003_goose.sql":         "-- +goose Up\nCREATE TABLE d (id INT);\n-- +goose Down\nDROP TABLE d;\n",
		"db/schema/README.md":             `not sql`,
		"db/schema/004_second.up.sql":     `ALTER TABLE a ADD COLUMN name TEXT;`,
		"storage/migrations/002.down.sql": `DROP TABLE b;`,
	})
	schema, err := Load(root, []string{"db/schema"})
	require.NoError(t, err)
	require.NotNil(t, schema)
	assert.NotNil(t, schema.Table("a"))
	assert.Nil(t, schema.Table("b"))
	assert.NotNil(t, schema.Table("c"))
	assert.NotNil(t, schema.Table("d"))
	assert.Equal(t, []string{"id", "name"}, schema.Table("a").Columns())
}

// An ALTER of a table a later migration creates fails on a fresh database: it
// is a fault of the migration, and the change still reaches the table, as on
// a database that had the table when the migration ran.
func TestLoadAlterBeforeCreate(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_categories.up.sql":    "-- categories\n\nALTER TABLE conversations\n    ADD COLUMN category TEXT NOT NULL DEFAULT 'none';\nALTER TABLE conversations ADD CONSTRAINT category_check CHECK (category <> '');\nALTER TABLE IF EXISTS archive ADD COLUMN note TEXT;\n",
		"migrations/002_conversations.up.sql": "CREATE TABLE conversations (id UUID PRIMARY KEY);\n",
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	require.Len(t, schema.Faults, 1)
	assert.Equal(t, filepath.Join(root, "migrations/001_categories.up.sql"), schema.Faults[0].Path)
	assert.Equal(t, 3, schema.Faults[0].Line)
	assert.Equal(t, "conversations", schema.Faults[0].Table)
	assert.Equal(t, []string{"id", "category"}, schema.Table("conversations").Columns())
}

// Tables the code creates, a temporary one for instance, join the schema for
// the statements beside them; the schema itself stays as the migrations
// leave it.
func TestWithCreatedTables(t *testing.T) {
	schema := testSchema(t)
	local := schema.With([]string{
		"CREATE TEMP TABLE staging (id UUID, amount NUMERIC) ON COMMIT DROP",
		"SELECT id FROM accounts",
	})
	problems, ok := local.CheckQuery("SELECT count(*), min(amount) FROM staging")
	require.True(t, ok)
	assert.Empty(t, problems)
	problems, ok = schema.CheckQuery("SELECT count(*) FROM staging")
	require.True(t, ok)
	assert.Equal(t, []string{"unknown_table:staging"}, problemTexts(problems))
}
