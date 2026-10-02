package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfComparisons(t *testing.T) {
	sql := `EXISTS (SELECT 1 FROM members m WHERE m.org_id = $1 AND (m.email = email OR lower(m.email) = lower(email)))`
	assert.Equal(t, at(sql, "email OR", "email)))"), SelfComparisons(sql))
	sql = `SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM members m WHERE m.org_id = $$9 AND m.email = email)`
	assert.Len(t, SelfComparisons(sql), 1, "a subquery of a statement, a format verb after $")
	sql = `SELECT * FROM a JOIN b ON a.code = code WHERE a.id = ?`
	assert.Len(t, SelfComparisons(sql), 1, "a join condition, a bind variable")
	for _, allowed := range []string{
		`EXISTS (SELECT 1 FROM members m WHERE m.org_id = $1 AND m.email = o.email)`,
		`SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM members m WHERE m.email = o.email AND o.code = code)`,
		`SELECT id FROM orders WHERE status = $1`,
		`not sql at all`,
	} {
		assert.Empty(t, SelfComparisons(allowed), allowed)
	}
}

func TestUnscopedLinkUpdates(t *testing.T) {
	sql := `UPDATE entries SET batch_id = NULL, updated_at = NOW() WHERE account_id = $1 AND seq = $2`
	assert.Equal(t, []LinkUpdate{{Table: "entries", Column: "batch_id", Clears: true, Offset: at(sql, "batch_id")[0]}}, UnscopedLinkUpdates(sql))
	sql = `UPDATE entries SET batch_id = $1 WHERE account_id = $2`
	assert.Equal(t, []LinkUpdate{{Table: "entries", Column: "batch_id", Offset: at(sql, "batch_id")[0]}}, UnscopedLinkUpdates(sql))
	for _, allowed := range []string{
		`UPDATE entries SET batch_id = NULL WHERE account_id = $1 AND batch_id = $2`,
		`UPDATE entries SET batch_id = $1 WHERE id = $2 AND batch_id IS NULL`,
		`UPDATE entries SET batch_id = (SELECT id FROM batches WHERE code = $1) WHERE id = $2`,
		`UPDATE entries SET note = $1 WHERE id = $2`,
		`UPDATE entries SET batch_id = NULL`,
	} {
		assert.Empty(t, UnscopedLinkUpdates(allowed), allowed)
	}
}

func TestPartialKeyReads(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE payments (id UUID PRIMARY KEY, order_id UUID, status TEXT NOT NULL, ref TEXT, code TEXT, email TEXT, account_id UUID, note TEXT);
CREATE UNIQUE INDEX payments_live_order ON payments (order_id) WHERE order_id IS NOT NULL AND status <> 'void';
CREATE UNIQUE INDEX payments_ref ON payments (ref) WHERE ref IS NOT NULL;
CREATE UNIQUE INDEX payments_code ON payments (code) WHERE status = 'open';
DROP INDEX payments_code;
CREATE UNIQUE INDEX payments_email ON payments (LOWER(email)) WHERE email IS NOT NULL AND email <> '';
CREATE UNIQUE INDEX payments_account_note ON payments (account_id, note) WHERE note LIKE 'auto:%';`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	sql := `SELECT * FROM payments WHERE order_id = $1 FOR UPDATE`
	assert.Equal(t, at(sql, "order_id"), schema.PartialKeyReads(sql))
	for _, allowed := range []string{
		`SELECT * FROM payments WHERE order_id = $1 AND status <> 'void'`,
		`SELECT * FROM payments WHERE order_id = $1 ORDER BY id DESC LIMIT 1`,
		`SELECT * FROM payments WHERE ref = $1`,
		`SELECT * FROM payments WHERE code = $1`,
		`SELECT * FROM payments WHERE id = $1 AND order_id = $2`,
		`SELECT count(*) FROM payments WHERE order_id = $1`,
		`SELECT * FROM payments WHERE LOWER(email) = LOWER($1) AND email <> ''`,
		`SELECT * FROM payments WHERE account_id = $1 AND note = $2`,
	} {
		assert.Empty(t, schema.PartialKeyReads(allowed), allowed)
	}
}

func TestUnkeyedReferences(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE transactions (id UUID PRIMARY KEY, hash TEXT);
CREATE TABLE ledger_lines (id UUID PRIMARY KEY, chain_tx_id UUID, transaction_id UUID REFERENCES transactions(id), note_id TEXT);
CREATE TABLE notes (id UUID PRIMARY KEY, transaction_id UUID, legacy_transaction_id BIGINT);
CREATE TABLE links (id UUID PRIMARY KEY, source_transaction_id UUID, CONSTRAINT links_source FOREIGN KEY (source_transaction_id) REFERENCES transactions(id));
CREATE TABLE marks (id UUID PRIMARY KEY, transaction_id UUID, CONSTRAINT marks_tx FOREIGN KEY (transaction_id) REFERENCES transactions(id));
ALTER TABLE marks DROP CONSTRAINT marks_tx;`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	assert.Equal(t, []Reference{
		{Table: "ledger_lines", Column: "chain_tx_id"},
		{Table: "marks", Column: "transaction_id"},
		{Table: "notes", Column: "transaction_id"},
	}, schema.UnkeyedReferences("transactions"))
	assert.Empty(t, schema.UnkeyedReferences("notes"))
}

func TestDeletesAndUpdatesOnConflict(t *testing.T) {
	sql := "DELETE FROM transactions\n WHERE wallet = ? AND leg NOT IN (?)"
	assert.Equal(t, []Delete{{Table: "transactions", Offset: at(sql, "transactions")[0]}}, Deletes(sql))
	assert.True(t, UpdatesOnConflict(`INSERT INTO t (a, b) VALUES (:a, :b) ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b`))
	assert.False(t, UpdatesOnConflict(`INSERT INTO t (a, b) VALUES ($1, $2) ON CONFLICT DO NOTHING`))
}

func TestNamesTable(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE batches (id UUID PRIMARY KEY);
CREATE TABLE accounts (id UUID PRIMARY KEY);
CREATE TABLE entries (id UUID PRIMARY KEY, batch_id UUID, owner_id UUID REFERENCES accounts(id), chat_account_id TEXT, holder_id UUID);
CREATE TABLE holds (id UUID PRIMARY KEY, holder_id UUID REFERENCES accounts(id));`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	assert.True(t, schema.NamesTable("entries", "batch_id"))
	assert.True(t, schema.NamesTable("entries", "owner_id"))
	assert.False(t, schema.NamesTable("entries", "chat_account_id"))
	assert.False(t, schema.NamesTable("entries", "holder_id"), "a foreign key of another table's column of that name")
	assert.False(t, schema.NamesTable("entries", "batch"))
}
