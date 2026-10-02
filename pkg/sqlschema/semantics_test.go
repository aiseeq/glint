package sqlschema

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// at returns the offsets of a marker in the text: where a finding points.
func at(sql string, markers ...string) []int {
	var offsets []int
	for _, m := range markers {
		offsets = append(offsets, strings.Index(sql, m))
	}
	return offsets
}

func TestUnorderedLimits(t *testing.T) {
	var none *Schema
	sql := `SELECT a.id, (SELECT address FROM wallets w WHERE w.account_id = a.id LIMIT 1) AS address FROM accounts a`
	assert.Equal(t, at(sql, "1)"), none.UnorderedLimits(sql))
	sql = `SELECT id FROM positions WHERE account_id = $1 LIMIT $2 OFFSET $3`
	assert.Equal(t, at(sql, "$2"), none.UnorderedLimits(sql), "a page with no order")

	for _, allowed := range []string{
		`SELECT id FROM positions WHERE account_id = $1 ORDER BY opened_at DESC LIMIT 1`,
		`SELECT EXISTS (SELECT 1 FROM positions WHERE account_id = $1 LIMIT 1)`,
		`SELECT count(*) FROM positions LIMIT 1`,
		`SELECT id FROM jobs WHERE status = 'new' LIMIT 10 FOR UPDATE SKIP LOCKED`,
		`SELECT email FROM accounts WHERE id = $1 LIMIT 1`,
		`SELECT id FROM a UNION SELECT id FROM b ORDER BY id LIMIT 5`,
		`SELECT version FROM schema_migrations LIMIT 1`,
	} {
		assert.Empty(t, none.UnorderedLimits(allowed), allowed)
	}
}

// A unique key the WHERE fixes makes one row: a lookup by email or by a
// unique reference is not an arbitrary pick.
func TestUnorderedLimitsUniqueKey(t *testing.T) {
	schema := uniqueSchema(t)
	assert.Empty(t, schema.UnorderedLimits(`SELECT id FROM members WHERE lower(email) = lower($1) LIMIT 1`))
	assert.Empty(t, schema.UnorderedLimits(`SELECT id FROM members WHERE external_ref = $1 LIMIT 1`))
	assert.Empty(t, schema.UnorderedLimits(`SELECT id FROM members WHERE org_id = $1 AND code = $2 LIMIT 1`))
	sql := `SELECT id FROM members WHERE org_id = $1 LIMIT 1`
	assert.Len(t, schema.UnorderedLimits(sql), 1, "one column of a two-column key")
	assert.Len(t, schema.UnorderedLimits(`SELECT id FROM members WHERE nickname = $1 LIMIT 1`), 1, "the unique index was dropped")
	assert.Len(t, schema.UnorderedLimits(`SELECT m.id FROM members m JOIN roles r ON r.member_id = m.id WHERE m.email = $1 LIMIT 1`), 1, "a join makes many rows")
}

func uniqueSchema(t *testing.T) *Schema {
	t.Helper()
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE members (id UUID PRIMARY KEY, email TEXT NOT NULL, external_ref TEXT UNIQUE, org_id UUID, code TEXT, nickname TEXT,
    CONSTRAINT members_org_code UNIQUE (org_id, code));
CREATE UNIQUE INDEX members_email_idx ON members (lower(email));
CREATE UNIQUE INDEX members_nickname_idx ON members (nickname);
CREATE TABLE roles (member_id UUID NOT NULL, name TEXT NOT NULL);
`,
		"migrations/002_drop.up.sql": `DROP INDEX members_nickname_idx;`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	return schema
}

func TestDefinesSchema(t *testing.T) {
	assert.True(t, DefinesSchema(`CREATE SEQUENCE IF NOT EXISTS address_seq START WITH 1`))
	assert.True(t, DefinesSchema(`ALTER TABLE accounts ADD COLUMN note TEXT`))
	assert.True(t, DefinesSchema(`CREATE INDEX IF NOT EXISTS idx ON accounts (email)`))
	assert.False(t, DefinesSchema(`CREATE TEMP TABLE batch (id UUID)`))
	assert.False(t, DefinesSchema(`CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY)`), "a migrator's own table")
	assert.False(t, DefinesSchema(`SELECT 1`))
}

func TestGroupedRows(t *testing.T) {
	var none *Schema
	assert.True(t, none.GroupedRows(`SELECT COUNT(DISTINCT user_id) FROM positions WHERE amount > 0 GROUP BY account_id HAVING COUNT(*) > 1`))
	assert.False(t, none.GroupedRows(`SELECT account_id, SUM(amount) FROM positions WHERE account_id = $1 GROUP BY account_id`), "the key is fixed")
	assert.False(t, none.GroupedRows(`SELECT account_id, SUM(amount) FROM positions GROUP BY account_id ORDER BY 2 DESC LIMIT 1`))
	assert.False(t, none.GroupedRows(`SELECT COUNT(*) FROM (SELECT account_id FROM positions GROUP BY account_id) g`), "grouped inside, one row outside")
	schema := uniqueSchema(t)
	assert.False(t, schema.GroupedRows(`SELECT m.id, m.email, MIN(r.name) FROM members m LEFT JOIN roles r ON r.member_id = m.id
		WHERE m.external_ref = $1 GROUP BY m.id, m.email`), "the member is fixed by a unique key")
	assert.True(t, schema.GroupedRows(`SELECT m.id, MIN(r.name) FROM members m LEFT JOIN roles r ON r.member_id = m.id
		WHERE m.org_id = $1 GROUP BY m.id`), "an organisation has many members")
}

func TestConflictParams(t *testing.T) {
	sql := `INSERT INTO ledger (id, ref, account_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET ref = EXCLUDED.ref`
	params, offset, ok := ConflictParams(sql)
	assert.True(t, ok)
	assert.Equal(t, map[string]int{"id": 1}, params)
	assert.Equal(t, strings.Index(sql, "ON CONFLICT"), offset)
	_, _, ok = ConflictParams(`INSERT INTO ledger (id, ref) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`)
	assert.False(t, ok)
}

func TestSessionDates(t *testing.T) {
	schema := testSchema(t)
	sql := `SELECT id FROM positions WHERE account_id = $1 AND opened_at::date = $2 AND date_trunc('day', updated_at) = CURRENT_DATE`
	assert.Equal(t, at(sql, "::date", "date_trunc", "CURRENT_DATE"), schema.SessionDates(sql))
	for _, allowed := range []string{
		`SELECT id FROM positions WHERE (opened_at AT TIME ZONE 'UTC')::date = $1`,
		`SELECT id FROM positions WHERE opened_at >= $1 AND opened_at < $2`,
		`SELECT id FROM accounts WHERE note::date = $1`,
	} {
		assert.Empty(t, schema.SessionDates(allowed), allowed)
	}
}

func TestRowWrite(t *testing.T) {
	schema := uniqueSchema(t)
	for _, sql := range []string{
		`UPDATE members SET code = $2 WHERE id = $1`,
		`DELETE FROM members WHERE external_ref = $1 AND code IS NULL`,
		`UPDATE members SET code = $3 WHERE org_id = $1 AND code = $2`,
	} {
		assert.True(t, schema.RowWrite(sql), sql)
	}
	for _, sql := range []string{
		`UPDATE members SET code = $2 WHERE id = $1 RETURNING id`,
		`UPDATE members SET code = $1 WHERE code IS NULL`,
		`DELETE FROM members WHERE nickname = $1`,
		`UPDATE members SET code = $1 WHERE id = 'singleton'`,
		`UPDATE members SET code = $2 WHERE id = $1 AND code IS NULL`,
		`UPDATE members SET nickname = $2 WHERE external_ref = $1 AND (nickname IS NULL OR nickname <> $2)`,
		`INSERT INTO members (id) VALUES ($1)`,
		`UPDATE members SET code = $2 WHERE id = $1; UPDATE members SET code = $2 WHERE id = $3`,
	} {
		assert.False(t, schema.RowWrite(sql), sql)
	}
}

// A column changed to timestamptz by a later migration cuts its dates in the
// session's zone from then on.
func TestSessionDatesAfterTypeChange(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql":  `CREATE TABLE holdings (id UUID PRIMARY KEY, closed_at TIMESTAMP, opened_at TIMESTAMPTZ);`,
		"migrations/002_zones.up.sql": `ALTER TABLE holdings ALTER COLUMN closed_at TYPE TIMESTAMPTZ USING closed_at AT TIME ZONE 'UTC';`,
		"migrations/003_naive.up.sql": `ALTER TABLE holdings ALTER COLUMN opened_at SET DATA TYPE TIMESTAMP;`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	assert.Equal(t, "timestamptz", schema.Table("holdings").Column("closed_at").Type)
	assert.Equal(t, "timestamp", schema.Table("holdings").Column("opened_at").Type)
	sql := `SELECT id FROM holdings WHERE closed_at::date = $1 AND opened_at::date = $1`
	assert.Equal(t, at(sql, "::date"), schema.SessionDates(sql))
}

// A constant named as a real column reads like the column: every row of the
// branch shows 'done' whatever the table holds.
func TestConstantColumns(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE payouts (id UUID PRIMARY KEY, account_id UUID, kind TEXT, state TEXT, receipt TEXT);
CREATE TABLE payout_requests (id UUID PRIMARY KEY, account_id UUID, kind TEXT, state TEXT);
CREATE TABLE accounts (id UUID PRIMARY KEY, email TEXT);
`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	sql := `SELECT * FROM (
		SELECT r.id, 'payout' AS kind, r.state, '' AS receipt, '' AS note FROM payout_requests r WHERE r.account_id = $1 AND r.kind = 'payout'
		UNION ALL
		SELECT p.id, 'payout' AS kind, 'done' AS state, p.receipt, '' AS note FROM payouts p LEFT JOIN accounts a ON a.id = p.account_id WHERE p.account_id = $2 AND p.kind = 'payout'
	) rows ORDER BY id`
	assert.Equal(t, at(sql, "'done'"), schema.ConstantColumns(sql))

	for _, allowed := range []string{
		`INSERT INTO payouts (id, state) SELECT id, 'done' AS state FROM payout_requests WHERE id = $1`,
		`SELECT 'done' AS state`,
		`SELECT p.id, NULL AS state FROM payouts p`,
		`SELECT p.id, '' AS state FROM payouts p`,
		`SELECT p.id, 'paid' AS state FROM payouts p UNION ALL SELECT r.id, 'asked' AS state FROM payout_requests r`,
		`SELECT p.id, 'done' AS status FROM payouts p`,
		`SELECT p.id, 'done' AS state FROM payouts p WHERE p.state = 'done'`,
	} {
		assert.Empty(t, schema.ConstantColumns(allowed), allowed)
	}
	var none *Schema
	assert.Empty(t, none.ConstantColumns(sql))
}

// A test that creates a migrated table again keeps its own copy of the
// definition, and the copy stays as the migrations move on.
func TestMigratedTables(t *testing.T) {
	schema := uniqueSchema(t)
	sql := `CREATE TABLE IF NOT EXISTS members (id UUID PRIMARY KEY, email TEXT);
CREATE TABLE scratch (id INT);
CREATE TEMP TABLE roles (member_id UUID);`
	assert.Equal(t, at(sql, "members"), schema.MigratedTables(sql))
	var none *Schema
	assert.Empty(t, none.MigratedTables(sql))
}

// Rows ordered by a date alone: rows of one day come in plan order, and a
// FIFO consumer takes them in an order that changes with the plan.
func TestDateOnlyOrders(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE cohorts (id UUID PRIMARY KEY, account_id UUID NOT NULL, event_date DATE NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE daily (account_id UUID NOT NULL, day DATE NOT NULL, amount NUMERIC, UNIQUE (account_id, day));`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	sql := `SELECT * FROM cohorts WHERE account_id = $1 ORDER BY event_date ASC`
	assert.Equal(t, at(sql, "event_date ASC"), schema.DateOnlyOrders(sql))
	for _, allowed := range []string{
		`SELECT * FROM cohorts WHERE account_id = $1 ORDER BY event_date ASC, created_at ASC`,
		`SELECT * FROM cohorts WHERE account_id = $1 ORDER BY created_at`,
		`SELECT * FROM daily WHERE account_id = $1 ORDER BY day`,
		`SELECT event_date, count(*) FROM cohorts GROUP BY event_date ORDER BY event_date`,
		`SELECT c.* FROM cohorts c JOIN daily d ON d.account_id = c.account_id ORDER BY c.event_date`,
		`SELECT event_date FROM cohorts WHERE event_date <= $1 ORDER BY event_date DESC LIMIT 1`,
		`SELECT a.id, s.amount FROM accounts a LEFT JOIN LATERAL (SELECT amount FROM daily WHERE account_id = a.id AND day <= $1 ORDER BY day DESC LIMIT 1) s ON true`,
	} {
		assert.Empty(t, schema.DateOnlyOrders(allowed), allowed)
	}
}

func TestReturningMayBeEmpty(t *testing.T) {
	assert.True(t, ReturningMayBeEmpty(`INSERT INTO sync (id, wallet) VALUES ($1, $2) ON CONFLICT (wallet) DO NOTHING RETURNING *`))
	assert.True(t, ReturningMayBeEmpty(`INSERT INTO sync (id, wallet) VALUES ($1, $2) ON CONFLICT (wallet) DO UPDATE SET id = EXCLUDED.id WHERE sync.id < EXCLUDED.id RETURNING id`))
	assert.False(t, ReturningMayBeEmpty(`INSERT INTO sync (id, wallet) VALUES ($1, $2) ON CONFLICT (wallet) DO UPDATE SET id = EXCLUDED.id RETURNING id`))
	assert.False(t, ReturningMayBeEmpty(`INSERT INTO sync (id, wallet) VALUES ($1, $2) ON CONFLICT (wallet) DO NOTHING`))
	assert.False(t, ReturningMayBeEmpty(`INSERT INTO sync (id, wallet) VALUES ($1, $2) RETURNING id`))
}
