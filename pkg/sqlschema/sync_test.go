package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func syncSchema(t *testing.T) *Schema {
	t.Helper()
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE journals (id UUID PRIMARY KEY, status TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE postings (id UUID PRIMARY KEY, journal_id UUID NOT NULL REFERENCES journals(id), account TEXT, amount NUMERIC, period TEXT);
CREATE TABLE batches (id UUID PRIMARY KEY, name TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE batch_members (batch_id UUID NOT NULL REFERENCES batches(id), member TEXT NOT NULL);
CREATE TABLE items (id UUID PRIMARY KEY, batch_id UUID REFERENCES batches(id), note TEXT);
CREATE TABLE notes (id UUID PRIMARY KEY, body TEXT);

CREATE OR REPLACE FUNCTION touch_row() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION audit_row() RETURNS TRIGGER AS $$
BEGIN
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER journals_touch BEFORE UPDATE ON journals FOR EACH ROW EXECUTE FUNCTION touch_row();
CREATE TRIGGER notes_touch AFTER UPDATE ON notes FOR EACH ROW EXECUTE FUNCTION touch_row();
CREATE TRIGGER batches_audit BEFORE UPDATE ON batches FOR EACH ROW EXECUTE FUNCTION audit_row();
`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	return schema
}

func TestStampedOnUpdate(t *testing.T) {
	schema := syncSchema(t)
	assert.Equal(t, "updated_at", schema.Table("journals").StampedOnUpdate())
	assert.Empty(t, schema.Table("notes").StampedOnUpdate(), "an AFTER trigger does not change the written row")
	assert.Empty(t, schema.Table("batches").StampedOnUpdate(), "a trigger function that stamps nothing")
	assert.True(t, schema.AnyStampedOnUpdate())
	assert.False(t, uniqueSchema(t).AnyStampedOnUpdate())
}

func TestStatusExclusions(t *testing.T) {
	schema := syncSchema(t)
	sql := `SELECT p.* FROM postings p JOIN journals j ON j.id = p.journal_id WHERE j.status <> 'reversed' AND p.period = $1`
	assert.Equal(t, []StatusExclusion{{Table: "journals", Column: "status", Values: []string{"reversed"}}}, schema.StatusExclusions(sql))
	sql = `SELECT id FROM journals WHERE status NOT IN ('void', 'cancelled', 'draft')`
	assert.Equal(t, []StatusExclusion{{Table: "journals", Column: "status", Values: []string{"void", "cancelled"}}}, schema.StatusExclusions(sql))
	for _, other := range []string{
		`SELECT id FROM journals WHERE status <> 'draft'`,
		`SELECT id FROM journals WHERE status = 'reversed'`,
		`SELECT id FROM journals WHERE status <> 'deleted'`,
		`SELECT p.id FROM postings p JOIN journals j ON j.id = p.journal_id WHERE status <> 'reversed'`,
	} {
		assert.Empty(t, schema.StatusExclusions(other), other)
	}
}

func TestChildReadsWithoutParent(t *testing.T) {
	schema := syncSchema(t)
	voided := map[string]bool{"journals": true}
	sql := `SELECT account, SUM(amount) FROM postings WHERE period = $1 GROUP BY account`
	assert.Equal(t, []ChildRead{{Child: "postings", Column: "journal_id", Parent: "journals", Offset: at(sql, "postings")[0]}}, schema.ChildReadsWithoutParent(sql, voided))
	for _, allowed := range []string{
		`SELECT p.account, SUM(p.amount) FROM postings p JOIN journals j ON j.id = p.journal_id WHERE j.status <> 'reversed' GROUP BY p.account`,
		`SELECT * FROM postings WHERE journal_id = $1`,
		`SELECT * FROM batch_members WHERE member = $1`,
		`SELECT * FROM postings WHERE period = $1`,
		`SELECT EXISTS (SELECT 1 FROM postings WHERE account = $1)`,
		`SELECT SUM(amount) FROM postings WHERE journal_id IN ($1, $2)`,
		`SELECT SUM(amount) FROM postings WHERE journal_id = ANY($1)`,
		`SELECT account, COUNT(*) FROM postings GROUP BY account`,
	} {
		assert.Empty(t, schema.ChildReadsWithoutParent(allowed, voided), allowed)
	}
	assert.Empty(t, schema.ChildReadsWithoutParent(sql, map[string]bool{"batches": true}))
	assert.Empty(t, schema.ChildReadsWithoutParent(`SELECT * FROM items WHERE note = $1`, map[string]bool{"batches": true}),
		"a nullable reference does not make the row a part of its parent")
}

func TestDeltaExports(t *testing.T) {
	assert.Equal(t, []string{"batches"}, DeltaExports(`SELECT * FROM batches WHERE updated_at >= $1 ORDER BY name`))
	assert.Equal(t, []string{"batches"}, DeltaExports(`SELECT b.* FROM batches b JOIN items i ON i.batch_id = b.id WHERE $1 < b.updated_at`))
	assert.Empty(t, DeltaExports(`SELECT * FROM batches WHERE updated_at < NOW() - INTERVAL '1 day'`))
	assert.Empty(t, DeltaExports(`SELECT * FROM batches WHERE created_at > $1`))
}

func TestParentUnlinks(t *testing.T) {
	schema := syncSchema(t)
	sql := `DELETE FROM batch_members WHERE batch_id = $1 AND member = $2`
	assert.Equal(t, []ParentUnlink{{Child: "batch_members", Column: "batch_id", Parent: "batches", Offset: at(sql, "batch_members")[0]}}, schema.ParentUnlinks(sql))
	sql = `UPDATE items SET batch_id = NULL WHERE batch_id = $1 AND id = $2`
	assert.Equal(t, []ParentUnlink{{Child: "items", Column: "batch_id", Parent: "batches", Offset: at(sql, "items")[0]}}, schema.ParentUnlinks(sql))
	for _, other := range []string{
		`DELETE FROM batch_members WHERE member = $1`,
		`UPDATE items SET note = NULL WHERE batch_id = $1`,
		`UPDATE items SET batch_id = NULL WHERE id = $1`,
	} {
		assert.Empty(t, schema.ParentUnlinks(other), other)
	}
	assert.Equal(t, []string{"batches", "items"}, UpdatedTables(`WITH gone AS (UPDATE items SET batch_id = NULL WHERE batch_id = $1 RETURNING id), touched AS (UPDATE batches SET updated_at = NOW() WHERE id = $1) SELECT COUNT(*) FROM gone`))
}

func TestStampOverwrites(t *testing.T) {
	schema := syncSchema(t)
	assert.Equal(t, []StampOverwrite{{Table: "journals", Column: "updated_at"}},
		schema.StampOverwrites(`UPDATE journals SET updated_at = NOW() - INTERVAL '30 days' WHERE id = $1`))
	assert.Empty(t, schema.StampOverwrites(`UPDATE journals SET updated_at = NOW(), status = 'x'`), "the trigger writes the same")
	assert.Empty(t, schema.StampOverwrites(`UPDATE journals SET updated_at = CURRENT_TIMESTAMP`))
	assert.Empty(t, schema.StampOverwrites(`UPDATE batches SET updated_at = $1`), "no stamping trigger")
	assert.Empty(t, schema.StampOverwrites(`UPDATE journals SET status = 'x'`))
}

// A trigger that stamps only when the status changes keeps the value of a
// write that leaves the status alone.
func TestStampOverwritesSkipsConditionalStamp(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE requests (id UUID PRIMARY KEY, status TEXT NOT NULL, status_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW());

CREATE OR REPLACE FUNCTION track_status() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.status_changed_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS requests_status ON requests;
CREATE TRIGGER requests_status BEFORE UPDATE ON requests FOR EACH ROW EXECUTE FUNCTION track_status();
`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	assert.Equal(t, "status_changed_at", schema.Table("requests").StampedOnUpdate())
	assert.Empty(t, schema.StampOverwrites(`UPDATE requests SET status_changed_at = NOW() - INTERVAL '5 days' WHERE id = $1`))
}
