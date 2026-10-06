package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A CHECK keeping a column within a set or a range is kept on the column,
// under its own name or the one PostgreSQL makes, until a migration drops it.
func TestValueChecks(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE items (
    id UUID PRIMARY KEY,
    category VARCHAR(32) NOT NULL CHECK (category IN ('dex', 'lending')),
    score SMALLINT CHECK (score BETWEEN 1 AND 10),
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    amount NUMERIC CHECK (amount > 0),
    CONSTRAINT items_kind_valid CHECK (kind IN ('a', 'b')),
    CONSTRAINT items_status_not CHECK (status NOT IN ('x'))
);
`,
		"migrations/002_kind.up.sql": `
ALTER TABLE items DROP CONSTRAINT items_kind_valid;
ALTER TABLE items ADD CONSTRAINT items_kind_valid CHECK (kind IN ('a', 'b', 'c'));
ALTER TABLE items DROP CONSTRAINT items_score_check;
`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	items := schema.Table("items")
	require.NotNil(t, items)

	require.NotNil(t, items.Column("category").Check)
	assert.Equal(t, "category IN ('dex', 'lending')", items.Column("category").Check.String("category"))
	assert.Equal(t, "items_category_check", items.Column("category").Check.Name)
	require.NotNil(t, items.Column("kind").Check)
	assert.Equal(t, []string{"a", "b", "c"}, items.Column("kind").Check.Values)
	assert.Nil(t, items.Column("score").Check, "dropped by its default name")
	assert.Nil(t, items.Column("status").Check, "NOT IN keeps no set")
	assert.Nil(t, items.Column("amount").Check, "a comparison is not a set or a range")
}

// BETWEEN keeps its bounds.
func TestValueCheckRange(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `CREATE TABLE scores (id INT PRIMARY KEY, score SMALLINT CHECK (score BETWEEN 1 AND 10));`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)
	check := schema.Table("scores").Column("score").Check
	require.NotNil(t, check)
	assert.Equal(t, "score BETWEEN 1 AND 10", check.String("score"))
}
