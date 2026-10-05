package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRestrictingReferencesAndUniqueConflicts(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{
		"migrations/001_init.up.sql": `
CREATE TABLE tariffs (
    id SERIAL PRIMARY KEY,
    project_id INT NOT NULL,
    corridor TEXT NOT NULL,
    note TEXT,
    CONSTRAINT tariffs_project_corridor_key UNIQUE (project_id, corridor)
);
CREATE TABLE link_codes (code TEXT PRIMARY KEY, user_id INT NOT NULL);
CREATE TABLE report_links (id SERIAL PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE);
CREATE TABLE orders (
    id UUID PRIMARY KEY,
    tariff_id INT REFERENCES tariffs(id),
    archived_tariff_id INT REFERENCES tariffs(id) ON DELETE SET NULL
);
CREATE TABLE order_notes (
    order_id UUID NOT NULL,
    tariff_id INT,
    CONSTRAINT order_notes_tariff_fkey FOREIGN KEY (tariff_id) REFERENCES tariffs(id) ON DELETE RESTRICT,
    CONSTRAINT order_notes_order_fkey FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
);
`,
	})
	schema, err := Load(root, nil)
	require.NoError(t, err)

	assert.Equal(t, []Reference{{Table: "order_notes", Column: "tariff_id"}, {Table: "orders", Column: "tariff_id"}}, schema.RestrictingReferences("tariffs"))
	assert.Empty(t, schema.RestrictingReferences("orders"))

	conflicts := schema.UniqueConflicts(`INSERT INTO tariffs (project_id, corridor, note) VALUES ($1, $2, $3) RETURNING id`)
	require.Len(t, conflicts, 1)
	assert.Equal(t, []string{"project_id", "corridor"}, conflicts[0].Key)
	assert.Empty(t, schema.UniqueConflicts(`INSERT INTO tariffs (project_id, corridor) VALUES ($1, $2) ON CONFLICT DO NOTHING`))
	assert.Empty(t, schema.UniqueConflicts(`INSERT INTO tariffs (project_id, note) VALUES ($1, $2)`))
	assert.Empty(t, schema.UniqueConflicts(`INSERT INTO orders (id, tariff_id) VALUES ($1, $2)`))
	assert.Empty(t, schema.UniqueConflicts(`INSERT INTO link_codes (code, user_id) VALUES ($1, $2)`))
	assert.Empty(t, schema.UniqueConflicts(`INSERT INTO report_links (token_hash) VALUES ($1)`))
}
