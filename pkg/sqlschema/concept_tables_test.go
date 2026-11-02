package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The body of a CTE is read once, under the names the WITH defines before it;
// the walk over the rest of the SELECT leaves the WITH clause to that pass.
func TestReadTablesReadsCTEBodyOnce(t *testing.T) {
	reads := ReadTables("WITH a AS (SELECT * FROM users), b AS (SELECT * FROM a JOIN orders o ON o.id = a.id) SELECT * FROM b")
	tables := make([]string, 0, len(reads))
	for _, read := range reads {
		tables = append(tables, read.Table)
	}
	require.ElementsMatch(t, []string{"users", "orders"}, tables)
}
