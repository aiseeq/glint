package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The columns a SELECT returns: the name the row has, as PostgreSQL names it,
// and whether the value can be NULL.
func TestSelectTargets(t *testing.T) {
	schema := testSchema(t)
	sql := "SELECT p.id, p.comment, COALESCE(a.email, '') AS email, a.email AS owner_email, amount,\n" +
		"  count(*), EXISTS(SELECT 1 FROM ledger), $1::text, a.note::text, (SELECT max(id) FROM ledger) AS top, x.v\n" +
		"FROM positions p LEFT JOIN accounts a ON a.id = p.account_id, unnest($2::int[]) AS x(v) WHERE $9"
	targets, ok := SelectTargets(sql, schema)
	require.True(t, ok)
	type row struct {
		Name     string
		Nullable bool
	}
	var got []row
	for _, target := range targets {
		got = append(got, row{target.Name, target.Nullable})
	}
	assert.Equal(t, []row{
		{"id", false}, {"comment", true}, {"email", false}, {"owner_email", true}, {"amount", false},
		{"count", false}, {"exists", false}, {"", false}, {"note", true}, {"top", false}, {"v", false},
	}, got)
	assert.Equal(t, "amount", sql[targets[4].Offset:targets[4].Offset+len("amount")])

	targets, ok = SelectTargets("SELECT id, note FROM accounts", nil)
	require.True(t, ok, "names without a schema")
	assert.Equal(t, "note", targets[1].Name)
	assert.False(t, targets[1].Nullable, "nullability needs the schema")

	for _, sql := range []string{
		"SELECT * FROM accounts",
		"SELECT a.* FROM accounts a",
		"SELECT id FROM accounts UNION SELECT id FROM positions",
		"INSERT INTO accounts (id) VALUES ($1)",
		"SELECT id FROM",
	} {
		_, ok := SelectTargets(sql, schema)
		assert.False(t, ok, sql)
	}
}

// A condition every returned row meets keeps NULL out: IS NOT NULL, or a
// comparison NULL never passes, in the WHERE clause or the ON of an inner
// join.
func TestSelectTargetsFilteredNulls(t *testing.T) {
	schema := testSchema(t)
	cases := map[string]bool{
		"SELECT comment FROM positions WHERE id = $1 AND comment IS NOT NULL":                            false,
		"SELECT comment FROM positions WHERE comment::text = $1":                                         false,
		"SELECT comment FROM positions WHERE comment = ANY($1) AND amount > 0":                           false,
		"SELECT comment FROM positions WHERE comment LIKE $1":                                            false,
		"SELECT p.comment FROM positions p JOIN accounts a ON a.note = p.comment":                        false,
		"SELECT a.note FROM positions p LEFT JOIN accounts a ON a.note = p.comment":                      true,
		"SELECT comment FROM positions WHERE comment IS NOT NULL OR amount > 0":                          true,
		"SELECT comment FROM positions WHERE comment IS DISTINCT FROM $1":                                true,
		"SELECT comment FROM positions WHERE id IN (SELECT id FROM positions WHERE comment IS NOT NULL)": true,
	}
	for sql, nullable := range cases {
		targets, ok := SelectTargets(sql, schema)
		require.True(t, ok, sql)
		assert.Equal(t, nullable, targets[0].Nullable, sql)
	}
}
