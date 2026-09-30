package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// rows.Next returns false both at the end of the rows and on an error mid
// way - a dropped connection, a row that fails to decode. Without rows.Err
// the function returns the rows it read as the whole list.
func TestSQLRowsErrUnchecked(t *testing.T) {
	files := map[string]string{
		"repo/orders.go": `package repo

import (
	"context"
	"database/sql"
)

type Repo struct{ db *sql.DB }

func (r *Repo) Amounts(ctx context.Context) ([]int, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT amount FROM orders")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() { // want sql-rows-err-unchecked
		var n int
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (r *Repo) Checked(ctx context.Context) ([]int, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT amount FROM orders")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (r *Repo) First(ctx context.Context) (int, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT amount FROM orders")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if rows.Next() {
		var n int
		return n, rows.Scan(&n)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return 0, sql.ErrNoRows
}
`,
	}
	violations, err := NewSQLRowsErrUncheckedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "sql-rows-err-unchecked"), foundLines(violations))
}

// A package that does not type-check still has its loops checked: the rows
// are the variable a Query call assigns.
func TestSQLRowsErrUncheckedUntyped(t *testing.T) {
	files := map[string]string{
		"repo/orders.go": `package repo

import (
	"context"
	"database/sql"
)

type Repo struct{ db *sql.DB }

func (r *Repo) Amounts(ctx context.Context) ([]int, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT amount FROM orders")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() { // want sql-rows-err-unchecked
		out = append(out, 1)
	}
	return out, undefinedHelper()
}

func (r *Repo) Checked(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, "SELECT amount FROM orders")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
	}
	return rows.Err()
}
`,
	}
	assert.Equal(t, wantedLines(files, "sql-rows-err-unchecked"), foundLines(runRuleOnBrokenFiles(t, NewSQLRowsErrUncheckedRule(), files)))
}
