package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const likePatternSource = `package storage

import (
	"fmt"
	"strings"
)

type Filter struct{ Search, Prefix string }

var likeEscaper = strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_")

func escapeLike(s string) string { return likeEscaper.Replace(s) }

func list(f Filter) (string, []any) {
	where := " WHERE 1=1"
	var args []any
	n := 1
	if f.Search != "" {
		where += fmt.Sprintf(" AND (reference ILIKE $%d OR name ILIKE $%d)", n, n)
		args = append(args, "%"+f.Search+"%") // want sql-like-pattern-unescaped
		n++
	}
	if f.Prefix != "" {
		where += fmt.Sprintf(" AND code LIKE $%d", n)
		args = append(args, f.Prefix+"%") // want sql-like-pattern-unescaped
		n++
	}
	return "SELECT id FROM orders" + where, args
}

func listEscaped(f Filter) (string, []any) {
	query := "SELECT id FROM orders WHERE reference ILIKE $1 OR code LIKE $2"
	return query, []any{"%" + escapeLike(f.Search) + "%", likeEscaper.Replace(f.Prefix) + "%"}
}

func search(term string) (string, []any) {
	return "SELECT id FROM orders WHERE lower(name) LIKE lower($1)", []any{fmt.Sprintf("%%%s%%", term)} // want sql-like-pattern-unescaped
}

func label(term string) string {
	return "%" + term + "%"
}
`

// A pattern wrapping the user's value in % without escaping it, in a
// function running a LIKE, lets the value's own % and _ match anything; an
// escaped value, and a function with no LIKE, are left alone.
func TestSQLLikePatternUnescaped(t *testing.T) {
	ctx := rulestest.GoFile(t, "storage/orders.go", likePatternSource)
	files := map[string]string{"storage/orders.go": likePatternSource}
	assert.Equal(t, wantedLines(files, "sql-like-pattern-unescaped"), foundLines(NewSQLLikePatternUnescapedRule().AnalyzeFile(ctx)))
}
