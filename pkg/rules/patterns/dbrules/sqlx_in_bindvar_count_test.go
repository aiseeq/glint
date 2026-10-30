package dbrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sqlxInBindvarFilesPrefix = "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/jmoiron/sqlx v1.0.0\n\nreplace github.com/jmoiron/sqlx => ./third_party/sqlx\n"

const sqlxInBindvarStub = `package sqlx

func In(query string, args ...interface{}) (string, []interface{}, error) { return query, args, nil }
`

func sqlxInBindvarViolations(t *testing.T, source string) ([]*core.Violation, map[string]string) {
	t.Helper()
	files := map[string]string{
		"go.mod":                   sqlxInBindvarFilesPrefix,
		"third_party/sqlx/go.mod":  "module github.com/jmoiron/sqlx\n\ngo 1.24\n",
		"third_party/sqlx/sqlx.go": sqlxInBindvarStub,
		"storage/repo.go":          source,
	}
	violations, err := NewSQLXInBindvarCountRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations, files
}

func TestSqlxInBindvarCount(t *testing.T) {
	violations, files := sqlxInBindvarViolations(t, `package storage

import "github.com/jmoiron/sqlx"

const staticQuery = "UPDATE users SET a = ?"

func update(unreachable string, ids []int, now int) {
	query, args, err := sqlx.In("UPDATE users SET a = ?, updated_at = ? WHERE id IN (?)", unreachable, ids) // want sqlx-in-bindvar-count
	_, _, _ = query, args, err
	args = append(args, now)
	query, args, err = sqlx.In(staticQuery, unreachable, ids) // want sqlx-in-bindvar-count
	_, _, _ = query, args, err
	_ = unreachable
}
`)
	require.Len(t, violations, 2)
	assert.Equal(t, patterntest.WantedLines(files, "sqlx-in-bindvar-count"), patterntest.FoundLines(violations))
	assert.Equal(t, core.SeverityHigh, violations[0].Severity)
	assert.Contains(t, violations[0].Message, "3")
	assert.Contains(t, violations[0].Message, "2")
	assert.Contains(t, violations[0].Message, "In")
	assert.Contains(t, violations[0].Suggestion, "all")
	assert.Contains(t, violations[0].Suggestion, "after")
}

func TestSqlxInBindvarCountNegatives(t *testing.T) {
	violations, _ := sqlxInBindvarViolations(t, `package storage

import "github.com/jmoiron/sqlx"

func In(query string, args ...interface{}) (string, []interface{}, error) { return query, args, nil }

func update(query string, values []interface{}) {
	static := "SELECT * FROM users WHERE id IN (" + "?)"
	_, _, _ = sqlx.In("SELECT * FROM users WHERE id = ?", values)
	_, _, _ = sqlx.In("SELECT * FROM users WHERE id = ?", values...)
	_, _, _ = sqlx.In(query, values)
	_, _, _ = In("SELECT * FROM users WHERE id = ? AND active = ?", values)
	_, _, _ = sqlx.In(static, values)
}
`)
	assert.Empty(t, violations)
}
