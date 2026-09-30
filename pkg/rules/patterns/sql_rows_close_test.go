package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLRowsCloseRule_Metadata(t *testing.T) {
	rule := NewSQLRowsCloseRule()

	assert.Equal(t, "sql-rows-close", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestSQLRowsCloseRule_Detection(t *testing.T) {
	rule := NewSQLRowsCloseRule()

	tests := []struct {
		name        string
		code        string
		extra       map[string]string
		expectMatch bool
	}{
		{
			name: "query without close",
			code: `package main

import "database/sql"

func example(db *sql.DB) {
	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		return
	}
	_ = rows
}
`,
			expectMatch: true,
		},
		{
			name: "query with defer close",
			code: `package main

import "database/sql"

func example(db *sql.DB) {
	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		return
	}
	defer rows.Close()
}
`,
			expectMatch: false,
		},
		{
			name: "query with close",
			code: `package main

import "database/sql"

func example(db *sql.DB) {
	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		return
	}
	rows.Close()
}
`,
			expectMatch: false,
		},
		{
			name: "queryContext without close",
			code: `package main

import (
	"context"
	"database/sql"
)

func example(ctx context.Context, db *sql.DB) {
	rows, err := db.QueryContext(ctx, "SELECT * FROM users")
	if err != nil {
		return
	}
	_ = rows
}
`,
			expectMatch: true,
		},
		{
			name: "rows handed to a same-file helper that closes them",
			code: `package main

import "database/sql"

func example(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT name FROM users")
	if err != nil {
		return nil, err
	}
	return scanNames(rows)
}

func scanNames(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
`,
			expectMatch: false,
		},
		{
			name: "rows handed to a same-file helper that leaks them",
			code: `package main

import "database/sql"

func example(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT name FROM users")
	if err != nil {
		return nil, err
	}
	return scanNames(rows)
}

func scanNames(rows *sql.Rows) ([]string, error) {
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
`,
			expectMatch: true,
		},
		{
			name: "rows returned to the caller",
			code: `package main

import "database/sql"

func example(db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("SELECT name FROM users")
	if err != nil {
		return nil, err
	}
	return rows, nil
}
`,
			expectMatch: false,
		},
		{
			name: "rows handed to a method of another package",
			code: `package main

import (
	"database/sql"

	"example.com/rulestest/scan"
)

func example(db *sql.DB, s *scan.Scanner) ([]string, error) {
	rows, err := db.Query("SELECT name FROM users")
	if err != nil {
		return nil, err
	}
	return s.Names(rows)
}
`,
			extra: map[string]string{"scan/scan.go": `package scan

import "database/sql"

type Scanner struct{}

func (s *Scanner) Names(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	return nil, rows.Err()
}
`},
			expectMatch: false,
		},
		{
			// Repro: url.Values from URL.Query() was taken for SQL rows —
			// only receivers spelled URL or url were excluded.
			name: "url values are not rows",
			code: `package main

import "net/url"

func example(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	values := parsed.Query()
	return values.Get("a"), nil
}
`,
			expectMatch: false,
		},
		{
			name: "query string getter is not rows",
			code: `package main

type ginLike struct{}

func (ginLike) Query(key string) string { return key }

func example(c ginLike) string {
	id := c.Query("id")
	return id
}
`,
			expectMatch: false,
		},
		{
			// Repro: the rows leaked inside the returned handler closure were
			// never looked at — function literals were skipped.
			name: "rows leaked inside a returned handler",
			code: `package main

import (
	"database/sql"
	"net/http"
)

type API struct{ db *sql.DB }

func (a *API) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := a.db.Query("SELECT id FROM t")
		if err != nil {
			return
		}
		for rows.Next() {
		}
	}
}
`,
			expectMatch: true,
		},
		{
			name: "rows-like interface of another driver",
			code: `package main

type Rows interface {
	Close()
	Next() bool
	Scan(dest ...any) error
	Err() error
}

type Pool interface {
	Query(sql string, args ...any) (Rows, error)
}

func example(p Pool) {
	rows, err := p.Query("SELECT 1")
	if err != nil {
		return
	}
	for rows.Next() {
	}
}
`,
			expectMatch: true,
		},
		{
			name: "rows ignored",
			code: `package main

import "database/sql"

func example(db *sql.DB) {
	_, err := db.Query("SELECT * FROM users")
	if err != nil {
		return
	}
}
`,
			expectMatch: false, // Ignored with _
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"service.go": tt.code}
			for name, source := range tt.extra {
				files[name] = source
			}
			violations := runRuleOnFiles(t, rule, files)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "sql_rows_leak", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}
