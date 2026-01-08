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
			ctx := createSQLContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "sql_rows_leak", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createSQLContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitSQLLines(code),
		Content: []byte(code),
	}

	if len(path) > 3 && path[len(path)-3:] == ".go" {
		parser := core.NewParser()
		fset, ast, err := parser.ParseGoFile(path, []byte(code))
		if err != nil {
			t.Fatalf("Failed to parse Go code: %v", err)
		}
		ctx.SetGoAST(fset, ast)
	}

	return ctx
}

func splitSQLLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
