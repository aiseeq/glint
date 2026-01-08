package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSQLInjectionRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
		wantPattern    string // "concatenation" or "sprintf"
	}{
		{
			name: "safe parameterized query",
			code: `package main

import "database/sql"

func getUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = $1", id)
}`,
			wantViolations: 0,
		},
		{
			name: "safe query with ? placeholder",
			code: `package main

import "database/sql"

func getUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
}`,
			wantViolations: 0,
		},
		{
			name: "string concatenation in Query",
			code: `package main

import "database/sql"

func getUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = " + id)
}`,
			wantViolations: 1,
			wantPattern:    "concatenation",
		},
		{
			name: "string concatenation in Exec",
			code: `package main

import "database/sql"

func deleteUser(db *sql.DB, id string) {
	db.Exec("DELETE FROM users WHERE id = " + id)
}`,
			wantViolations: 1,
			wantPattern:    "concatenation",
		},
		{
			name: "string concatenation in QueryRow",
			code: `package main

import "database/sql"

func getUser(db *sql.DB, name string) {
	db.QueryRow("SELECT * FROM users WHERE name = " + name)
}`,
			wantViolations: 1,
			wantPattern:    "concatenation",
		},
		{
			name: "fmt.Sprintf in Query",
			code: `package main

import (
	"database/sql"
	"fmt"
)

func getUser(db *sql.DB, id string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}`,
			wantViolations: 1,
			wantPattern:    "sprintf",
		},
		{
			name: "fmt.Sprintf in Exec",
			code: `package main

import (
	"database/sql"
	"fmt"
)

func updateUser(db *sql.DB, id, name string) {
	db.Exec(fmt.Sprintf("UPDATE users SET name = '%s' WHERE id = %s", name, id))
}`,
			wantViolations: 1,
			wantPattern:    "sprintf",
		},
		// Note: Get/Select/QueryContext have SQL as 2nd+ argument
		// Current implementation only checks first argument - these are limitations
		{
			name: "sqlx Get - SQL in 2nd arg (limitation)",
			code: `package main

import "github.com/jmoiron/sqlx"

func getUser(db *sqlx.DB, id string) {
	var user User
	db.Get(&user, "SELECT * FROM users WHERE id = " + id)
}`,
			wantViolations: 0, // Limitation: SQL is 2nd arg
		},
		{
			name: "sqlx Select - SQL in 2nd arg (limitation)",
			code: `package main

import (
	"fmt"
	"github.com/jmoiron/sqlx"
)

func getUsers(db *sqlx.DB, role string) {
	var users []User
	db.Select(&users, fmt.Sprintf("SELECT * FROM users WHERE role = '%s'", role))
}`,
			wantViolations: 0, // Limitation: SQL is 2nd arg
		},
		{
			name: "QueryContext - SQL in 2nd arg (limitation)",
			code: `package main

import (
	"context"
	"database/sql"
)

func getUser(ctx context.Context, db *sql.DB, id string) {
	db.QueryContext(ctx, "SELECT * FROM users WHERE id = " + id)
}`,
			wantViolations: 0, // Limitation: SQL is 2nd arg
		},
		{
			name: "Prepare with concatenation - should detect",
			code: `package main

import "database/sql"

func prepare(db *sql.DB, table string) {
	db.Prepare("SELECT * FROM " + table)
}`,
			wantViolations: 1,
			wantPattern:    "concatenation",
		},
		{
			name: "NamedExec with Sprintf",
			code: `package main

import (
	"fmt"
	"github.com/jmoiron/sqlx"
)

func insertUser(db *sqlx.DB, table string) {
	db.NamedExec(fmt.Sprintf("INSERT INTO %s (name) VALUES (:name)", table), map[string]interface{}{"name": "John"})
}`,
			wantViolations: 1,
			wantPattern:    "sprintf",
		},
		{
			name: "non-SQL concatenation - should not flag",
			code: `package main

import "database/sql"

func getUser(db *sql.DB, id string) {
	msg := "Hello " + id
	db.Query("SELECT * FROM users WHERE id = $1", id)
	println(msg)
}`,
			wantViolations: 0,
		},
		{
			name: "concatenation without SQL keywords - should not flag",
			code: `package main

import "database/sql"

func doSomething(db *sql.DB, value string) {
	db.Query("data: " + value)
}`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSQLInjectionRule()

			parser := core.NewParser()
			ctx := core.NewFileContext("/src/db.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/db.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)

			if tt.wantPattern != "" && len(violations) > 0 {
				pattern := violations[0].Context["pattern"]
				assert.Equal(t, tt.wantPattern, pattern,
					"Expected pattern '%s' but got '%s'", tt.wantPattern, pattern)
			}
		})
	}
}

func TestSQLInjectionSkipsNonGoFiles(t *testing.T) {
	rule := NewSQLInjectionRule()

	ctx := core.NewFileContext("/src/file.ts", "/src", []byte("db.query('SELECT * FROM ' + id)"), core.DefaultConfig())

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

func TestSQLInjectionNoAST(t *testing.T) {
	rule := NewSQLInjectionRule()

	// Go file without AST
	ctx := core.NewFileContext("/src/file.go", "/src", []byte("package main"), core.DefaultConfig())
	// Don't set AST

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
