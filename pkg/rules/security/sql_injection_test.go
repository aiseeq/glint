package security

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
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
			name: "chained concatenation with trailing literal",
			code: `package main

import "database/sql"

func getUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = " + id + " LIMIT 1")
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
		{
			name: "sqlx Get - SQL in 2nd arg",
			code: `package main

import "github.com/jmoiron/sqlx"

func getUser(db *sqlx.DB, id string) {
	var user User
	db.Get(&user, "SELECT * FROM users WHERE id = " + id)
}`,
			wantViolations: 1,
			wantPattern:    "concatenation",
		},
		{
			name: "sqlx Select - SQL in 2nd arg",
			code: `package main

import (
	"fmt"
	"github.com/jmoiron/sqlx"
)

func getUsers(db *sqlx.DB, role string) {
	var users []User
	db.Select(&users, fmt.Sprintf("SELECT * FROM users WHERE role = '%s'", role))
}`,
			wantViolations: 1,
			wantPattern:    "sprintf",
		},
		{
			name: "QueryContext - SQL in 2nd arg",
			code: `package main

import (
	"context"
	"database/sql"
)

func getUser(ctx context.Context, db *sql.DB, id string) {
	db.QueryContext(ctx, "SELECT * FROM users WHERE id = " + id)
}`,
			wantViolations: 1,
			wantPattern:    "concatenation",
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
			t.Parallel() // each case loads its own module
			violations := analyzeSQLInjection(t, tt.code)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)

			if tt.wantPattern != "" && len(violations) > 0 {
				pattern := violations[0].Context["pattern"]
				assert.Equal(t, tt.wantPattern, pattern,
					"Expected pattern '%s' but got '%s'", tt.wantPattern, pattern)
			}
		})
	}
}

// fakeSQLXModule stands in for github.com/jmoiron/sqlx so the typed load
// resolves the import without network access.
var fakeSQLXModule = map[string]string{
	"go.mod":                  "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/jmoiron/sqlx v1.0.0\n\nreplace github.com/jmoiron/sqlx => ./third_party/sqlx\n",
	"third_party/sqlx/go.mod": "module github.com/jmoiron/sqlx\n\ngo 1.24\n",
	"third_party/sqlx/sqlx.go": `package sqlx

type DB struct{}

func (db *DB) Get(dest interface{}, query string, args ...interface{}) error    { return nil }
func (db *DB) Select(dest interface{}, query string, args ...interface{}) error { return nil }
func (db *DB) NamedExec(query string, arg interface{}) (interface{}, error)     { return nil, nil }
`,
}

// analyzeSQLInjection loads code as db/db.go of a typed module and returns the
// rule's findings in it. User stands in for the row type the cases scan into.
func analyzeSQLInjection(t *testing.T, code string) []*core.Violation {
	t.Helper()
	files := map[string]string{"db/db.go": code + "\n\ntype User struct{}\n"}
	for name, content := range fakeSQLXModule {
		files[name] = content
	}
	project := rulestest.Project(t, files)
	violations, err := NewSQLInjectionRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var inFile []*core.Violation
	for _, v := range violations {
		if filepath.ToSlash(v.File) == "db/db.go" {
			inFile = append(inFile, v)
		}
	}
	return inFile
}

func TestSQLInjectionQueryArgumentBySignature(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
	"fmt"
)

const usersTable = "users"

type Cache struct{}

func (Cache) Get(key string) string { return key }

func byIDCtx(ctx context.Context, db *sql.DB, id string) {
	db.QueryContext(ctx, "SELECT * FROM users WHERE id = '"+id+"'")
}

func byIDVar(db *sql.DB, id string) {
	q := "SELECT * FROM users WHERE id = '" + id + "'"
	db.Query(q)
}

func byIDAppended(db *sql.DB, id string) {
	q := "SELECT * FROM users"
	q += " WHERE id = '" + id + "'"
	db.Query(q)
}

func delCtx(ctx context.Context, db *sql.DB, id string) {
	db.ExecContext(ctx, fmt.Sprintf("DELETE FROM users WHERE id = '%s'", id))
}

func all(db *sql.DB) {
	db.Query("SELECT * FROM " + usersTable)
}

func allSprintfConst(db *sql.DB) {
	db.Query(fmt.Sprintf("SELECT * FROM %s", usersTable))
}

func ordered(db *sql.DB) {
	q := "SELECT * FROM users"
	q += " ORDER BY name"
	db.Query(q)
}

func last(c Cache, id string) string {
	return c.Get("lastUpdated:" + id)
}

func selectKey(c Cache, id string) string {
	return c.Get("select from where:" + id)
}
`
	violations := analyzeSQLInjection(t, code)
	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	// byIDCtx, byIDVar, byIDAppended, delCtx.
	assert.Equal(t, []int{16, 21, 27, 31}, lines)
}

func TestSQLInjectionWrapperMethodWithQueryParameter(t *testing.T) {
	code := `package main

import "context"

type DBTX interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (interface{}, error)
}

type Store struct{ db DBTX }

func (s Store) byID(ctx context.Context, id string) {
	s.db.QueryContext(ctx, "SELECT * FROM users WHERE id = " + id)
}
`
	violations := analyzeSQLInjection(t, code)
	require.Len(t, violations, 1)
	assert.Equal(t, 12, violations[0].Line)
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
