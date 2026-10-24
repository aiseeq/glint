package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// lib/pq encodes no slice but []byte: the permissions list fails the
// update on every run, "unsupported type []string".
func TestSQLUnsupportedArg(t *testing.T) {
	files := map[string]string{
		"go.mod":                "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/lib/pq v1.0.0\n\nreplace github.com/lib/pq => ./third_party/pq\n",
		"third_party/pq/go.mod": "module github.com/lib/pq\n\ngo 1.24\n",
		"third_party/pq/pq.go": `package pq

import "database/sql/driver"

type StringArray []string

func (a StringArray) Value() (driver.Value, error) { return nil, nil }

func Array(a any) any { return a }
`,
		"storage/sessions.go": `package storage

import (
	"context"
	"database/sql"
	"encoding/json"

	_ "github.com/lib/pq"
	"github.com/lib/pq"
)

type Session struct {
	ID          string
	Permissions []string
	Labels      map[string]string
	Token       []byte
}

func Update(ctx context.Context, db *sql.DB, s *Session) error {
	_, err := db.ExecContext(ctx, "UPDATE sessions SET permissions = $1, labels = $2, token = $3 WHERE id = $4",
		s.Permissions, s.Labels, s.Token, s.ID)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(s.Permissions)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "UPDATE sessions SET permissions = $1, roles = $2, scopes = $3 WHERE id = $4",
		encoded, pq.Array(s.Permissions), pq.StringArray(s.Permissions), s.ID)
	return err
}

func Delete(ctx context.Context, db *sql.DB, args []any) error {
	_, err := db.ExecContext(ctx, "DELETE FROM sessions WHERE id = $1", args...)
	return err
}
`,
	}
	violations, err := NewSQLUnsupportedArgRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"storage/sessions.go:21", "storage/sessions.go:21"}, foundLines(violations))
}

// sqlxStub keeps the signatures of github.com/jmoiron/sqlx v1.4: the query
// arguments are the variadic tail, the destination and the named-parameter
// argument are not.
const sqlxStub = `package sqlx

import (
	"context"
	"database/sql"
)

type DB struct{ *sql.DB }

func (db *DB) Queryx(query string, args ...interface{}) (*Rows, error) { return nil, nil }

func (db *DB) Select(dest interface{}, query string, args ...interface{}) error { return nil }

func (db *DB) GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	return nil
}

type Stmt struct{ *sql.Stmt }

func (s *Stmt) Get(dest interface{}, args ...interface{}) error { return nil }

type NamedStmt struct{}

func (n *NamedStmt) Exec(arg interface{}) (sql.Result, error) { return nil, nil }

func (n *NamedStmt) Select(dest interface{}, arg interface{}) error { return nil }

type Rows struct{}

type Queryer interface {
	Queryx(query string, args ...interface{}) (*Rows, error)
}

type Execer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

type Ext interface {
	Queryer
	Execer
}

func Get(q Queryer, dest interface{}, query string, args ...interface{}) error { return nil }

func SelectContext(ctx context.Context, q Queryer, dest interface{}, query string, args ...interface{}) error {
	return nil
}

func In(query string, args ...interface{}) (string, []interface{}, error) { return query, args, nil }

func NamedExec(e Ext, query string, arg interface{}) (sql.Result, error) { return nil, nil }
`

// sqlUnsupportedArgLines runs the rule on a project on lib/pq with one
// source file, storage/repo.go, and returns the places it reports.
func sqlUnsupportedArgLines(t *testing.T, src string) []string {
	t.Helper()
	files := map[string]string{
		"go.mod":                   "module example.com/rulestest\n\ngo 1.24\n\nrequire (\n\tgithub.com/lib/pq v1.0.0\n\tgithub.com/jmoiron/sqlx v1.0.0\n)\n\nreplace github.com/lib/pq => ./third_party/pq\n\nreplace github.com/jmoiron/sqlx => ./third_party/sqlx\n",
		"third_party/pq/go.mod":    "module github.com/lib/pq\n\ngo 1.24\n",
		"third_party/pq/pq.go":     "package pq\n\nfunc Array(a any) any { return a }\n",
		"third_party/sqlx/go.mod":  "module github.com/jmoiron/sqlx\n\ngo 1.24\n",
		"third_party/sqlx/sqlx.go": sqlxStub,
		"storage/repo.go":          src,
	}
	violations, err := NewSQLUnsupportedArgRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return foundLines(violations)
}

// A NamedStmt binds a map or a struct by parameter names: the map is
// expanded by sqlx, and the driver receives scalars.
func TestSQLUnsupportedArgNamedParameters(t *testing.T) {
	got := sqlUnsupportedArgLines(t, `package storage

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func Run(n *sqlx.NamedStmt, e sqlx.Ext, ids []string) error {
	if _, err := n.Exec(map[string]interface{}{"id": 1}); err != nil {
		return err
	}
	var rows []string
	if err := n.Select(&rows, map[string]interface{}{"id": 1}); err != nil {
		return err
	}
	query, args, err := sqlx.In("SELECT a FROM t WHERE id IN (?)", ids)
	if err != nil {
		return err
	}
	_ = query
	_ = args
	_, err = sqlx.NamedExec(e, "UPDATE t SET a = :a", map[string]interface{}{"a": 1})
	return err
}
`)
	assert.Empty(t, got)
}

// database/sql does not take the address of an argument: a Value method on
// *T leaves a T passed by value unencoded, "unsupported type Tags, a slice
// of string". The pointer itself is a driver.Valuer.
func TestSQLUnsupportedArgPointerReceiverValue(t *testing.T) {
	got := sqlUnsupportedArgLines(t, `package storage

import (
	"database/sql"
	"database/sql/driver"

	_ "github.com/lib/pq"
)

type Tags []string

func (t *Tags) Value() (driver.Value, error) { return nil, nil }

func Run(db *sql.DB, tags Tags) error {
	if _, err := db.Exec("UPDATE t SET tags = $1", tags); err != nil {
		return err
	}
	_, err := db.Exec("UPDATE t SET tags = $1", &tags)
	return err
}
`)
	assert.Equal(t, []string{"storage/repo.go:15"}, got)
}

// A method named Value is not driver.Valuer unless it returns
// (driver.Value, error): Value() string and Value() (any, error) leave the
// slice to the default converter, which rejects it.
func TestSQLUnsupportedArgValueWrongSignature(t *testing.T) {
	got := sqlUnsupportedArgLines(t, `package storage

import (
	"database/sql"

	_ "github.com/lib/pq"
)

type Tags []string

func (t Tags) Value() string { return "" }

type AnyTags []string

func (t AnyTags) Value() (any, error) { return nil, nil }

func Run(db *sql.DB, tags Tags, anyTags AnyTags) error {
	_, err := db.Exec("UPDATE t SET tags = $1", tags)
	_, err = db.Exec("UPDATE t SET tags = $1", anyTags)
	return err
}
`)
	assert.Equal(t, []string{"storage/repo.go:18", "storage/repo.go:19"}, got)
}

// The default converter dereferences a pointer and rejects an array of any
// element, [16]byte too: "unsupported type [16]uint8, a array".
func TestSQLUnsupportedArgPointerAndArray(t *testing.T) {
	got := sqlUnsupportedArgLines(t, `package storage

import (
	"database/sql"

	_ "github.com/lib/pq"
)

func Run(db *sql.DB, tags []string, labels map[string]string, pair [2]string, raw [16]byte, token []byte) error {
	_, err := db.Exec("UPDATE t SET a = $1, b = $2, c = $3, d = $4, e = $5",
		&tags,
		&labels,
		pair,
		raw,
		&token)
	return err
}
`)
	assert.Equal(t, []string{"storage/repo.go:11", "storage/repo.go:12", "storage/repo.go:13", "storage/repo.go:14"}, got)
}

// A handle reached through an alias of the pointer type, a struct embedding
// it, or an sqlx interface is the same handle; sqlx package-level helpers
// pass their variadic tail to it.
func TestSQLUnsupportedArgHandleForms(t *testing.T) {
	got := sqlUnsupportedArgLines(t, `package storage

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type DB = *sql.DB

type Repo struct{ *sql.DB }

func Run(ctx context.Context, db DB, r Repo, x *sqlx.DB, q sqlx.Queryer, e sqlx.Ext, ids []string) error {
	_, err := db.Exec("DELETE FROM t WHERE id = $1", ids)
	_, err = r.Exec("DELETE FROM t WHERE id = $1", ids)
	var d string
	err = sqlx.Get(x, &d, "SELECT a FROM t WHERE id = $1", ids)
	var rows []string
	err = sqlx.SelectContext(ctx, x, &rows, "SELECT a FROM t WHERE id = $1", ids)
	_, err = q.Queryx("SELECT a FROM t WHERE id = $1", ids)
	_, err = e.Exec("DELETE FROM t WHERE id = $1", ids)
	return err
}
`)
	assert.Equal(t, []string{
		"storage/repo.go:16", "storage/repo.go:17", "storage/repo.go:19", "storage/repo.go:21",
		"storage/repo.go:22", "storage/repo.go:23",
	}, got)
}

// The destination of Get and Select is a pointer to a slice or a struct
// that sqlx fills; only the arguments after the query string go to the
// driver.
func TestSQLUnsupportedArgDestination(t *testing.T) {
	got := sqlUnsupportedArgLines(t, `package storage

import (
	"context"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func Run(ctx context.Context, x *sqlx.DB, s *sqlx.Stmt, ids []string) error {
	var rows []string
	if err := x.Select(&rows, "SELECT a FROM t WHERE b = $1", 1); err != nil {
		return err
	}
	var names map[string]string
	if err := x.GetContext(ctx, &names, "SELECT a FROM t WHERE id = $1", ids); err != nil {
		return err
	}
	return s.Get(&rows, ids)
}
`)
	assert.Equal(t, []string{"storage/repo.go:16", "storage/repo.go:19"}, got)
}
