package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// A prefix cut from a value of unknown length panics on a short one: a short
// e-mail turns the handler into a 500, a short secret fails the test helper.
func TestStringPrefixSliceUnguarded(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewStringPrefixSliceUnguardedRule(), map[string]string{
		"admin/label.go": `package admin

import (
	"fmt"

	"example.com/rulestest/uuid"
)

type Claims struct{ Email string }

type User struct {
	ID    string
	Email string
}

const prefix = "admin-"

func AdminID(claims Claims) string {
	return fmt.Sprintf("admin-%s", claims.Email[:8])
}

func Labels(users []User) []string {
	var out []string
	for i := range users {
		out = append(out, fmt.Sprintf("%s (ID: %s...)", users[i].Email, users[i].ID[:8]))
	}
	return out
}

func Guarded(claims Claims) string {
	email := claims.Email
	if len(email) > 8 {
		email = email[:8]
	}
	return email
}

func Fixed() string {
	short := uuid.NewString()[:8]
	id := uuid.New().String()
	return short + id[:8] + prefix[:3]
}

func Bytes(buf []byte) []byte {
	return buf[:4]
}

func Whole(claims Claims) string {
	return claims.Email[:]
}

type release struct{ head, name string }

func Capitalize(words []string, r release) string {
	for i, word := range words {
		words[i] = word[:2]
	}
	return r.head[:12] + r.name[:1]
}
`,
		"uuid/uuid.go": `package uuid

type UUID [16]byte

func (u UUID) String() string { return "00000000-0000-0000-0000-000000000000" }

func New() UUID { return UUID{} }

func NewString() string { return New().String() }
`,
		"admin/label_test.go": `package admin

import (
	"os"
	"testing"
)

type authConfig struct{ JWTSecret string }

type config struct{ Auth authConfig }

func restore(t *testing.T, cfg *config) {
	envSecret := os.Getenv("JWT_SECRET")
	t.Logf("restoring secret: '%s...' -> '%s...'", cfg.Auth.JWTSecret[:30], envSecret[:30])
	if len(envSecret) > 4 {
		t.Logf("prefix %s", envSecret[:4])
	}
	_ = cfg.Auth.JWTSecret[:2]
	data := []byte(envSecret)
	t.Logf("discriminator=%v", data[:8])
}
`,
	})
	assert.Equal(t, []string{"admin/label.go:19", "admin/label.go:25", "admin/label_test.go:14", "admin/label_test.go:14"}, found)
}

// encoding/json keeps the outer field of a name and drops the promoted one:
// a details type that adds a placeholder under the base type's JSON name
// sends the placeholder and loses the real value.
func TestJSONTagShadowsEmbeddedField(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewJSONTagShadowsEmbeddedFieldRule(), map[string]string{
		"models/investment.go": `package models

type Investment struct {
	ID           string ` + "`json:\"id\"`" + `
	StrategyName string ` + "`json:\"strategy\"`" + `
	Amount       string
}

type Audit struct {
	CreatedBy string ` + "`json:\"createdBy\"`" + `
}

type InvestmentDetails struct {
	Investment
	*Audit
	UserEmail string      ` + "`json:\"userEmail,omitempty\"`" + `
	Strategy  interface{} ` + "`json:\"strategy,omitempty\"`" + `
	Total     string      ` + "`json:\"Amount\"`" + `
	Author    string      ` + "`json:\"createdBy\"`" + `
	Ignored   string      ` + "`json:\"-\"`" + `
}

type Override struct {
	Investment
	ID string ` + "`json:\"id\"`" + `
}

type Named struct {
	Investment ` + "`json:\"investment\"`" + `
	Strategy string ` + "`json:\"strategy\"`" + `
}
`,
	})
	assert.Equal(t, []string{"models/investment.go:17", "models/investment.go:18", "models/investment.go:19"}, found)
}

// A state compared with a string that none of its constants holds: the value
// comes from another status set, and the compiler cannot see the drift.
func TestEnumComparedToForeignLiteral(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewEnumComparedToForeignLiteralRule(), map[string]string{
		"domain/state.go": `package domain

type State string

const (
	StateCreated  State = "created"
	StatePending  State = "pending_approval"
	StateRejected State = "rejected"
)

type Free string
`,
		"service/cancel.go": `package service

import (
	"errors"

	"example.com/rulestest/domain"
)

func Cancel(raw string, free domain.Free) error {
	state := domain.State(raw)
	if state != domain.StatePending && state != domain.StateCreated && string(state) != "pending" {
		return errors.New("cannot cancel")
	}
	if state == "canceled" {
		return errors.New("already")
	}
	if string(state) == "created" || free == "anything" || raw == "pending" {
		return nil
	}
	switch state {
	case domain.StateRejected, "refunded":
		return nil
	}
	if state == "" || state == "*" {
		return nil
	}
	return nil
}
`,
	})
	assert.Equal(t, []string{"service/cancel.go:11", "service/cancel.go:14", "service/cancel.go:21"}, found)
}

// A host matched by suffix without the dot: evilexample.com passes a check
// for example.com.
func TestHostSuffixWithoutDot(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewHostSuffixWithoutDotRule(), map[string]string{
		"middleware/https.go": `package middleware

import "strings"

func Allowed(host, baseDomain string) bool {
	if baseDomain != "" && !strings.HasSuffix(strings.Split(host, ":")[0], baseDomain) {
		return false
	}
	return strings.HasSuffix(host, "example.com")
}

func Strict(host, baseDomain string) bool {
	return host == baseDomain || strings.HasSuffix(host, "."+baseDomain) || strings.HasSuffix(host, ".example.com")
}

func Other(name, ext string) bool {
	return strings.HasSuffix(name, ext) || strings.HasSuffix(name, ".go")
}

var testEmailDomains = []string{"@local.test", "@" + localDomain}

const localDomain = "app.test"

func IsTestEmail(email string) bool {
	for _, domain := range testEmailDomains {
		if strings.HasSuffix(email, domain) {
			return true
		}
	}
	return false
}

func IsTestDomain(domainPart string) bool {
	for _, testDomain := range []string{"local.test", "example.com"} {
		if strings.HasSuffix(domainPart, testDomain) {
			return true
		}
	}
	return strings.HasSuffix(domainPart, "@"+localDomain)
}
`,
	})
	assert.Equal(t, []string{"middleware/https.go:35", "middleware/https.go:6", "middleware/https.go:9"}, found)
}

// JSON written with a format verb inside quotes: a quote or a newline in the
// value breaks the frame or adds fields.
func TestJSONBuiltByFormat(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewJSONBuiltByFormatRule(), map[string]string{
		"sse/handler.go": `package sse

import (
	"fmt"
	"net/http"
)

func Connected(w http.ResponseWriter, userID string, count int) {
	fmt.Fprintf(w, "data: {\"status\":\"connected\",\"userId\":\"%s\"}\n\n", userID)
	body := fmt.Sprintf(` + "`{\"error\": \"%v\"}`" + `, userID)
	_ = body
	fmt.Fprintf(w, "data: {\"count\":%d}\n\n", count)
	fmt.Fprintf(w, "user %q connected", userID)
}
`,
		"sse/handler_test.go": `package sse

import "fmt"

func body(email string) string {
	return fmt.Sprintf(` + "`{\"email\":\"%s\"}`" + `, email)
}
`,
	})
	assert.Equal(t, []string{"sse/handler.go:10", "sse/handler.go:9"}, found)
}

// Quotes doubled by hand in place of bind parameters: other metacharacters
// pass, and the SQL built around the value escapes the injection checks. The
// escaped value is reported where it reaches SQL text: a concatenation or a
// format with SQL in it, a query builder, a database call, through variables,
// helpers that return it and the callers of those helpers.
func TestSQLQuoteEscapedByHand(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewSQLQuoteEscapedByHandRule(), map[string]string{
		"helpers/where.go": `package helpers

import "strings"

func escapeSQLLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

var quoter = strings.NewReplacer("'", "''", "\\", "\\\\")

func legacy(s string) string {
	return strings.Replace(s, "'", "''", -1)
}

func other(s string) string {
	return strings.ReplaceAll(s, "\"", "'")
}

func unused(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
`,
		"helpers/db.go": `package helpers

import (
	"database/sql"
	"fmt"
	"strings"
)

var DB *sql.DB

func ByName(name string) (*sql.Rows, error) {
	return DB.Query("SELECT id FROM users WHERE name = '" + escapeSQLLiteral(name) + "'")
}

func ByCity(city string) string {
	return fmt.Sprintf("SELECT id FROM users WHERE city = '%s'", quoter.Replace(city))
}

func ByTags(tags []string) (*sql.Rows, error) {
	var conds []string
	for _, t := range tags {
		conds = append(conds, "'"+legacy(t)+"'")
	}
	query := "SELECT id FROM items WHERE tag IN (" + strings.Join(conds, ", ") + ")"
	return DB.Query(query)
}

func ByBuilder(name string) (*sql.Rows, error) {
	var b strings.Builder
	b.WriteString("SELECT id FROM users WHERE name = ")
	b.WriteString("'" + strings.ReplaceAll(name, "'", "''") + "'")
	return DB.Query(b.String())
}

func Raw(stmt string) error {
	_, err := DB.Exec(strings.ReplaceAll(stmt, "'", "''"))
	return err
}

func label(s string) string { return other(s) + unused("") }
`,
		"helpers/owner.go": `package helpers

import (
	"database/sql"
	"strings"
)

func ByOwner(owner string) (*sql.Rows, error) {
	query := "SELECT id FROM items WHERE owner = "
	query += "'" + strings.ReplaceAll(owner, "'", "''") + "'"
	return DB.Query(query)
}

func ByRegion(region string) (*sql.Rows, error) {
	return filtered("'" + strings.ReplaceAll(region, "'", "''") + "'")
}

func filtered(value string) (*sql.Rows, error) {
	return DB.Query("SELECT id FROM items WHERE region = " + value)
}

func ByParam(name string) (*sql.Rows, error) {
	return DB.Query("SELECT id FROM users WHERE name = $1", strings.ReplaceAll(name, "'", "''"))
}
`,
	})
	assert.Equal(t, []string{"helpers/db.go:31", "helpers/db.go:36", "helpers/owner.go:10", "helpers/owner.go:15", "helpers/where.go:12", "helpers/where.go:6", "helpers/where.go:9"}, found)

	// A tool that hands SQL text to the psql command has no bind parameters.
	cli := rulestest.ProjectRulePlaces(t, NewSQLQuoteEscapedByHandRule(), map[string]string{
		"flags/sql.go": `package flags

import "strings"

func literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
`,
	})
	assert.Empty(t, cli)
}

// A spreadsheet range quotes a sheet name in apostrophes and doubles the
// apostrophes inside it: that text goes to the spreadsheet API, not to SQL, even in a project that
// runs queries, and even in a function that runs one.
func TestSQLQuoteEscapedByHandOutsideSQL(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewSQLQuoteEscapedByHandRule(), map[string]string{
		"export/sheet.go": `package export

import (
	"database/sql"
	"strings"
)

var DB *sql.DB

type valuesService struct{}

type valuesCall struct{}

func (valuesService) Get(sheetID, rng string) valuesCall { return valuesCall{} }

func (valuesCall) Do() (string, error) { return "", nil }

func readTab(svc valuesService, sheetID, tab string) (string, error) {
	rng := "'" + strings.ReplaceAll(tab, "'", "''") + "'!A1:Z200"
	return svc.Get(sheetID, rng).Do()
}

func exportTab(svc valuesService, sheetID, tab string) error {
	rows, err := DB.Query("SELECT name FROM tabs WHERE title = $1", tab)
	if err != nil {
		return err
	}
	defer rows.Close()
	_, err = svc.Get(sheetID, a1Range(tab, "A1:B2")).Do()
	return err
}

func a1Range(tab, cells string) string {
	return "'" + strings.ReplaceAll(tab, "'", "''") + "'!" + cells
}
`,
	})
	assert.Empty(t, found)
}

// A driver call is seen by the package of the method (also one promoted from
// an embedded *sql.DB) or by an interface that answers a driver type, and the
// query is the parameter the driver names query or sql: a destination before
// it (sqlx Get, Select), a gorm model or a value to scan is bound, not SQL
// text, and so is the statement name of pgx Prepare.
func TestSQLQuoteEscapedByHandDriverCalls(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewSQLQuoteEscapedByHandRule(), map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n\nrequire (\n\tgithub.com/jmoiron/sqlx v1.0.0\n\tgithub.com/jackc/pgx/v5 v5.0.0\n\tgorm.io/gorm v1.0.0\n)\n\n" +
			"replace github.com/jmoiron/sqlx => ./third_party/sqlx\n\nreplace github.com/jackc/pgx/v5 => ./third_party/pgx\n\nreplace gorm.io/gorm => ./third_party/gorm\n",
		"third_party/sqlx/go.mod": "module github.com/jmoiron/sqlx\n\ngo 1.24\n",
		"third_party/sqlx/sqlx.go": `package sqlx

import "database/sql"

type DB struct{ *sql.DB }

func (db *DB) Get(dest interface{}, query string, args ...interface{}) error    { return nil }
func (db *DB) Select(dest interface{}, query string, args ...interface{}) error { return nil }
`,
		"third_party/pgx/go.mod": "module github.com/jackc/pgx/v5\n\ngo 1.24\n",
		"third_party/pgx/pgx.go": `package pgx

import "context"

type Conn struct{}

type StatementDescription struct{}

func (c *Conn) Prepare(ctx context.Context, name, sql string) (*StatementDescription, error) {
	return nil, nil
}
`,
		"third_party/gorm/go.mod": "module gorm.io/gorm\n\ngo 1.24\n",
		"third_party/gorm/gorm.go": `package gorm

type DB struct{}

func (db *DB) Create(value interface{}) *DB                     { return db }
func (db *DB) Find(dest interface{}, conds ...interface{}) *DB { return db }
`,
		"store/drivers.go": `package store

import (
	"context"
	"database/sql"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jmoiron/sqlx"
	"gorm.io/gorm"
)

var DB *sqlx.DB

func Load(stmt string) ([]int, error) {
	var ids []int
	err := DB.Select(&ids, strings.ReplaceAll(stmt, "'", "''"))
	return ids, err
}

func One(stmt string) (int, error) {
	var id int
	err := DB.Get(&id, strings.ReplaceAll(stmt, "'", "''"))
	return id, err
}

func Prepare(ctx context.Context, conn *pgx.Conn, name, stmt string) error {
	if _, err := conn.Prepare(ctx, strings.ReplaceAll(name, "'", "''"), "SELECT 1"); err != nil {
		return err
	}
	_, err := conn.Prepare(ctx, name, strings.ReplaceAll(stmt, "'", "''"))
	return err
}

func Scan(s string) error {
	var ns sql.NullString
	return ns.Scan(strings.ReplaceAll(s, "'", "''"))
}

type User struct{ Name string }

func Add(db *gorm.DB, n string) {
	db.Create(&User{Name: strings.ReplaceAll(n, "'", "''")})
	db.Find(&User{Name: strings.ReplaceAll(n, "'", "''")})
}
`,
		"store/wrapped.go": `package store

import (
	"context"
	"database/sql"
	"strings"
)

type Store struct{ *sql.DB }

func (s Store) Raw(stmt string) error {
	_, err := s.Exec(strings.ReplaceAll(stmt, "'", "''"))
	return err
}

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
}

func Run(ctx context.Context, db DBTX, stmt string) error {
	_, err := db.ExecContext(ctx, strings.ReplaceAll(stmt, "'", "''"))
	return err
}

type runner interface {
	Exec(command string) error
}

func Shell(r runner, arg string) error {
	return r.Exec(strings.ReplaceAll(arg, "'", "''"))
}
`,
	})
	assert.Equal(t, []string{"store/drivers.go:17", "store/drivers.go:23", "store/drivers.go:31", "store/wrapped.go:12", "store/wrapped.go:21"}, found)
}

// The escaped value is followed through closures, struct fields and the
// results of helpers. A field is followed by itself, a result keeps its
// position, and a helper returns the value to the call it was handed to
// only: a sheet name escaped through a helper the queries share, or held in
// the field next to the query, never reaches SQL.
func TestSQLQuoteEscapedByHandFlow(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewSQLQuoteEscapedByHandRule(), map[string]string{
		"repo/reach.go": `package repo

import (
	"database/sql"
	"strings"
)

var DB *sql.DB

func Called(name string) (*sql.Rows, error) {
	q := func() string { return strings.ReplaceAll(name, "'", "''") }()
	return DB.Query("SELECT id FROM users WHERE name = '" + q + "'")
}

func Closure(x string) (*sql.Rows, error) {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	return DB.Query("SELECT id FROM t WHERE a = " + quote(x))
}

type filter struct {
	Value string
	sb    strings.Builder
}

func Field(name string) (*sql.Rows, error) {
	var f filter
	f.Value = "'" + strings.ReplaceAll(name, "'", "''") + "'"
	return DB.Query("SELECT id FROM users WHERE name = " + f.Value)
}

func BuilderField(name string) (*sql.Rows, error) {
	var f filter
	f.sb.WriteString("SELECT id FROM users WHERE name = ")
	f.sb.WriteString("'" + strings.ReplaceAll(name, "'", "''") + "'")
	return DB.Query(f.sb.String())
}

func identity(s string) string { return s }

func Nested(name string) (*sql.Rows, error) {
	return DB.Query("SELECT id FROM users WHERE name = '" + identity(identity(strings.ReplaceAll(name, "'", "''"))) + "'")
}

func Lookup(names []string) (*sql.Rows, error) {
	m := map[string]string{"a": strings.ReplaceAll(names[0], "'", "''")}
	v, ok := m["a"]
	if !ok {
		return nil, nil
	}
	return DB.Query("SELECT id FROM users WHERE name = '" + v + "'")
}

func build(name string) (string, error) {
	return "SELECT id FROM users WHERE name = '" + strings.ReplaceAll(name, "'", "''") + "'", nil
}

func Built(name string) (*sql.Rows, error) {
	q, err := build(name)
	if err != nil {
		return nil, err
	}
	return DB.Query(q)
}
`,
		"repo/apart.go": `package repo

import (
	"database/sql"
	"strings"
)

func split(name string) (string, string) {
	return "SELECT id FROM users WHERE name = $1", strings.ReplaceAll(name, "'", "''")
}

func forward(name string) (string, string) { return split(name) }

func ByParam(name string) (*sql.Rows, error) {
	q, arg := split(name)
	return DB.Query(q, arg)
}

func ByForwarded(name string) (*sql.Rows, error) {
	q, arg := forward(name)
	return DB.Query(q, arg)
}

func Sheet(tab string) string {
	return identity("'" + strings.ReplaceAll(tab, "'", "''") + "'!A1:B2")
}

func Run(stmt string) (*sql.Rows, error) {
	return DB.Query(identity(stmt))
}

func wrap(s string) string { return "'" + s + "'" }

func SheetRange(tab string) string {
	return wrap(strings.ReplaceAll(tab, "'", "''")) + "!A1"
}

func ByWrapped(v string) (*sql.Rows, error) {
	return DB.Query("SELECT id FROM t WHERE a = " + wrap(v))
}

type request struct {
	Sheet string
	SQL   string
}

func Fields(tab string) (*sql.Rows, error) {
	var v request
	v.Sheet = "'" + strings.ReplaceAll(tab, "'", "''") + "'!A1:B2"
	v.SQL = "SELECT 1"
	return DB.Query(v.SQL)
}
`,
	})
	assert.Equal(t, []string{"repo/reach.go:11", "repo/reach.go:16", "repo/reach.go:27", "repo/reach.go:34", "repo/reach.go:41", "repo/reach.go:45", "repo/reach.go:54"}, found)
}

// A metric answered by a literal zero: the API reports no return instead of
// failing or leaving the field out.
func TestSQLMetricLiteralZero(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewSQLMetricLiteralZeroRule(), map[string]string{
		"repo/portfolio.go": `package repo

const summaryQuery = ` + "`" + `
	SELECT
		COUNT(*) as total_investments,
		COALESCE(SUM(amount), 0) as total_value,
		0 as total_return,
		0::numeric AS realized_profit
	FROM investments WHERE user_id = $1` + "`" + `

const unionQuery = ` + "`" + `
	SELECT amount, 0 AS fee FROM deposits
	UNION ALL
	SELECT amount, fee FROM withdrawals` + "`" + `

const flagQuery = ` + "`SELECT id, 0 AS retry_count FROM jobs`" + `

func Query() string { return summaryQuery + unionQuery + flagQuery }
`,
	})
	assert.Equal(t, []string{"repo/portfolio.go:7", "repo/portfolio.go:8"}, found)
}

// A template passes a permission name to a FuncMap helper that converts it
// to the permission type: a name no constant holds (a permission of an
// older set) hides the button for everyone, and nothing compiles it.
func TestEnumComparedToForeignLiteralInTemplate(t *testing.T) {
	found := rulestest.ProjectRulePlaces(t, NewEnumComparedToForeignLiteralRule(), map[string]string{
		"domain/perm.go": `package domain

type Permission string

const (
	PermOperations Permission = "operations"
	PermExport     Permission = "export"
)

type Role string

func HasPermission(role Role, perm Permission) bool { return role == "admin" || perm == PermExport }
`,
		"admin/funcs.go": `package admin

import (
	"html/template"

	"example.com/rulestest/domain"
)

var funcs = template.FuncMap{
	"hasPerm": func(role, perm string) bool {
		return domain.HasPermission(domain.Role(role), domain.Permission(perm))
	},
	"upper": func(s string) string { return s },
}
`,
		"admin/templates/layout.html": `<nav>
{{if hasPerm .Role "execute_transaction"}}<a href="/run">Run</a>{{end}}
{{if hasPerm .Role "operations"}}<a href="/ops">Ops</a>{{end}}
{{upper "anything"}}
</nav>
`,
	})
	assert.Equal(t, []string{"admin/funcs.go:10"}, found)
}
