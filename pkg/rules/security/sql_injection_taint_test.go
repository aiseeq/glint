package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSQLInjectionTaintModel covers where the text of a query comes from: a
// string that entered the function as a parameter and reaches the SQL text
// unvalidated is reported; constant text, numbers, placeholders built from
// counters, fragments returned by helpers and values chosen from a whitelist
// are not.
func TestSQLInjectionTaintModel(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "dynamic filter appended by a helper",
			code: `package main

import "database/sql"

type Filter struct{ Kind string }

func appendFilter(q string, args []any, f Filter) (string, []any, int) {
	if f.Kind != "" {
		args = append(args, f.Kind)
		q += " AND kind = $1"
	}
	return q, args, len(args)
}

func countByKind(db *sql.DB, f Filter) {
	query := "SELECT kind, COUNT(*) FROM events WHERE 1=1"
	args := make([]any, 0)
	query, args, _ = appendFilter(query, args, f)
	query += " GROUP BY kind"
	db.Query(query, args...)
}`,
		},
		{
			name: "placeholders built from counters",
			code: `package main

import (
	"database/sql"
	"fmt"
	"strings"
)

func insertAll(db *sql.DB, names []string) {
	query := "INSERT INTO items (name, pos) VALUES "
	values := make([]string, 0, len(names))
	args := make([]any, 0, len(names)*2)
	placeholders := make([]string, 2)
	for i, n := range names {
		for j := range placeholders {
			placeholders[j] = fmt.Sprintf("$%d", i*2+j+1)
		}
		values = append(values, "("+strings.Join(placeholders, ", ")+")")
		args = append(args, n, i)
	}
	query += strings.Join(values, ", ")
	db.Exec(query, args...)
}`,
		},
		{
			name: "IN list of placeholders",
			code: `package main

import (
	"database/sql"
	"fmt"
	"strings"
)

func byKinds(db *sql.DB, kinds []string) {
	query := "SELECT id FROM events WHERE 1=1"
	args := []any{}
	if len(kinds) > 0 {
		ph := make([]string, len(kinds))
		for i, k := range kinds {
			ph[i] = fmt.Sprintf("$%d", i+1)
			args = append(args, k)
		}
		query += " AND kind IN (" + strings.Join(ph, ", ") + ")"
	}
	db.Query(query, args...)
}`,
		},
		{
			name: "fragment helpers called with constants",
			code: `package main

import "database/sql"

func clauseFor(alias string) string { return " AND " + alias + ".kind = 'real'" }

var excludeSystem = clauseFor("u")

const activeOnly = " AND u.active"

func listIDs(db *sql.DB) {
	const query = "SELECT u.id FROM users u WHERE u.deleted = false"
	db.Query(query + clauseFor("t") + activeOnly + excludeSystem)
}`,
		},
		{
			name: "Sprintf with numbers and a validated table",
			code: `package main

import (
	"database/sql"
	"fmt"
	"time"
)

func tableFor(name string) (string, error) {
	if name != "archive" {
		return "", fmt.Errorf("unknown table %q", name)
	}
	return "items_archive", nil
}

func history(db *sql.DB, name string, limit int, since time.Time) error {
	table, err := tableFor(name)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("SELECT price FROM %s WHERE day >= '%s' LIMIT %d", table, since.Format("2006-01-02"), limit)
	_, err = db.Query(query)
	return err
}

func sequence(db *sql.DB, shard int) {
	name := fmt.Sprintf("counter_%d_seq", shard)
	db.QueryRow(fmt.Sprintf("SELECT nextval('%s')", name))
}`,
		},
		{
			name: "condition chosen by a switch",
			code: `package main

import (
	"database/sql"
	"fmt"
)

func undelivered(db *sql.DB, channel string, limit int) error {
	var condition string
	switch channel {
	case "mail":
		condition = "delivered_mail = false"
	case "chat":
		condition = "delivered_chat = false"
	default:
		return fmt.Errorf("unknown channel %q", channel)
	}
	_, err := db.Query(fmt.Sprintf("SELECT id FROM runs WHERE %s LIMIT $1", condition), limit)
	return err
}`,
		},
		{
			name: "parameter validated by a switch with a rejecting default",
			code: `package main

import (
	"database/sql"
	"fmt"
)

func setField(db *sql.DB, column string, value any, id int) error {
	switch column {
	case "is_active", "title":
	default:
		return fmt.Errorf("unsupported column %q", column)
	}
	_, err := db.Exec("UPDATE projects SET "+column+" = $1 WHERE id = $2", value, id)
	return err
}`,
		},
		{
			name: "parameter validated by a whitelist map or a validator",
			code: `package main

import (
	"database/sql"
	"errors"
)

var sortable = map[string]bool{"name": true, "created_at": true}

func validIdent(s string) error { return nil }

func sorted(db *sql.DB, sortBy string) error {
	if !sortable[sortBy] {
		return errors.New("bad sort")
	}
	_, err := db.Query("SELECT id FROM users ORDER BY " + sortBy)
	return err
}

func fromTable(db *sql.DB, table string) error {
	if err := validIdent(table); err != nil {
		return err
	}
	_, err := db.Query("SELECT id FROM " + table)
	return err
}`,
		},
		{
			name: "column looked up in a whitelist map",
			code: `package main

import (
	"database/sql"
	"errors"
)

type ListRequest struct{ Sort string }

var sortColumns = map[string]string{"name": "u.name", "created": "u.created_at"}

func list(db *sql.DB, req ListRequest) error {
	col, ok := sortColumns[req.Sort]
	if !ok {
		return errors.New("bad sort")
	}
	_, err := db.Query("SELECT id FROM users u ORDER BY " + col)
	return err
}`,
		},
		{
			name: "condition parts with placeholders only",
			code: `package main

import (
	"database/sql"
	"fmt"
	"strings"
)

func search(db *sql.DB, status, email string) {
	conds := []string{"1=1"}
	args := []any{}
	if status != "" {
		args = append(args, status)
		conds = append(conds, fmt.Sprintf("status = $%d", len(args)))
	}
	if email != "" {
		args = append(args, email)
		conds = append(conds, "email = $"+fmt.Sprint(len(args)))
	}
	db.Query("SELECT id FROM users WHERE "+strings.Join(conds, " AND "), args...)
}`,
		},
		{
			name: "closure parameter is not an outside value",
			code: `package main

import (
	"database/sql"
	"strings"
)

func search(db *sql.DB, status string) {
	var conds []string
	var args []any
	add := func(cond string, v any) {
		conds = append(conds, cond)
		args = append(args, v)
	}
	add("status = $1", status)
	db.Query("SELECT id FROM users WHERE "+strings.Join(conds, " AND "), args...)
}`,
		},
		{
			name: "parameter joined into condition parts",
			code: `package main

import (
	"database/sql"
	"strings"
)

func search(db *sql.DB, name string) {
	conds := []string{"1=1"}
	if name != "" {
		conds = append(conds, "name = '"+name+"'")
	}
	db.Query("SELECT id FROM users WHERE " + strings.Join(conds, " AND "))
}`,
			want: 1,
		},
		{
			name: "request field in ORDER BY",
			code: `package main

import "database/sql"

type ListRequest struct {
	Sort  string
	Limit int
}

func list(db *sql.DB, req *ListRequest) {
	query := "SELECT id FROM users"
	if req.Sort != "" {
		query += " ORDER BY " + req.Sort
	}
	db.Query(query)
}`,
			want: 1,
		},
		{
			name: "columns ranged from a parameter",
			code: `package main

import "database/sql"

func pick(db *sql.DB, cols []string) {
	query := "SELECT id"
	for _, c := range cols {
		query += ", " + c
	}
	db.Query(query + " FROM users")
}`,
			want: 1,
		},
		{
			name: "empty-string check is no validation",
			code: `package main

import (
	"database/sql"
	"fmt"
)

func byTable(db *sql.DB, table string) error {
	if table == "" {
		return fmt.Errorf("empty table")
	}
	_, err := db.Query(fmt.Sprintf("SELECT id FROM %s", table))
	return err
}`,
			want: 1,
		},
		{
			name: "error check of the database call is no validation",
			code: `package main

import (
	"database/sql"
	"fmt"
)

func touch(db *sql.DB, table, id string) error {
	query := fmt.Sprintf("UPDATE %s SET seen = true WHERE id = $1", table)
	result, err := db.Exec(query, id)
	if err != nil {
		return err
	}
	_ = result
	return nil
}

func count(db *sql.DB, table string) error {
	query := "SELECT COUNT(*) FROM " + table
	var n int
	if err := db.QueryRow(query).Scan(&n); err != nil {
		return err
	}
	return nil
}`,
			want: 2,
		},
		{
			name: "error check of a call with several arguments is no validation",
			code: `package main

import (
	"context"
	"database/sql"
)

func audit(ctx context.Context, table string) error { return nil }

func purge(ctx context.Context, db *sql.DB, table string) error {
	if err := audit(ctx, table); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, "DELETE FROM "+table)
	return err
}`,
			want: 1,
		},
		{
			name: "builder of a package-private type",
			code: `package main

import (
	"database/sql"
	"fmt"
	"strings"
)

type withdrawalQuery struct {
	where string
	args  []any
}

func buildWithdrawalQuery(status string) *withdrawalQuery {
	conds := []string{"type = 'withdrawal'"}
	var args []any
	if status != "" {
		args = append(args, status)
		conds = append(conds, fmt.Sprintf("status = $%d", len(args)))
	}
	return &withdrawalQuery{where: strings.Join(conds, " AND "), args: args}
}

func countWithdrawals(db *sql.DB, q *withdrawalQuery) {
	db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM requests WHERE %s", q.where), q.args...)
}`,
		},
		{
			name: "exported method taking a raw WHERE clause",
			code: `package main

import "database/sql"

type Repo struct{ db *sql.DB }

func (r *Repo) Count(where string, args []any) {
	query := "SELECT COUNT(*) FROM items i" + where
	r.db.QueryRow(query, args...)
}`,
			want: 1,
		},
		{
			name: "switch without a rejecting default is no validation",
			code: `package main

import "database/sql"

func byTable(db *sql.DB, table string) {
	switch table {
	case "":
		table = "users"
	}
	db.Query("SELECT id FROM " + table)
}`,
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // each case loads its own module
			violations := analyzeSQLInjection(t, tt.code)
			assert.Len(t, violations, tt.want, "Code:\n%s", tt.code)
		})
	}
}

func TestSQLInjectionHTTPRequestValuesAreSources(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "request query value",
			code: `package main
import ("database/sql"; "net/http")
func run(db *sql.DB, request *http.Request) {
	value := request.URL.Query().Get("name")
	db.Query("SELECT * FROM users WHERE name='" + value + "'")
}`,
			want: 1,
		},
		{
			name: "request containers kept through local variables",
			code: `package main
import ("database/sql"; "net/http")
func run(db *sql.DB, request *http.Request) {
	values := request.URL.Query()
	form := request.Form
	postForm := request.PostForm
	header := request.Header
	db.Query("SELECT * FROM users WHERE name='" + values.Get("name") + "'")
	db.Query("SELECT * FROM users WHERE name='" + form.Get("name") + "'")
	db.Query("SELECT * FROM users WHERE name='" + postForm.Get("name") + "'")
	db.Query("SELECT * FROM " + header.Get("X-Table"))
}`,
			want: 4,
		},
		{
			name: "request form methods",
			code: `package main
import ("database/sql"; "net/http")
func run(db *sql.DB, request *http.Request) {
	db.Query("SELECT * FROM users WHERE name='" + request.FormValue("name") + "'")
	value := request.PostFormValue("name")
	db.Query("SELECT * FROM users WHERE name='" + value + "'")
}`,
			want: 2,
		},
		{
			name: "request path and header methods",
			code: `package main
import ("database/sql"; "net/http")
func run(db *sql.DB, request *http.Request) {
	value := request.PathValue("id")
	db.Query("SELECT * FROM users WHERE id=" + value)
	value = request.Header.Get("X-Table")
	db.Query("SELECT * FROM " + value)
}`,
			want: 2,
		},
		{
			name: "request cookie value",
			code: `package main
import ("database/sql"; "net/http")
func run(db *sql.DB, request *http.Request) {
	cookie, _ := request.Cookie("session")
	db.Query("SELECT * FROM users WHERE session='" + cookie.Value + "'")
}`,
			want: 1,
		},
		{
			name: "local typed values and headers are not request sources",
			code: `package main
import ("database/sql"; "net/http"; "net/url")
func run(db *sql.DB) {
	var values url.Values
	var header http.Header
	db.Query("SELECT * FROM users WHERE name='" + values.Get("name") + "'")
	db.Query("SELECT * FROM " + header.Get("X-Table"))
}`,
			want: 0,
		},
		{
			name: "unrelated method with matching name",
			code: `package main
import "database/sql"
type lookup struct{}
func (lookup) Get(string) string { return "fixed" }
func run(db *sql.DB, values lookup) {
	db.Query("SELECT * FROM users WHERE name='" + values.Get("name") + "'")
}`,
		},
		{
			name: "placeholder whitelist and numeric conversion stay safe",
			code: `package main
import ("database/sql"; "net/http"; "strconv")
func run(db *sql.DB, request *http.Request) {
	db.Query("SELECT * FROM users WHERE name=$1", request.FormValue("name"))
	order := request.URL.Query().Get("order")
	if order != "name" { return }
	db.Query("SELECT * FROM users ORDER BY " + order)
	n, err := strconv.Atoi(request.URL.Query().Get("limit"))
	if err != nil { return }
	db.Query("SELECT * FROM users LIMIT " + strconv.Itoa(n))
}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			violations := analyzeSQLInjection(t, tt.code)
			assert.Len(t, violations, tt.want, "Code:\n%s", tt.code)
		})
	}
}

func TestSQLInjectionWhitelistMustPrecedeQueryAndRestrictValues(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"regexp"
)

var columnPattern = regexp.MustCompile("^(name|email)$")
var loosePattern = regexp.MustCompile("name|email")
var sharedColumn string

func isBlocked(value string) bool { return value == "blocked" }
func isKnownColumn(value string) bool { return value == "name" || value == "email" }
func looksOkay(value string) bool { return len(value) > 0 }

func late(db *sql.DB, value string) {
	db.Query("SELECT * FROM users WHERE name='" + value + "'")
	if value != "admin" { return }
}

func blacklist(db *sql.DB, value string) {
	if isBlocked(value) { return }
	db.Query("SELECT * FROM users WHERE name='" + value + "'")
}

func arbitrary(db *sql.DB, value string) {
	if !looksOkay(value) { return }
	db.Query("SELECT * FROM users WHERE name='" + value + "'")
}

func whitelist(db *sql.DB, column string) {
	if !isKnownColumn(column) { return }
	db.Query("SELECT " + column + " FROM users")
}

func regexpWhitelist(db *sql.DB, column string) {
	if !columnPattern.MatchString(column) { return }
	db.Query("SELECT " + column + " FROM users")
}

func unanchoredRegexp(db *sql.DB, column string) {
	if !loosePattern.MatchString(column) { return }
	db.Query("SELECT " + column + " FROM users")
}

func validateElsewhere() {
	if !isKnownColumn(sharedColumn) { return }
}

func setShared(column string) {
	sharedColumn = column
}

func useShared(db *sql.DB) {
	db.Query("SELECT " + sharedColumn + " FROM users")
}

func conditionallyValidated(db *sql.DB, column string, enabled bool) {
	if enabled {
		if !isKnownColumn(column) { return }
	}
	db.Query("SELECT " + column + " FROM users")
}

func reassignedAfterValidation(db *sql.DB, column, replacement string) {
	if !isKnownColumn(column) { return }
	column = replacement
	db.Query("SELECT " + column + " FROM users")
}

func localMapWhitelist(db *sql.DB, column string) {
	allowed := map[string]bool{"name": true, "email": true}
	if !allowed[column] { return }
	db.Query("SELECT " + column + " FROM users")
}

`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 7, "late checks, blacklists, arbitrary predicates, unanchored regexps, off-path checks and reassigned values should report")
}

func TestSQLInjectionWhitelistInitOuterBlockAndRegexpAnchors(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"regexp"
)

var allowed = map[string]bool{"name": true, "created": true}
var misleading = regexp.MustCompile("^a|.*$")
var multiline = regexp.MustCompile("(?m)^[a-z_]+$")

func commaOK(db *sql.DB, column string) {
	if _, ok := allowed[column]; !ok { return }
	db.Query("SELECT " + column + " FROM users")
}

func inLoop(db *sql.DB, column string, ids []int) {
	if column != "name" { return }
	for range ids {
		db.Query("SELECT " + column + " FROM users")
	}
}

func inIf(db *sql.DB, column string, enabled bool) {
	if column != "name" { return }
	if enabled {
		db.Query("SELECT " + column + " FROM users")
	}
}

func falseAnchor(db *sql.DB, column string) {
	if !misleading.MatchString(column) { return }
	db.Query("SELECT " + column + " FROM users")
}

func lineAnchor(db *sql.DB, column string) {
	if !multiline.MatchString(column) { return }
	db.Query("SELECT " + column + " FROM users")
}
`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 2, "comma-ok maps and outer-block checks should whitelist, while unanchored regexp branches and line anchors should report")
}

func TestSQLInjectionWhitelistReviewDefects(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "rejecting conjunction of finite exclusions",
			code: `package main
import "database/sql"
func run(db *sql.DB, value string) {
	if value != "first" && value != "second" { return }
	db.Query("SELECT " + value)
}`,
		},
		{
			name: "outer validation before immediately called closure",
			code: `package main
import "database/sql"
func run(db *sql.DB, value string) {
	if value != "column" { return }
	func() { db.Query("SELECT " + value) }()
}`,
		},
		{
			name: "literal map mutated with a dynamic key",
			code: `package main
import "database/sql"
func run(db *sql.DB, value, extra string) {
	allowed := map[string]bool{"fixed": true}
	allowed[extra] = true
	if !allowed[value] { return }
	db.Query("SELECT " + value)
}`,
			want: 1,
		},
		{
			name: "literal map with a dynamic key",
			code: `package main
import "database/sql"
func run(db *sql.DB, value, key string) {
	allowed := map[string]bool{key: true}
	if !allowed[value] { return }
	db.Query("SELECT " + value)
}`,
			want: 1,
		},
		{
			name: "validator error accepted on nil",
			code: `package main
import "database/sql"
func validate(string) error { return nil }
func run(db *sql.DB, value string) {
	if err := validate(value); err == nil { return }
	db.Query("SELECT " + value)
}`,
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			violations := analyzeSQLInjection(t, tt.code)
			assert.Len(t, violations, tt.want, "Code:\n%s", tt.code)
		})
	}
}

func TestSQLInjectionDeferredClosureRunsAfterWhitelistCanChange(t *testing.T) {
	code := `package main
import "database/sql"
func run(db *sql.DB, value, replacement string) {
	if value != "column" { return }
	defer func() { db.Query("SELECT " + value) }()
	value = replacement
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 1, "deferred closures run after the enclosing function returns")
}

func TestSQLInjectionEscapedLiteralMapIsNotAWhitelist(t *testing.T) {
	code := `package main
import "database/sql"
func addValue(values map[string]bool, value string) { values[value] = true }
func run(db *sql.DB, value, extra string) {
	allowed := map[string]bool{"fixed": true}
	addValue(allowed, extra)
	if !allowed[value] { return }
	db.Query("SELECT " + value)
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 1, "a map passed to a function may no longer have a finite literal key set")
}

func TestSQLInjectionLocalURLValuesAndHeadersAreNotRequestSources(t *testing.T) {
	code := `package main
import ("database/sql"; "net/http"; "net/url")
func run(db *sql.DB) {
	values := url.Values{"name": []string{"fixed"}}
	header := http.Header{"X-Table": []string{"users"}}
	parsed, _ := url.ParseQuery("name=fixed")
	db.Query("SELECT * FROM users WHERE name='" + values.Get("name") + "'")
	db.Query("SELECT * FROM " + header.Get("X-Table"))
	db.Query("SELECT * FROM users WHERE name='" + parsed.Get("name") + "'")
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 0, "local values and parsed constants are not HTTP request data")
}

func TestSQLInjectionDeferredClosureKeepsEarlierWhitelistWithoutWrites(t *testing.T) {
	code := `package main
import "database/sql"
func run(db *sql.DB, deferred, launched, changed, replacement string) {
	if deferred != "column" { return }
	defer func() { db.Query("SELECT " + deferred) }()
	if launched != "column" { return }
	go func() { db.Query("SELECT " + launched) }()
	if changed != "column" { return }
	defer func() { db.Query("SELECT " + changed) }()
	changed = replacement
	if replacement != "column" { return }
	go func() { db.Query("SELECT " + replacement) }()
	replacement = changed
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 2, "deferred and launched closures retain validation only when the captured value is never written again")
}

func TestSQLInjectionReadOnlyMapUsesKeepFiniteWhitelist(t *testing.T) {
	code := `package main
import "database/sql"
func inspect(map[string]bool) int { return 0 }
func run(db *sql.DB, value string) {
	allowed := map[string]bool{"column": true}
	_ = len(allowed)
	_ = cap([]int{1})
	for range allowed {}
	if !allowed[value] { return }
	db.Query("SELECT " + value)
}
func passedToHelper(db *sql.DB, value string) {
	allowed := map[string]bool{"column": true}
	inspect(allowed)
	if !allowed[value] { return }
	db.Query("SELECT " + value)
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 1, "read-only builtins and ranging preserve a finite map while passing it to a helper does not")
}

func TestSQLInjectionRequestURLAliasesRemainRequestSources(t *testing.T) {
	code := `package main
import ("database/sql"; "net/http")
func run(db *sql.DB, request *http.Request) {
	urlValue := request.URL
	alias := urlValue
	db.Query("SELECT * FROM users WHERE name='" + alias.Query().Get("name") + "'")
	other := request.URL
	values := other.Query()
	db.Query("SELECT * FROM " + values.Get("table"))
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 2, "URL values copied through local variables still originate from the HTTP request")
}

func TestSQLInjectionURLAssignmentCycleEnds(t *testing.T) {
	code := `package main
import ("database/sql"; "net/url")
func run(db *sql.DB, left, right *url.URL) {
	left = right
	right = left
	db.Query("SELECT * FROM users WHERE name='" + right.Query().Get("name") + "'")
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 0, "URLs assigned to each other are not request data and must not loop")
}

func TestSQLInjectionDeferredClosureNeedsCheckOnItsPath(t *testing.T) {
	code := `package main
import "database/sql"
func run(db *sql.DB, deferred, launched string, strict bool) {
	if strict { if deferred != "column" { return } }
	defer func() { db.Query("SELECT " + deferred) }()
	if strict { if launched != "column" { return } }
	go func() { db.Query("SELECT " + launched) }()
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 2, "a check in a branch does not guard a closure launched after the branch")
}

func TestSQLInjectionCheckInClosureLosesCapturedVariableWrittenOutside(t *testing.T) {
	code := `package main
import "database/sql"
func run(db *sql.DB, deferred, direct, kept, input string, resume chan struct{}) {
	go func() {
		if deferred != "column" { return }
		defer func() { db.Query("SELECT " + deferred) }()
		<-resume
	}()
	go func() {
		if direct != "column" { return }
		<-resume
		db.Query("SELECT " + direct)
	}()
	go func() {
		if kept != "column" { return }
		<-resume
		db.Query("SELECT " + kept)
	}()
	deferred = input
	direct = input
	close(resume)
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 2, "the enclosing function writes the captured variables after the closures check them")
}

func TestSQLInjectionCheckInSynchronousClosureKeepsLaterWrite(t *testing.T) {
	code := `package main
import "database/sql"
func run(db *sql.DB, plain, deferred, input string) {
	func() {
		if plain != "column" { return }
		db.Query("SELECT " + plain)
	}()
	plain = input
	func() {
		if deferred != "column" { return }
		defer func() { db.Query("SELECT " + deferred) }()
	}()
	deferred = input
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 0, "a closure called in place finishes before the enclosing function writes again")
}

func TestSQLInjectionParenthesizedClosureCalledInPlaceKeepsCheck(t *testing.T) {
	code := `package main
import "database/sql"
func run(db *sql.DB, single, double string) {
	if single != "column" { return }
	(func() { db.Query("SELECT " + single) })()
	if double != "column" { return }
	((func() { db.Query("SELECT " + double) }))()
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 0, "parentheses around a closure called in place do not change when it runs")
}

func TestSQLInjectionStoredAndDeferredClosuresKeepTheirChecks(t *testing.T) {
	code := `package main
import "database/sql"
func run(db *sql.DB, outer, inner, deferred, input string) {
	if outer != "column" { return }
	stored := func() { db.Query("SELECT " + outer) }
	stored()
	checking := func() {
		if inner != "column" { return }
		db.Query("SELECT " + inner)
	}
	checking()
	inner = input
	defer func() {
		if deferred != "column" { return }
		db.Query("SELECT " + deferred)
	}()
	deferred = input
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 0, "a closure that checks when it runs, or runs after an unchanged check, is guarded")
}

func TestSQLInjectionStoredClosureLosesOuterCheckOnLaterWrite(t *testing.T) {
	code := `package main
import "database/sql"
func run(db *sql.DB, x, input string) {
	if x != "column" { return }
	stored := func() { db.Query("SELECT " + x) }
	x = input
	stored()
}`
	violations := analyzeSQLInjection(t, code)
	assert.Len(t, violations, 1, "the closure runs after the checked variable is replaced")
}
