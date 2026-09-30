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
