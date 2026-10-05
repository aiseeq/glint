package patterns

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const sqlScanMigration = `
CREATE TABLE requests (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL,
    from_addr TEXT,
    to_addr TEXT,
    memo TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE accounts (id UUID PRIMARY KEY, email TEXT NOT NULL, nickname TEXT);
`

const sqlScanModel = `package storage

import "time"

type Request struct {
	ID        string    ` + "`db:\"id\"`" + `
	AccountID string    ` + "`db:\"account_id\"`" + `
	FromAddr  string    ` + "`db:\"from_addr\"`" + `
	ToAddr    *string   ` + "`db:\"to_addr\"`" + `
	Memo      string    ` + "`db:\"memo\"`" + `
	CreatedAt time.Time ` + "`db:\"created_at\"`" + `
}

type Stats struct {
	AccountID string // want sqlx-column-without-field
	Total     int    ` + "`db:\"total\"`" + `
}
`

const sqlScanRepo = `package storage

import (
	"context"
	"fmt"
)

type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
}

type Row interface{ Scan(dest ...any) error }

type DB interface {
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) Row
	GetContext(ctx context.Context, dest any, query string, args ...any) error
	SelectContext(ctx context.Context, dest any, query string, args ...any) error
}

func List(ctx context.Context, db DB, where string) ([]Request, error) {
	query := fmt.Sprintf(` + "`" + `
		SELECT r.id, r.account_id, r.from_addr, r.to_addr, a.email
		FROM requests r JOIN accounts a ON a.id = r.account_id
		WHERE %s` + "`" + `, where)
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		var email string
		if err := rows.Scan(
			&r.ID,
			&r.AccountID,
			&r.FromAddr, // want sql-scan-nullable-into-value
			&r.ToAddr,
			&email,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func Owner(ctx context.Context, db DB, id string) (string, error) {
	var nickname string
	err := db.QueryRowContext(ctx, "SELECT a.nickname FROM requests r LEFT JOIN accounts a ON a.id = r.account_id WHERE r.id = $1", id).Scan(&nickname) // want sql-scan-nullable-into-value
	return nickname, err
}

func Email(ctx context.Context, db DB, id string) (string, error) {
	var email string
	err := db.QueryRowContext(ctx, "SELECT email FROM accounts WHERE id = $1", id).Scan(&email)
	return email, err
}

func Recent(ctx context.Context, db DB, filter string) ([]*Request, error) {
	query := ` + "`" + `SELECT r.id, r.account_id, COALESCE(r.from_addr, '') AS from_addr,
		r.memo, r.created_at
		FROM requests r WHERE 1=1` + "`" + ` + filter // the line above: want sql-scan-nullable-into-value
	query += " ORDER BY r.created_at DESC"
	var out []*Request
	err := db.SelectContext(ctx, &out, query)
	return out, err
}

func AccountStats(ctx context.Context, db DB) ([]Stats, error) {
	var out []Stats
	err := db.SelectContext(ctx, &out, ` + "`SELECT account_id, COUNT(*) AS total FROM requests GROUP BY account_id`" + `)
	return out, err
}

func Totals(ctx context.Context, db DB) ([]Stats, error) {
	var out []Stats
	err := db.SelectContext(ctx, &out, ` + "`SELECT COUNT(*) AS total, max(created_at) AS latest FROM requests`" + `) // want sqlx-column-without-field
	return out, err
}

func Count(ctx context.Context, db DB) (int, error) {
	var n int
	err := db.GetContext(ctx, &n, "SELECT COUNT(*) FROM requests")
	return n, err
}
`

// wantedLines returns file:line of the lines marked "want <rule>"; a marker
// saying "the line above" points at the previous line.
func wantedLines(files map[string]string, rule string) []string {
	var places []string
	for name, source := range files {
		for i, line := range strings.Split(source, "\n") {
			if !strings.Contains(line, "want "+rule) {
				continue
			}
			n := i + 1
			if strings.Contains(line, "the line above") {
				n--
			}
			places = append(places, fmt.Sprintf("%s:%d", name, n))
		}
	}
	slices.Sort(places)
	return places
}

func foundLines(violations []*core.Violation) []string {
	var places []string
	for _, v := range violations {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	slices.Sort(places)
	return places
}

func TestSQLScanRules(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": sqlScanMigration,
		"storage/model.go":                   sqlScanModel,
		"storage/repo.go":                    sqlScanRepo,
	}
	project := rulestest.Project(t, files)

	// A column that can be NULL read into a string, a number, a bool or a
	// time fails the query on the first row holding NULL.
	violations, err := NewSQLScanNullableRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "sql-scan-nullable-into-value"), foundLines(violations))

	// sqlx fails a Get or Select whose row has a column the struct has no
	// field for; a field without a db tag reads its lower-cased name.
	violations, err = NewSQLXColumnWithoutFieldRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "sqlx-column-without-field"), foundLines(violations))
}

const sqlScanCountRepo = `package storage

import (
	"context"
	"fmt"
)

type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
}

type Row interface{ Scan(dest ...any) error }

type DB interface {
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) Row
}

type Account struct {
	ID, Email, Nickname, Source string
}

const accountColumns = "id, email, nickname"

func ByID(ctx context.Context, db DB, id string) (*Account, error) {
	query := ` + "`SELECT id, email, nickname FROM accounts WHERE id = $1`" + `
	var a Account
	err := db.QueryRowContext(ctx, query, id).Scan(&a.ID, &a.Email, &a.Source, &a.Nickname) // want sql-scan-arg-count-mismatch
	return &a, err
}

func List(ctx context.Context, db DB) ([]Account, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, email FROM accounts ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Email, &a.Nickname); err != nil { // want sql-scan-arg-count-mismatch
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func Matching(ctx context.Context, db DB, id string) (*Account, error) {
	var a Account
	err := db.QueryRowContext(ctx, "SELECT "+accountColumns+" FROM accounts WHERE id = $1", id).Scan(&a.ID, &a.Email, &a.Nickname)
	return &a, err
}

func Built(ctx context.Context, db DB, columns string, id string) (*Account, error) {
	var a Account
	err := db.QueryRowContext(ctx, "SELECT id, "+columns+" FROM accounts WHERE id = $1", id).Scan(&a.ID, &a.Email, &a.Nickname)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("SELECT %s FROM accounts WHERE id = $1", columns)
	err = db.QueryRowContext(ctx, query, id).Scan(&a.ID, &a.Email)
	return &a, err
}

func Spread(ctx context.Context, db DB, id string, dest []any) error {
	return db.QueryRowContext(ctx, "SELECT id, email FROM accounts WHERE id = $1", id).Scan(dest...)
}
`

// A Scan with more or fewer destinations than the SELECT has columns is
// refused on every row; a select list the code builds is not counted.
func TestSQLScanArgCountMismatch(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": sqlScanMigration,
		"storage/repo.go":                    sqlScanCountRepo,
	}
	violations, err := NewSQLScanArgCountRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "sql-scan-arg-count-mismatch"), foundLines(violations))
}
