package patterns

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func columnWidthFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	base := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"migrations/001_init.up.sql": `CREATE TABLE orders (
    id BIGSERIAL PRIMARY KEY,
    status VARCHAR(20) NOT NULL,
    error_code VARCHAR(20),
    error_message TEXT,
    country CHAR(3)
);`,
		"db/db.go": `package db

import "context"

type Result struct{}

type Pool struct{}

func (p *Pool) Exec(ctx context.Context, sql string, args ...any) (Result, error) { return Result{}, nil }
`,
	}
	for name, content := range files {
		base[name] = content
	}
	violations, err := NewStringLiteralExceedsColumnWidthRule().AnalyzeGoProject(rulestest.Project(t, base))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

const columnWidthRepo = `package store

import (
	"context"

	"example.com/rulestest/db"
)

type Status string

type Repo struct{ pool *db.Pool }

func (r *Repo) SetError(ctx context.Context, id int64, status Status, code, message string) error {
	query := ` + "`UPDATE orders SET status = $1, error_code = $2, error_message = $3 WHERE id = $4`" + `
	_, err := r.pool.Exec(ctx, query, string(status), code, message, id)
	return err
}
`

// A label handed down through two functions to a VARCHAR(20) column is
// refused by the database every time; a short one, and one landing in TEXT,
// fit.
func TestStringLiteralExceedsColumnWidth(t *testing.T) {
	got := columnWidthFindings(t, map[string]string{
		"store/repo.go": columnWidthRepo,
		"flow/flow.go": `package flow

import (
	"context"

	"example.com/rulestest/store"
)

type Flow struct{ repo *store.Repo }

const stepSend = "send the order to the carrier"

func (f *Flow) fail(ctx context.Context, id int64, operation string, err error) {
	_ = f.repo.SetError(ctx, id, "FAILED", operation, err.Error())
}

func (f *Flow) Run(ctx context.Context, id int64, err error) {
	f.fail(ctx, id, "quote", err)
	f.fail(ctx, id, "send order to the carrier", err)
	f.fail(ctx, id, stepSend, err)
	_ = f.repo.SetError(ctx, id, "FAILED", "short", "a message far longer than twenty characters")
	_ = f.repo.SetError(ctx, id, "WAITING_FOR_THE_CARRIER", "short", "")
}
`,
	})
	assert.Equal(t, []string{"flow/flow.go:19", "flow/flow.go:20", "flow/flow.go:22"}, got)
}

// A constant bound to the column in the call that runs the statement is the
// same refusal.
func TestStringLiteralExceedsColumnWidthDirectBind(t *testing.T) {
	got := columnWidthFindings(t, map[string]string{
		"store/repo.go": `package store

import (
	"context"

	"example.com/rulestest/db"
)

type Repo struct{ pool *db.Pool }

func (r *Repo) Expire(ctx context.Context, id int64) error {
	_, err := r.pool.Exec(ctx, ` + "`UPDATE orders SET error_code = $1 WHERE id = $2`" + `, "expired before delivery window", id)
	return err
}

func (r *Repo) Country(ctx context.Context, id int64) error {
	_, err := r.pool.Exec(ctx, ` + "`UPDATE orders SET country = $1 WHERE id = $2`" + `, "SGP", id)
	return err
}
`,
	})
	assert.Equal(t, []string{"store/repo.go:12"}, got)
}

func charColumnLines(t *testing.T, migrations map[string]string, analyzed string) []int {
	t.Helper()
	ctx := rulestest.TextFile(t, analyzed, migrations[analyzed])
	for name, content := range migrations {
		path := filepath.Join(ctx.ProjectRoot, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	return violationLines(NewSQLCharColumnPadsValueRule().AnalyzeFile(ctx))
}

// A CHAR(3) column pads a two-letter code with a space; the line reported is
// the one that gave the column its type last, and a column a later migration
// made VARCHAR, a CHAR(1) flag, and a down migration are left alone.
func TestSQLCharColumnPadsValue(t *testing.T) {
	migrations := map[string]string{
		"migrations/001_init.up.sql": `CREATE TABLE transfers (
    id BIGSERIAL PRIMARY KEY,
    sender_country CHAR(3) NOT NULL,
    payout_country CHAR(3) NOT NULL,
    kind CHAR(1),
    currency VARCHAR(3)
);`,
		"migrations/002_widen.up.sql": `ALTER TABLE transfers ALTER COLUMN payout_country TYPE VARCHAR(3);
ALTER TABLE transfers ADD COLUMN wallet_currency character(3);`,
		"migrations/002_widen.down.sql": `ALTER TABLE transfers ALTER COLUMN payout_country TYPE CHAR(3);`,
	}
	assert.Equal(t, []int{3}, charColumnLines(t, migrations, "migrations/001_init.up.sql"))
	assert.Equal(t, []int{2}, charColumnLines(t, migrations, "migrations/002_widen.up.sql"))
	assert.Empty(t, charColumnLines(t, migrations, "migrations/002_widen.down.sql"))
}
