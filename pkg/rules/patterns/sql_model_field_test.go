package patterns

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A model saved or loaded by a query that leaves out some of its db columns:
// the INSERT stores the column default instead of the model's value, the
// SELECT hands back a model whose fields stay zero, the column list of the
// model misses one of its own fields.
func TestSQLModelFieldSkipped(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": `
CREATE TABLE positions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    amount NUMERIC NOT NULL,
    region_id INT NOT NULL DEFAULT 1,
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE runs (id UUID PRIMARY KEY, status TEXT NOT NULL, found INT NOT NULL DEFAULT 0);`,
		"storage/model.go": `package storage

type Position struct {
	ID        string ` + "`db:\"id\"`" + `
	AccountID string ` + "`db:\"account_id\"`" + `
	Amount    string ` + "`db:\"amount\"`" + `
	RegionID int    ` + "`db:\"region_id\"`" + `
	Comment   string ` + "`db:\"comment\"`" + `
	CreatedAt string ` + "`db:\"created_at\"`" + `
	Label     string ` + "`json:\"label\"`" + `
}

type Run struct {
	ID     string ` + "`db:\"id\"`" + `
	Status string ` + "`db:\"status\"`" + `
	Found  int    ` + "`db:\"found\"`" + `
}

func (p *Position) InsertColumns() []string {
	return []string{
		"id", "account_id", "amount", "created_at",
	}
}

func (p *Position) AllColumns() []string {
	return []string{"id", "account_id", "amount", "region_id", "comment", "created_at"}
}
`,
		"storage/repo.go": `package storage

import "context"

type Result interface{ RowsAffected() (int64, error) }

type Row interface{ Scan(dest ...any) error }

type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) Row
}

func Save(ctx context.Context, db DB, p *Position) error {
	_, err := db.ExecContext(ctx, ` + "`INSERT INTO positions (id, account_id, amount) VALUES ($1, $2, $3)`" + `, p.ID, p.AccountID, p.Amount)
	return err
}

func SaveFull(ctx context.Context, db DB, p *Position) error {
	_, err := db.ExecContext(ctx, ` + "`INSERT INTO positions (account_id, amount, region_id, comment) VALUES ($1, $2, $3, $4)`" + `,
		p.AccountID, p.Amount, p.RegionID, p.Comment)
	return err
}

func Get(ctx context.Context, db DB, id string) (*Position, error) {
	var p Position
	query := ` + "`" + `
		SELECT id, account_id, amount,
		       created_at
		FROM positions WHERE id = $1` + "`" + `
	err := db.QueryRowContext(ctx, query, id).Scan(&p.ID, &p.AccountID, &p.Amount, &p.CreatedAt)
	return &p, err
}

func AmountOf(ctx context.Context, db DB, id string) (string, error) {
	var p Position
	err := db.QueryRowContext(ctx, "SELECT amount, account_id FROM positions WHERE id = $1", id).Scan(&p.Amount, &p.AccountID)
	return p.Amount, err
}

// A run is created first and its counters are written when it finishes.
func StartRun(ctx context.Context, db DB, run *Run) error {
	_, err := db.ExecContext(ctx, "INSERT INTO runs (id, status) VALUES ($1, $2)", run.ID, run.Status)
	return err
}

func FinishRun(ctx context.Context, db DB, run *Run) error {
	_, err := db.ExecContext(ctx, "UPDATE runs SET status = $1, found = $2 WHERE id = $3", run.Status, run.Found, run.ID)
	return err
}

func Exists(ctx context.Context, db DB, id string) (bool, error) {
	var found string
	err := db.QueryRowContext(ctx, "SELECT id FROM positions WHERE id = $1", id).Scan(&found)
	return found != "", err
}
`,
	}
	violations, err := NewSQLModelFieldSkippedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var places []string
	for _, v := range violations {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	slices.Sort(places)
	assert.Equal(t, []string{"storage/model.go:21", "storage/repo.go:15", "storage/repo.go:29"}, places)
}
