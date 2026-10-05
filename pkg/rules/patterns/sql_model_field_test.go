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

// A model without db tags is mapped by hand: the repository binds its fields
// one by one into the INSERT and scans them back. Fields the handler fills
// (Remark, State) that neither the INSERT nor any read of the repository
// mentions are lost on the first reload, though the request builder reads
// them later. A field nobody sets (a computed one) is not a loss, and a field
// with a db tag is the tagged check's: db:"-" says it is not kept, a column
// tag is read by name.
func TestSQLModelFieldNeverPersistedByHandMapping(t *testing.T) {
	files := map[string]string{
		"domain/txn.go": `package domain

type Transaction struct {
	ID, Ref, Status, Currency, Country, FirstName, LastName, Email, Phone, City string
	Amount, Fee                                                                int64
	Remark, State                                                              string
	Display                                                                    string
	Derived                                                                    bool ` + "`db:\"-\"`" + `
}
`,
		"storage/repo.go": `package storage

import "example.com/rulestest/domain"

type DB interface {
	Exec(query string, args ...any) error
	Scan(dest ...any) error
}

type Repo struct{ db DB }

func (r *Repo) Create(tx *domain.Transaction) error {
	query := "INSERT INTO transactions (id, ref, status, currency, country, first_name, last_name, email, phone, city, amount, fee) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
	return r.db.Exec(query, tx.ID, tx.Ref, tx.Status, tx.Currency, tx.Country, tx.FirstName,
		tx.LastName, nullStr(tx.Email), tx.Phone, tx.City, tx.Amount, tx.Fee)
}

func (r *Repo) Get(tx *domain.Transaction) error {
	return r.db.Scan(&tx.ID, &tx.Ref, &tx.Status, &tx.Currency, &tx.Country, &tx.FirstName,
		&tx.LastName, &tx.Email, &tx.Phone, &tx.City, &tx.Amount, &tx.Fee)
}

func nullStr(s string) *string { return &s }
`,
		"admin/handler.go": `package admin

import "example.com/rulestest/domain"

func build(remark, state string) *domain.Transaction {
	tx := &domain.Transaction{Remark: remark}
	tx.State = state
	tx.Derived = true
	return tx
}

func request(tx *domain.Transaction) string { return tx.Remark + tx.State + tx.Display }
`,
	}
	violations, err := NewSQLModelFieldSkippedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "storage/repo.go", violations[0].File)
	assert.Equal(t, 14, violations[0].Line)
	assert.Contains(t, violations[0].Message, "leaves out Remark, State,")
}
