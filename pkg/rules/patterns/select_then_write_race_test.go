package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSelectThenWriteRaceRule(t *testing.T) {
	rule := NewSelectThenWriteRaceRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			// Repro: projectB financial_repository.go UpdateTransactionStatusLocked
			// before 52352f4 — status read, validated, written without a lock.
			name: "status read then written without lock",
			code: `package repo
import "context"
func (r *Repo) UpdateTransactionStatusLocked(ctx context.Context, id, newStatus string) error {
	var currentStatus string
	err := r.db.GetContext(ctx, &currentStatus,
		` + "`SELECT status FROM financial_transactions WHERE id = $1`" + `, id)
	if err != nil {
		return err
	}
	if err := validator.CanTransition("financial_transaction", currentStatus, newStatus); err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		` + "`UPDATE financial_transactions SET status = $2, updated_at = $3 WHERE id = $1`" + `,
		id, newStatus, timeNow())
	return err
}`,
			expectedCount: 1,
		},
		{
			// Post-fix shape: the SELECT locks the row.
			name: "select with FOR UPDATE is silent",
			code: `package repo
import "context"
func (r *Repo) UpdateStatus(ctx context.Context, id, newStatus string) error {
	var currentStatus string
	err := r.db.GetContext(ctx, &currentStatus,
		` + "`SELECT status FROM financial_transactions WHERE id = $1 FOR UPDATE`" + `, id)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		` + "`UPDATE financial_transactions SET status = $2 WHERE id = $1`" + `, id, newStatus)
	return err
}`,
			expectedCount: 0,
		},
		{
			name: "different tables are silent",
			code: `package repo
import "context"
func (r *Repo) Move(ctx context.Context, id string) error {
	var status string
	_ = r.db.GetContext(ctx, &status, ` + "`SELECT status FROM orders WHERE id = $1`" + `, id)
	_, err := r.db.ExecContext(ctx, ` + "`UPDATE shipments SET status = $2 WHERE id = $1`" + `, id, status)
	return err
}`,
			expectedCount: 0,
		},
		{
			name: "different columns are silent",
			code: `package repo
import "context"
func (r *Repo) Touch(ctx context.Context, id string) error {
	var name string
	_ = r.db.GetContext(ctx, &name, ` + "`SELECT name FROM orders WHERE id = $1`" + `, id)
	_, err := r.db.ExecContext(ctx, ` + "`UPDATE orders SET updated_at = now() WHERE id = $1`" + `, id)
	return err
}`,
			expectedCount: 0,
		},
		{
			name: "update before select is silent",
			code: `package repo
import "context"
func (r *Repo) WriteThenRead(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, ` + "`UPDATE orders SET status = $2 WHERE id = $1`" + `, id, "done")
	if err != nil {
		return err
	}
	var status string
	return r.db.GetContext(ctx, &status, ` + "`SELECT status FROM orders WHERE id = $1`" + `, id)
}`,
			expectedCount: 0,
		},
		{
			name: "select star is silent",
			code: `package repo
import "context"
func (r *Repo) Reload(ctx context.Context, id string) error {
	var row Order
	_ = r.db.GetContext(ctx, &row, ` + "`SELECT * FROM orders WHERE id = $1`" + `, id)
	_, err := r.db.ExecContext(ctx, ` + "`UPDATE orders SET status = $2 WHERE id = $1`" + `, id, row.Status)
	return err
}`,
			expectedCount: 0,
		},
		{
			name: "insert on conflict do update is not an update statement",
			code: `package repo
import "context"
func (r *Repo) Upsert(ctx context.Context, id string) error {
	var status string
	_ = r.db.GetContext(ctx, &status, ` + "`SELECT status FROM orders WHERE id = $1`" + `, id)
	_, err := r.db.ExecContext(ctx,
		` + "`INSERT INTO orders (id, status) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status`" + `,
		id, status)
	return err
}`,
			expectedCount: 0,
		},
		{
			name: "multiline query literals",
			code: `package repo
import "context"
func (r *Repo) Transition(ctx context.Context, id string) error {
	var status string
	_ = r.db.GetContext(ctx, &status, ` + "`\n\t\tSELECT status\n\t\tFROM defi_positions\n\t\tWHERE id = $1`" + `, id)
	if status == "closed" {
		return errClosed
	}
	_, err := r.db.ExecContext(ctx, ` + "`\n\t\tUPDATE defi_positions\n\t\tSET status = $2, updated_at = now()\n\t\tWHERE id = $1`" + `, id, "closed")
	return err
}`,
			expectedCount: 1,
		},
		{
			name: "suppression comment is honored",
			code: `package repo
import "context"
func (r *Repo) Transition(ctx context.Context, id string) error {
	var status string
	_ = r.db.GetContext(ctx, &status, ` + "`SELECT status FROM orders WHERE id = $1`" + `, id)
	_, err := r.db.ExecContext(ctx,
		// nolint:select-then-write-race — единственный писатель, сериализовано advisory lock'ом
		` + "`UPDATE orders SET status = $2 WHERE id = $1`" + `, id, "done")
	return err
}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/src/file.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}
