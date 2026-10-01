package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
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
			// — status read, validated, written without a lock.
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
			// The recommended fix: the UPDATE compares the column it read, so a
			// concurrent change makes it affect no row instead of overwriting.
			name: "optimistic compare-and-set on the value read is silent",
			code: `package repo
import "context"
func (r *Repo) Close(ctx context.Context, id string) error {
	var st string
	_ = r.db.GetContext(ctx, &st, ` + "`SELECT status FROM orders WHERE id = $1`" + `, id)
	_, err := r.db.ExecContext(ctx, ` + "`UPDATE orders SET status = $1 WHERE id = $2 AND o.status = $3`" + `, "closed", id, st)
	return err
}`,
			expectedCount: 0,
		},
		{
			name: "conditional update on an allowed set is silent",
			code: `package repo
import "context"
func (r *Repo) Close(ctx context.Context, id string) error {
	var st string
	_ = r.db.GetContext(ctx, &st, ` + "`SELECT status FROM orders WHERE id = $1`" + `, id)
	_, err := r.db.ExecContext(ctx, ` + "`UPDATE orders SET status = 'closed' WHERE id = $1 AND status IN ('open', 'pending')`" + `, id)
	return err
}`,
			expectedCount: 0,
		},
		{
			name: "a quoted word in WHERE is not the column",
			code: `package repo
import "context"
func (r *Repo) Close(ctx context.Context, id string) error {
	var st string
	_ = r.db.GetContext(ctx, &st, ` + "`SELECT status FROM orders WHERE id = $1`" + `, id)
	_, err := r.db.ExecContext(ctx, ` + "`UPDATE orders SET status = $1 WHERE id = $2 AND note <> 'status'`" + `, "closed", id)
	return err
}`,
			expectedCount: 1,
		},
		{
			// An upsert replaced by a lookup and an INSERT: two webhooks
			// for one hash both find no row and both insert.
			name: "lookup by key then insert without ON CONFLICT",
			code: `package repo
import "context"
func (h *Handler) Save(ctx context.Context, hash, status string) error {
	var existingID, existingStatus string
	err := h.db.QueryRowContext(ctx, ` + "`SELECT id, status FROM transactions WHERE transaction_hash = $1`" + `, hash).Scan(&existingID, &existingStatus)
	if err == nil {
		return nil
	}
	_, err = h.db.ExecContext(ctx, ` + "`INSERT INTO transactions (id, status, transaction_hash) VALUES ($1, $2, $3)`" + `, newID(), status, hash)
	return err
}`,
			expectedCount: 1,
		},
		{
			name: "existence count then insert",
			code: `package repo
import "context"
func (r *Repo) Register(ctx context.Context, email string) error {
	var n int
	_ = r.db.QueryRowContext(ctx, ` + "`SELECT COUNT(*) FROM users WHERE email = $1`" + `, email).Scan(&n)
	if n > 0 {
		return errExists
	}
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO users (id, email) VALUES ($1, $2)`" + `, newID(), email)
	return err
}`,
			expectedCount: 1,
		},
		{
			// The upsert itself, and an insert of a key the lookup did not
			// read, stay silent.
			name: "insert with ON CONFLICT or of another key",
			code: `package repo
import "context"
func (h *Handler) Save(ctx context.Context, hash, userID string) error {
	var id string
	_ = h.db.QueryRowContext(ctx, ` + "`SELECT id FROM transactions WHERE transaction_hash = $1`" + `, hash).Scan(&id)
	_, err := h.db.ExecContext(ctx, ` + "`INSERT INTO transactions (id, transaction_hash) VALUES ($1, $2) ON CONFLICT (transaction_hash) DO UPDATE SET updated_at = now()`" + `, id, hash)
	if err != nil {
		return err
	}
	_, err = h.db.ExecContext(ctx, ` + "`INSERT INTO audit_log (id, user_id) VALUES ($1, $2)`" + `, id, userID)
	if err != nil {
		return err
	}
	_, err = h.db.ExecContext(ctx, ` + "`INSERT INTO transactions (id, user_id) VALUES ($1, $2)`" + `, id, userID)
	return err
}`,
			expectedCount: 0,
		},
		{
			// An advisory lock taken first serializes the callers.
			name: "advisory lock before lookup and insert",
			code: `package repo
import "context"
func (r *Repo) Apply(ctx context.Context, tx Tx, name string) error {
	if _, err := tx.Exec(ctx, ` + "`SELECT pg_advisory_xact_lock($1)`" + `, lockKey); err != nil {
		return err
	}
	var applied bool
	_ = tx.QueryRow(ctx, ` + "`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE filename = $1)`" + `, name).Scan(&applied)
	if applied {
		return nil
	}
	_, err := tx.Exec(ctx, ` + "`INSERT INTO schema_migrations (filename) VALUES ($1)`" + `, name)
	return err
}`,
			expectedCount: 0,
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

// Queries held in package constants are read through the type checker's
// constant values.
func TestSelectThenWriteRaceRule_PackageConstants(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"repo/queries.go": `package repo

const selectStatus = "SELECT status FROM orders WHERE id = $1"

const (
	updatePrefix = "UPDATE orders "
	updateStatus = updatePrefix + "SET status = $1 WHERE id = $2"
)
`,
		"repo/repo.go": `package repo

import (
	"context"
	"database/sql"
)

type Repo struct{ db *sql.DB }

func (r *Repo) Close(ctx context.Context, id int) error {
	var st string
	if err := r.db.QueryRowContext(ctx, selectStatus, id).Scan(&st); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, updateStatus, "closed", id)
	return err
}

func (r *Repo) CloseLocked(ctx context.Context, id int) error {
	var st string
	if err := r.db.QueryRowContext(ctx, selectStatus+" FOR UPDATE", id).Scan(&st); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, updateStatus, "closed", id)
	return err
}
`,
	})

	violations, err := NewSelectThenWriteRaceRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "Close", violations[0].Context["function"])
	assert.Equal(t, "status", violations[0].Context["column"])
	assert.Equal(t, 15, violations[0].Line)
}
