package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const upsertStageRepo = `package store

import (
	"context"
	"time"

	"example.com/rulestest/db"
)

type PaymentStatus string

const (
	PaymentPending   PaymentStatus = "pending"
	PaymentCompleted PaymentStatus = "completed"
	PaymentFailed    PaymentStatus = "failed"
)

type Payment struct {
	ID          string
	Status      string
	SettledAt   *time.Time
	RefundedAt  *time.Time
}

type Repo struct{ pool *db.Pool }

// The upsert records the settlement time when the payment arrives
// completed, under a name that is not the status's.
func (r *Repo) Upsert(ctx context.Context, p *Payment) error {
	settledAt := p.SettledAt
	if settledAt == nil && p.Status == string(PaymentCompleted) {
		now := time.Now()
		settledAt = &now
	}
	_, err := r.pool.Exec(ctx, ` + "`" + `INSERT INTO payments (id, status, settled_at, refunded_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status,
			settled_at = COALESCE(payments.settled_at, EXCLUDED.settled_at),
			refunded_at = EXCLUDED.refunded_at` + "`" + `, p.ID, p.Status, settledAt, p.RefundedAt)
	return err
}

func (r *Repo) SetStatus(ctx context.Context, id string, status string) error {
	_, err := r.pool.Exec(ctx, "UPDATE payments SET status = $1, updated_at = NOW() WHERE id = $2", status, id) // want status-write-skips-stage-timestamp
	return err
}

func (r *Repo) Complete(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "UPDATE payments SET status = 'completed', settled_at = COALESCE(settled_at, NOW()) WHERE id = $1", id)
	return err
}

func (r *Repo) Fail(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "UPDATE payments SET status = 'failed' WHERE id = $1", id)
	return err
}
`

// The upsert stamps settled_at for completed payments by a value it sets
// in Go when the status is completed; the manual status change can set
// completed and leaves settled_at NULL. A column the upsert copies
// whatever the status (refunded_at) is not tied to a stage, and a write of
// another status needs no stamp.
func TestStatusWriteSkipsStageTimestampStampedByUpsert(t *testing.T) {
	files := map[string]string{
		"go.mod":        "module example.com/rulestest\n\ngo 1.24\n",
		"db/db.go":      "package db\n\nimport \"context\"\n\ntype Result struct{}\n\ntype Pool struct{}\n\nfunc (p *Pool) Exec(ctx context.Context, sql string, args ...any) (Result, error) { return Result{}, nil }\n",
		"store/repo.go": upsertStageRepo,
	}
	violations, err := NewStatusWriteSkipsStageTimestampRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "status-write-skips-stage-timestamp"), foundLines(violations))
}
