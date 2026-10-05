package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// queueDB stands in for a pool and a transaction of a database driver.
const queueDB = `package db

import "context"

type Rows struct{}

func (r *Rows) Close() {}

type Tag struct{}

func (t Tag) RowsAffected() int64 { return 1 }

type Pool struct{}

func (p *Pool) Query(ctx context.Context, sql string, args ...any) (*Rows, error) { return &Rows{}, nil }
func (p *Pool) Exec(ctx context.Context, sql string, args ...any) (Tag, error)    { return Tag{}, nil }
func (p *Pool) Begin(ctx context.Context) (*Tx, error)                             { return &Tx{}, nil }

type Tx struct{}

func (t *Tx) Query(ctx context.Context, sql string, args ...any) (*Rows, error) { return &Rows{}, nil }
func (t *Tx) Commit(ctx context.Context) error                                    { return nil }
`

// A claim that re-takes rows whose lease expired, without counting the
// attempt, loops forever on a row the worker crashes on.
func TestLeaseReclaimWithoutAttemptLimit(t *testing.T) {
	assert.Equal(t, []string{"queue/claim.go:12"}, typedFuncFindings(t, NewLeaseReclaimWithoutAttemptLimitRule(), map[string]string{
		"db/db.go": queueDB,
		"queue/claim.go": `package queue

import (
	"context"

	"example.com/rulestest/db"
)

type Repo struct{ pool *db.Pool }

func (r *Repo) Claim(ctx context.Context, limit int, leaseSeconds float64) error {
	query := ` + "`" + `
		WITH candidates AS (
			SELECT id FROM outbox
			WHERE (status = 'PENDING' AND next_retry_at <= NOW())
				OR (status = 'PROCESSING' AND updated_at <= NOW() - ($2 * interval '1 second'))
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE outbox q SET status = 'PROCESSING' FROM candidates c WHERE q.id = c.id
		RETURNING q.id, q.attempts, q.max_attempts` + "`" + `
	_, err := r.pool.Query(ctx, query, limit, leaseSeconds)
	return err
}

func (r *Repo) ClaimCounted(ctx context.Context, limit int, leaseSeconds float64) error {
	query := ` + "`" + `
		WITH candidates AS (
			SELECT id FROM outbox
			WHERE (status = 'PENDING' AND next_retry_at <= NOW())
				OR (status = 'PROCESSING' AND updated_at <= NOW() - ($2 * interval '1 second'))
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE outbox q SET status = 'PROCESSING',
			attempts = q.attempts + (CASE WHEN q.status = 'PROCESSING' THEN 1 ELSE 0 END)
		FROM candidates c WHERE q.id = c.id` + "`" + `
	_, err := r.pool.Query(ctx, query, limit, leaseSeconds)
	return err
}

// ClaimPending takes only pending rows: nothing is reclaimed.
func (r *Repo) ClaimPending(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, ` + "`" + `UPDATE outbox SET status = 'PROCESSING' WHERE status = 'PENDING' AND next_retry_at <= NOW()` + "`" + `)
	return err
}
`,
	}))
}

// A claim that leaves the row in its claimable status and does not test a
// column it sets lets a second caller claim the same row again.
func TestRepeatableClaim(t *testing.T) {
	assert.Equal(t, []string{"approvals/repo.go:14"}, typedFuncFindings(t, NewRepeatableClaimRule(), map[string]string{
		"db/db.go": queueDB,
		"approvals/repo.go": `package approvals

import (
	"context"
	"errors"

	"example.com/rulestest/db"
)

type Repo struct{ pool *db.Pool }

// ClaimForApproval records the approver while the row waits for approval.
func (r *Repo) ClaimForApproval(ctx context.Context, id string, version int, approver int) error {
	query := ` + "`" + `
		UPDATE payments
		SET approved_by = $1, version = version + 1
		WHERE id = $2 AND version = $3 AND status = $4` + "`" + `
	tag, err := r.pool.Exec(ctx, query, approver, id, version, "WAITING_APPROVAL")
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("conflict")
	}
	return nil
}

// ClaimOnce tests the column it sets: a second claim finds it taken.
func (r *Repo) ClaimOnce(ctx context.Context, id string, version int, approver int) error {
	query := ` + "`" + `
		UPDATE payments
		SET approved_by = $1, version = version + 1
		WHERE id = $2 AND version = $3 AND status = $4 AND approved_by IS NULL` + "`" + `
	_, err := r.pool.Exec(ctx, query, approver, id, version, "WAITING_APPROVAL")
	return err
}

// ClaimRunning moves the row out of the claimable status.
func (r *Repo) ClaimRunning(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, ` + "`" + `UPDATE batches SET status = 'RUNNING', updated_at = now() WHERE id = $1 AND status = 'PENDING'` + "`" + `, id)
	return err
}
`,
	}))
}

// FOR UPDATE through the pool locks the rows for the one statement that
// selects them: the lock is gone before the caller updates them.
func TestForUpdateOutsideTransaction(t *testing.T) {
	assert.Equal(t, []string{"queue/pending.go:20"}, typedFuncFindings(t, NewForUpdateOutsideTransactionRule(), map[string]string{
		"db/db.go": queueDB,
		"queue/pending.go": `package queue

import (
	"context"

	"example.com/rulestest/db"
)

type Repo struct{ pool *db.Pool }

func (r *Repo) Pending(ctx context.Context, limit int) error {
	query := ` + "`" + `
		SELECT id, payload
		FROM outbox
		WHERE status = 'PENDING'
		ORDER BY next_retry_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED` + "`" + `

	rows, err := r.pool.Query(ctx, query, limit)
	if err != nil {
		return err
	}
	rows.Close()
	return nil
}

// The claim selects and updates in one statement.
func (r *Repo) Claim(ctx context.Context, limit int) error {
	rows, err := r.pool.Query(ctx, ` + "`" + `
		WITH c AS (SELECT id FROM outbox WHERE status = 'PENDING' LIMIT $1 FOR UPDATE SKIP LOCKED)
		UPDATE outbox q SET status = 'PROCESSING' FROM c WHERE q.id = c.id RETURNING q.id` + "`" + `, limit)
	if err != nil {
		return err
	}
	rows.Close()
	return nil
}

// Inside a transaction the lock holds until Commit.
func (r *Repo) Locked(ctx context.Context, limit int) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, ` + "`SELECT id FROM outbox WHERE status = 'PENDING' FOR UPDATE`" + `)
	if err != nil {
		return err
	}
	rows.Close()
	return tx.Commit(ctx)
}
`,
	}))
}

// An error branch after a claim that returns without finalizing the item
// leaves it leased: the lease expires, the row is claimed again and fails the
// same way, forever.
func TestPoisonRowLeftClaimed(t *testing.T) {
	assert.Equal(t, []string{"worker/worker.go:32"}, typedFuncFindings(t, NewPoisonRowLeftClaimedRule(), map[string]string{
		"worker/worker.go": `package worker

import (
	"context"
	"errors"
	"log/slog"
)

type Item struct{ ID, Lease string }

type Repo struct{}

func (r *Repo) ClaimPending(ctx context.Context, limit int) ([]Item, error) { return nil, nil }
func (r *Repo) ClaimLegs(ctx context.Context) ([]Item, error)                 { return nil, nil }
func (r *Repo) ClaimRow(ctx context.Context, id string) (bool, error)        { return true, nil }
func (r *Repo) LockOrder(ctx context.Context, id string) (Item, error)       { return Item{}, nil }

type Worker struct {
	repo   *Repo
	logger *slog.Logger
}

func validate(item Item) error { return errors.New("bad counters") }

func (w *Worker) Next(ctx context.Context) {
	items, err := w.repo.ClaimPending(ctx, 1)
	if err != nil {
		w.logger.Error("claim failed", "error", err)
		return
	}
	for _, item := range items {
		if err := validate(item); err != nil {
			w.logger.Error("invalid item", "id", item.ID, "error", err)
			return
		}
		if err := w.deliver(ctx, item); err != nil {
			if ferr := w.handleFailure(ctx, item, err); ferr != nil {
				w.logger.Error("failed to record failure", "error", ferr)
				return
			}
			continue
		}
		if merr := w.markSent(ctx, item); merr != nil {
			w.logger.Error("failed to mark sent", "error", merr)
		}
	}
}

func (w *Worker) NextDeadLettered(ctx context.Context) {
	items, err := w.repo.ClaimPending(ctx, 1)
	if err != nil {
		return
	}
	for _, item := range items {
		if err := validate(item); err != nil {
			_ = w.markFailed(ctx, item, err)
			continue
		}
	}
}

// A claim of one row answered with a flag, and a lock taken in a
// transaction, hold nothing past the function: the rollback releases them.
func (w *Worker) ClaimOne(ctx context.Context, id string) error {
	claimed, err := w.repo.ClaimRow(ctx, id)
	if err != nil {
		return err
	}
	if !claimed {
		return nil
	}
	if err := validate(Item{ID: id}); err != nil {
		return err
	}
	return nil
}

func (w *Worker) Locked(ctx context.Context, id string) error {
	order, err := w.repo.LockOrder(ctx, id)
	if err != nil {
		return err
	}
	if err := validate(order); err != nil {
		return err
	}
	return nil
}

// A report over reward claims settles nothing: "claim" is its subject, not
// a lease.
func (w *Worker) Report(ctx context.Context) error {
	legs, err := w.repo.ClaimLegs(ctx)
	if err != nil {
		return err
	}
	for _, leg := range legs {
		if err := validate(leg); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) deliver(ctx context.Context, item Item) error                   { return nil }
func (w *Worker) handleFailure(ctx context.Context, item Item, err error) error { return nil }
func (w *Worker) markSent(ctx context.Context, item Item) error                  { return nil }
func (w *Worker) markFailed(ctx context.Context, item Item, err error) error     { return nil }
`,
	}))
}

// A failed remote cancel that is only logged, followed by the local
// cancellation, leaves money moving at the provider while the record says it
// stopped; a classifier that reads "completed" as "already cancelled" does the
// same for a payout that went through.
func TestRemoteCancelFailureIgnored(t *testing.T) {
	assert.Equal(t, []string{"payout/cancel.go:25", "payout/cancel.go:37"}, typedFuncFindings(t, NewRemoteCancelFailureIgnoredRule(), map[string]string{
		"payout/cancel.go": `package payout

import (
	"context"
	"log/slog"
	"strings"
)

type Client struct{}

func (c *Client) CancelTransaction(ref string) error { return nil }

type Repo struct{}

func (r *Repo) UpdateStatus(ctx context.Context, id, status string) error { return nil }

type Service struct {
	client *Client
	repo   *Repo
	logger *slog.Logger
}

func (s *Service) Cancel(ctx context.Context, id, ref string) error {
	if ref != "" {
		if err := s.client.CancelTransaction(ref); err != nil {
			s.logger.Error("failed to cancel at provider", "error", err)
		}
	}
	return s.repo.UpdateStatus(ctx, id, "CANCELLED")
}

// alreadyTerminal tells whether the provider's refusal means the transfer
// is already over.
func alreadyTerminal(message string) bool {
	msg := strings.ToLower(message)
	return strings.Contains(msg, "cancelled") ||
		strings.Contains(msg, "completed")
}

func alreadyCancelled(message string) bool {
	msg := strings.ToLower(message)
	return strings.Contains(msg, "cancelled") || strings.Contains(msg, "canceled")
}

func (s *Service) CancelStrict(ctx context.Context, id, ref string) error {
	if err := s.client.CancelTransaction(ref); err != nil {
		if !alreadyCancelled(err.Error()) {
			return err
		}
		s.logger.Info("already cancelled at provider")
	}
	return s.repo.UpdateStatus(ctx, id, "CANCELLED")
}
`,
	}))
}
