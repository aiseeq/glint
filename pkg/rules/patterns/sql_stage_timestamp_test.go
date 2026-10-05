package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const stageRepo = `package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"example.com/rulestest/db"
)

type Status string

const (
	StatusPending   Status = "PENDING"
	StatusConfirmed Status = "CONFIRMED"
	StatusCompleted Status = "COMPLETED"
	StatusFailed    Status = "FAILED"
)

// EventUpdated is not a status: updated_at is not a stage.
const EventUpdated = "updated"

type Repo struct{ pool *db.Pool }

func (r *Repo) UpdateStatus(ctx context.Context, id int64, status Status) error {
	_, err := r.pool.Exec(ctx, "UPDATE transfers SET status = $1, version = version + 1 WHERE id = $2", string(status), id) // want status-write-skips-stage-timestamp
	return err
}

func (r *Repo) MarkFailed(ctx context.Context, id int64, status Status, code string) error {
	query := "UPDATE transfers SET status = $1, error_code = $2 WHERE id = $3"
	_, err := r.pool.Exec(ctx, query, string(status), code, id)
	return err
}

func (r *Repo) UpdateFromWebhook(ctx context.Context, id int64, status Status, completedAt *time.Time) error {
	_, err := r.pool.Exec(ctx, ` + "`" + `UPDATE transfers
		SET status = $1,
			completed_at = $2, -- want terminal-timestamp-overwritten-on-later-update
			updated_at = $4
		WHERE id = $3` + "`" + `, string(status), completedAt, id, time.Now())
	return err
}

func (r *Repo) ApplyPollResult(ctx context.Context, id int64, status Status, completedAt *time.Time) error {
	_, err := r.pool.Exec(ctx, ` + "`" + `UPDATE transfers
		SET status = $1, completed_at = COALESCE(completed_at, $2)
		WHERE id = $3` + "`" + `, string(status), completedAt, id)
	return err
}

func (r *Repo) Confirm(ctx context.Context, id int64) error {
	_, err := r.pool.Exec(ctx, "UPDATE transfers SET status = 'CONFIRMED', confirmed_at = NOW() WHERE id = $1", id)
	return err
}

func (r *Repo) ConfirmBulk(ctx context.Context, ids []int64) error {
	_, err := r.pool.Exec(ctx, "UPDATE transfers SET status = 'CONFIRMED' WHERE id = ANY($1)", ids) // want status-write-skips-stage-timestamp
	return err
}

func (r *Repo) Cancel(ctx context.Context, id int64) error {
	_, err := r.pool.Exec(ctx, "UPDATE transfers SET status = 'CANCELLED' WHERE id = $1", id)
	return err
}

func (r *Repo) ListStuck(ctx context.Context, before time.Time) error {
	_, err := r.pool.Exec(ctx, ` + "`" + `SELECT id FROM transfers
		WHERE status = 'CONFIRMED'
			AND confirmed_at < $1 -- want status-write-skips-stage-timestamp
		ORDER BY confirmed_at` + "`" + `, before)
	return err
}

func (r *Repo) Finish(ctx context.Context, id int64, status Status) error {
	query := "UPDATE transfers SET status = $1, updated_at = NOW()"
	if status == StatusCompleted {
		query += ", completed_at = NOW()"
	}
	query += " WHERE id = $2"
	_, err := r.pool.Exec(ctx, query, string(status), id)
	return err
}

func (r *Repo) Edit(ctx context.Context, id int64, columns []string) error {
	var b strings.Builder
	b.WriteString("UPDATE transfers SET status = 'COMPLETED', version = version + 1")
	for i, column := range columns {
		fmt.Fprintf(&b, ", %s = $%d", column, i+1)
	}
	_, err := r.pool.Exec(ctx, b.String(), id)
	return err
}

func (r *Repo) Recent(ctx context.Context, since time.Time) error {
	_, err := r.pool.Exec(ctx, "SELECT id FROM transfers WHERE status = 'PENDING' AND created_at > $1", since)
	return err
}
`

const stageFlow = `package flow

import (
	"context"

	"example.com/rulestest/store"
)

type Flow struct{ repo *store.Repo }

func (f *Flow) Fail(ctx context.Context, id int64) error {
	return f.repo.MarkFailed(ctx, id, store.StatusFailed, "timeout")
}

func (f *Flow) Move(ctx context.Context, id int64, next store.Status) error {
	return f.repo.UpdateStatus(ctx, id, next)
}
`

func stageFiles() map[string]string {
	return map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"db/db.go": `package db

import "context"

type Result struct{}

type Pool struct{}

func (p *Pool) Exec(ctx context.Context, sql string, args ...any) (Result, error) { return Result{}, nil }
`,
		"store/repo.go": stageRepo,
		"flow/flow.go":  stageFlow,
	}
}

// A status written by a path that skips the column another path stamps for
// it leaves the column NULL: the generic status update and the bulk confirm
// are reported, and so is the reconciler reading CONFIRMED rows by
// confirmed_at. A write only ever given another status, one of a status
// with no stamp, and the bookkeeping updated_at are left alone.
func TestStatusWriteSkipsStageTimestamp(t *testing.T) {
	files := stageFiles()
	violations, err := NewStatusWriteSkipsStageTimestampRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "status-write-skips-stage-timestamp"), foundLines(violations))
}

// A webhook write setting completed_at straight from its parameter
// overwrites the completion time on the next event; COALESCE keeps it.
func TestTerminalTimestampOverwrittenOnLaterUpdate(t *testing.T) {
	files := stageFiles()
	violations, err := NewTerminalTimestampOverwrittenRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "terminal-timestamp-overwritten-on-later-update"), foundLines(violations))
}
