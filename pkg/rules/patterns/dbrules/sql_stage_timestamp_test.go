package dbrules

import (
	"go/ast"
	"go/types"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStagePrechecksFollowBoundQueryArguments(t *testing.T) {
	statusProject := rulestest.Project(t, map[string]string{"store.go": `package sample
import "context"
type Repo struct{}
func (r *Repo) exec(context.Context, string, ...any) int { return 0 }
func (r *Repo) ConfirmPair(ctx context.Context, a, b int64) int {
	return r.exec(ctx, "UPDATE transfers SET status = 'CONFIRMED', confirmed_at = NOW() WHERE id = $1", a) +
		r.exec(ctx, "UPDATE transfers SET status = 'CONFIRMED' WHERE id = $1", b)
}
`})
	statusDecls, err := patternkit.FuncDeclsByObject(statusProject)
	require.NoError(t, err)
	status := NewStatusWriteSkipsStageTimestampRule()
	assert.True(t, status.ProjectPrecheck(statusDecls))
	violations, err := status.AnalyzeGoProject(statusProject)
	require.NoError(t, err)
	require.Len(t, violations, 1)

	terminalProject := rulestest.Project(t, map[string]string{"store.go": `package sample
import (
	"context"
	"time"
)
type Repo struct{}
type Status string
const StatusCompleted Status = "COMPLETED"
func (r *Repo) exec(context.Context, string, ...any) int { return 0 }
func (r *Repo) ApplyWebhookEvent(ctx context.Context, id int64, status Status, at *time.Time) int {
	return 0 + r.exec(ctx, "UPDATE transfers SET status = $1, completed_at = $2 WHERE id = $3", status, at, id)
}
`})
	terminalDecls, err := patternkit.FuncDeclsByObject(terminalProject)
	require.NoError(t, err)
	terminal := NewTerminalTimestampOverwrittenRule()
	assert.True(t, terminal.ProjectPrecheck(terminalDecls))
	violations, err = terminal.AnalyzeGoProject(terminalProject)
	require.NoError(t, err)
	require.Len(t, violations, 1)
}

func TestStageLiteralUpdatesUsesBareFallback(t *testing.T) {
	updates := stageLiteralUpdates(patternkit.SqlLiteral{
		Text: "not valid SQL",
		Bare: "UPDATE records SET status = 'DONE'",
	})
	require.Len(t, updates, 1)
	_, ok := updates[0].Assignment("status")
	assert.True(t, ok)
}

func TestStageRulesProjectPrechecks(t *testing.T) {
	project := rulestest.Project(t, map[string]string{"store.go": `package sample
func read() { _ = "SELECT 1" }
`})
	decls, err := patternkit.FuncDeclsByObject(project)
	require.NoError(t, err)
	status := NewStatusWriteSkipsStageTimestampRule()
	terminal := NewTerminalTimestampOverwrittenRule()
	statusAnalysisCalled, terminalAnalysisCalled := false, false
	statusProjectAnalysis := status.ForProject
	status.ForProject = func(decls map[*types.Func]patternkit.TypedFuncDecl) func(patternkit.FuncScope, *ast.FuncDecl) []patternkit.FuncFinding {
		statusAnalysisCalled = true
		return statusProjectAnalysis(decls)
	}
	terminalProjectAnalysis := terminal.ForProject
	terminal.ForProject = func(decls map[*types.Func]patternkit.TypedFuncDecl) func(patternkit.FuncScope, *ast.FuncDecl) []patternkit.FuncFinding {
		terminalAnalysisCalled = true
		return terminalProjectAnalysis(decls)
	}
	assert.False(t, status.ProjectPrecheck(decls))
	assert.False(t, terminal.ProjectPrecheck(decls))
	violations, err := status.AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
	assert.False(t, statusAnalysisCalled, "ранний выход должен пропустить проектный индекс")
	violations, err = terminal.AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
	assert.False(t, terminalAnalysisCalled, "ранний выход должен пропустить проектный индекс")

	statusOnly := rulestest.Project(t, map[string]string{"store.go": `package sample
import "context"
func exec(context.Context, string) {}
func update(ctx context.Context) { exec(ctx, "UPDATE records SET status = 'done'"); exec(ctx, "UPDATE records SET finished_at = NOW()") }
`})
	statusDecls, err := patternkit.FuncDeclsByObject(statusOnly)
	require.NoError(t, err)
	assert.True(t, status.ProjectPrecheck(statusDecls))
	assert.True(t, terminal.ProjectPrecheck(statusDecls))

	statusNotAssigned := rulestest.Project(t, map[string]string{"store.go": `package sample
import "context"
func exec(context.Context, string) {}
func update(ctx context.Context) { exec(ctx, "UPDATE records SET note = 'done' WHERE status = 'done'") }
`})
	statusNotAssignedDecls, err := patternkit.FuncDeclsByObject(statusNotAssigned)
	require.NoError(t, err)
	assert.False(t, status.ProjectPrecheck(statusNotAssignedDecls))

	statusWithoutTimestamp := rulestest.Project(t, map[string]string{"store.go": `package sample
import "context"
func exec(context.Context, string) {}
func update(ctx context.Context) { exec(ctx, "UPDATE records SET status = 'done'") }
`})
	statusWithoutTimestampDecls, err := patternkit.FuncDeclsByObject(statusWithoutTimestamp)
	require.NoError(t, err)
	assert.True(t, status.ProjectPrecheck(statusWithoutTimestampDecls))
	assert.False(t, terminal.ProjectPrecheck(statusWithoutTimestampDecls))

	timestampPredicateOnly := rulestest.Project(t, map[string]string{"store.go": `package sample
import "context"
func exec(context.Context, string) {}
func update(ctx context.Context) { exec(ctx, "UPDATE records SET status = 'done' WHERE finished_at IS NULL") }
`})
	predicateDecls, err := patternkit.FuncDeclsByObject(timestampPredicateOnly)
	require.NoError(t, err)
	assert.False(t, terminal.ProjectPrecheck(predicateDecls))

	timestampOnly := rulestest.Project(t, map[string]string{"store.go": `package sample
import "context"
func exec(context.Context, string) {}
func update(ctx context.Context) { exec(ctx, "UPDATE records SET finished_at = NOW()") }
`})
	timestampDecls, err := patternkit.FuncDeclsByObject(timestampOnly)
	require.NoError(t, err)
	assert.False(t, status.ProjectPrecheck(timestampDecls))
	assert.True(t, terminal.ProjectPrecheck(timestampDecls))
}

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

func (r *Repo) UpdateFromProviderEvent(ctx context.Context, id int64, status Status, completedAt *time.Time) error {
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
	assert.Equal(t, patterntest.WantedLines(files, "status-write-skips-stage-timestamp"), patterntest.FoundLines(violations))
}

// A webhook write setting completed_at straight from its parameter
// overwrites the completion time on the next event; COALESCE keeps it.
func TestTerminalTimestampOverwrittenOnLaterUpdate(t *testing.T) {
	files := stageFiles()
	violations, err := NewTerminalTimestampOverwrittenRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "terminal-timestamp-overwritten-on-later-update"), patterntest.FoundLines(violations))
}
