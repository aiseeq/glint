package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

type goProjectRule interface {
	AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
}

func projectRuleLines(t *testing.T, rule goProjectRule, files map[string]string) []string {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return foundLines(violations)
}

// A sync service built and handed to a handler, never started: the
// background sync it exists for never runs.
func TestServiceNeverStarted(t *testing.T) {
	files := map[string]string{
		"worker/sync.go": `package worker

import (
	"context"
	"time"
)

type SyncService struct{ interval time.Duration }

func NewSyncService() *SyncService { return &SyncService{interval: time.Minute} }

func (s *SyncService) Start(ctx context.Context) error {
	go s.loop(ctx)
	return nil
}

func (s *SyncService) loop(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *SyncService) SyncNow() {}

type Poller struct{}

func NewPoller() *Poller { return &Poller{} }

func (p *Poller) Start(ctx context.Context) {
	go func() { <-ctx.Done() }()
}

type Job struct{}

func (j *Job) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		return nil
	}
	return ctx.Err()
}

type Runner interface{ Run(ctx context.Context) error }

func RunAll(ctx context.Context, rs []Runner) {
	for _, r := range rs {
		_ = r.Run(ctx)
	}
}

type Unbuilt struct{}

func (Unbuilt) Start() { go func() {}() }
`,
		"cmd/app/main.go": `package main

import (
	"context"

	"example.com/rulestest/worker"
)

func main() {
	ctx := context.Background()
	s := worker.NewSyncService()
	s.SyncNow()
	worker.NewPoller().Start(ctx)
	worker.RunAll(ctx, []worker.Runner{&worker.Job{}})
}
`,
	}
	assert.Equal(t, []string{"worker/sync.go:12"}, projectRuleLines(t, NewServiceNeverStartedRule(), files))
}

const slogLoggerNoDefault = `package logging

import (
	"io"
	"log/slog"
)

func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, nil))
}
`

// The configured logger is built, slog.Default is not set to it: the
// package-level slog calls write to the standard text handler instead.
func TestSlogDefaultNotSet(t *testing.T) {
	files := map[string]string{
		"logging/logger.go": slogLoggerNoDefault,
		"mail/send.go": `package mail

import "log/slog"

func Send(to string) {
	slog.Info("sent", "to", to)
}
`,
	}
	assert.Equal(t, []string{"logging/logger.go:9"}, projectRuleLines(t, NewSlogDefaultNotSetRule(), files))

	files["logging/logger.go"] = `package logging

import (
	"io"
	"log/slog"
)

func New(w io.Writer) *slog.Logger {
	logger := slog.New(slog.NewJSONHandler(w, nil))
	slog.SetDefault(logger)
	return logger
}
`
	assert.Empty(t, projectRuleLines(t, NewSlogDefaultNotSetRule(), files))

	delete(files, "mail/send.go")
	files["logging/logger.go"] = slogLoggerNoDefault
	assert.Empty(t, projectRuleLines(t, NewSlogDefaultNotSetRule(), files), "nothing logs through the default")
}

// Close waits for the goroutines the WaitGroup counts; a flush started
// without it is cut off when the service closes, and its events are lost.
func TestGoroutineUntrackedOnClose(t *testing.T) {
	files := map[string]string{
		"events/service.go": `package events

import "sync"

type Service struct {
	mu    sync.Mutex
	queue []string
	wg    sync.WaitGroup
	done  chan struct{}
}

func New() *Service {
	s := &Service{done: make(chan struct{})}
	s.wg.Add(1)
	go s.flusher()
	return s
}

func (s *Service) flusher() {
	defer s.wg.Done()
	<-s.done
}

func (s *Service) Enqueue(e string) {
	s.mu.Lock()
	s.queue = append(s.queue, e)
	full := len(s.queue) > 10
	s.mu.Unlock()
	if full {
		go s.flush()
	}
}

func (s *Service) EnqueueTracked(e string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.flush()
	}()
}

func (s *Service) Restart() {
	s.wg.Add(1)
	go s.flusher()
}

func (s *Service) flush() {}

func (s *Service) Close() {
	close(s.done)
	s.wg.Wait()
	s.flush()
}

type Fanout struct{ wg sync.WaitGroup }

func (f *Fanout) Go(work func()) { go work() }
`,
	}
	assert.Equal(t, []string{"events/service.go:30"}, projectRuleLines(t, NewGoroutineUntrackedOnCloseRule(), files))
}

// A package default swapped for one call and put back: two calls at once
// see each other's value.
func TestGlobalSwapRestore(t *testing.T) {
	files := map[string]string{
		"limits/check.go": `package limits

type Limits struct{ Max int }

func Check(n int) bool { return n <= defaultLimits.Max }

type Validator struct{ limits Limits }

func (v *Validator) CheckWith(n int) bool {
	old := defaultLimits
	defaultLimits = v.limits
	ok := Check(n)
	defaultLimits = old
	return ok
}

func (v *Validator) CheckDeferred(n int) bool {
	old := defaultLimits
	defer func() { defaultLimits = old }()
	defaultLimits = v.limits
	return Check(n)
}

func Local() int {
	x := 1
	old := x
	x = 2
	x = old
	return x
}

func SetDefault(l Limits) { defaultLimits = l }
`,
		"limits/defaults.go": `package limits

var defaultLimits Limits
`,
	}
	assert.Equal(t, []string{"limits/check.go:11", "limits/check.go:20"}, projectRuleLines(t, NewGlobalSwapRestoreRule(), files))
}
