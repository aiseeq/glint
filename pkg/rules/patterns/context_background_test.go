package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestContextBackgroundRule(t *testing.T) {
	rule := NewContextBackgroundRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "context.Background in func with ctx param",
			code: `package main
import "context"
func foo(ctx context.Context) {
	newCtx := context.Background()
	_ = newCtx
}`,
			expectedCount: 1,
		},
		{
			name: "context.TODO in func with ctx param",
			code: `package main
import "context"
func foo(ctx context.Context) {
	newCtx := context.TODO()
	_ = newCtx
}`,
			expectedCount: 1,
		},
		{
			name: "context.Background in func without ctx - OK",
			code: `package main
import "context"
func foo() {
	ctx := context.Background()
	_ = ctx
}`,
			expectedCount: 0,
		},
		{
			name: "Using ctx param - OK",
			code: `package main
import "context"
func foo(ctx context.Context) {
	doSomething(ctx)
}
func doSomething(ctx context.Context) {}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.InMemoryGoFile(t, "/src/file.go", "/src", tt.code, core.DefaultConfig())

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

// Repro: the standard graceful shutdown waits for ctx to end and then needs a
// fresh context — the cancelled ctx would abort Shutdown at once. Advising
// "use ctx" there breaks the shutdown.
func TestContextBackgroundRuleShutdownAfterDone(t *testing.T) {
	violations := runRuleOnFiles(t, NewContextBackgroundRule(), map[string]string{"server/run.go": `package server

import (
	"context"
	"net/http"
	"time"
)

func Run(ctx context.Context, srv *http.Server) error {
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func RunSelect(ctx context.Context, srv *http.Server, errs <-chan error) error {
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
`})
	assert.Empty(t, violations)
}

func TestContextBackgroundRuleTypedParams(t *testing.T) {
	violations := runRuleOnFiles(t, NewContextBackgroundRule(), map[string]string{"svc/svc.go": `package svc

import stdctx "context"

func work(ctx stdctx.Context) stdctx.Context {
	return stdctx.Background()
}

func discard(_ stdctx.Context) stdctx.Context {
	return stdctx.Background()
}

func before(ctx stdctx.Context) stdctx.Context {
	fresh := stdctx.Background()
	<-ctx.Done()
	return fresh
}
`})
	assert.Len(t, violations, 2)
}

func TestContextBackgroundRuleSkipsTestFiles(t *testing.T) {
	code := `package svc

import "context"

func helper(ctx context.Context) context.Context {
	return context.Background()
}
`
	assert.Empty(t, NewContextBackgroundRule().AnalyzeFile(rulestest.GoFile(t, "svc/svc_test.go", code)))
}

func TestContextBackgroundRuleNoAST(t *testing.T) {
	rule := NewContextBackgroundRule()

	ctx := core.NewFileContext("/src/file.go", "/src", []byte("context.Background()"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

// Repro: WithoutCancel(ctx) in place of Background() keeps the values and
// still drops the caller's cancellation — a read the request waits for runs
// on after the client is gone. Detaching a write that must complete, work
// handed to a goroutine and a context handed back to the caller is the
// function's purpose and stays silent.
func TestContextBackgroundRuleWithoutCancel(t *testing.T) {
	violations := runRuleOnFiles(t, NewContextBackgroundRule(), map[string]string{"svc/balance.go": `package svc

import (
	"context"
	"time"
)

type Repo interface {
	ListTransactions(ctx context.Context, userID string) ([]string, error)
	GetUser(ctx context.Context, userID string) (string, error)
	UpsertRates(ctx context.Context, rates []string) error
}

type Service struct{ repo Repo }

type job struct{ ctx context.Context }

func (s *Service) Load(ctx context.Context, userID string) ([]string, error) {
	sqlCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	return s.repo.ListTransactions(sqlCtx, userID)
}

func (s *Service) User(ctx context.Context, userID string) (string, error) {
	return s.repo.GetUser(context.WithoutCancel(ctx), userID)
}

func (s *Service) Persist(ctx context.Context, rates []string) error {
	return s.repo.UpsertRates(context.WithoutCancel(ctx), rates)
}

func (s *Service) Mixed(ctx context.Context, userID string) error {
	detached := context.WithoutCancel(ctx)
	if _, err := s.repo.GetUser(detached, userID); err != nil {
		return err
	}
	return s.repo.UpsertRates(detached, nil)
}

func (s *Service) Handle(ctx context.Context, userID string) {
	go s.refreshAsync(ctx, userID)
	detached := context.WithoutCancel(ctx)
	go func() { _, _ = s.repo.GetUser(detached, userID) }()
}

func (s *Service) refreshAsync(ctx context.Context, userID string) {
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	_, _ = s.repo.ListTransactions(bg, userID)
}

func (s *Service) Persistence(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
}

func (s *Service) Store(ctx context.Context) *job {
	j := &job{}
	j.ctx = context.WithoutCancel(ctx)
	return j
}
`})
	assert.Equal(t, []string{"svc/balance.go:19", "svc/balance.go:25"}, foundLines(violations))
}
