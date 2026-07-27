package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeContextFirst(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return NewContextFirstRule().AnalyzeFile(rulestest.GoFile(t, "service.go", source))
}

func TestContextFirstReportsManufacturedContext(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

import "context"

type Service struct{ repo Repo }

type Repo interface {
	Save(ctx context.Context, address string) error
}

func (s *Service) SyncWallet(address string) error {
	ctx := context.Background()
	return s.repo.Save(ctx, address)
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 12, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Service.SyncWallet")
}

// The context handed straight to the call is the same mistake written shorter.
func TestContextFirstReportsInlineBackground(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

import "context"

type Service struct{ repo Repo }

type Repo interface {
	Save(ctx context.Context, address string) error
}

func (s *Service) SyncWallet(address string) error {
	return s.repo.Save(context.TODO(), address)
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 12, violations[0].Line)
}

// A deadline on top of a fresh root is still a fresh root.
func TestContextFirstSeesThroughWithTimeout(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

import (
	"context"
	"time"
)

type Service struct{ repo Repo }

type Repo interface {
	Save(ctx context.Context, address string) error
}

func (s *Service) SyncWallet(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.repo.Save(ctx, address)
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "SyncWallet")
}

// Repro for the false positives that made this rule unusable: a pure function
// has nothing to cancel, whatever its name looks like.
func TestContextFirstIgnoresPureFunctions(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

type Service struct{ wallets []string }

func DetectWalletType(address string) string {
	if address == "" {
		return "unknown"
	}
	return "evm"
}

func (s *Service) WalletCount() int {
	return len(s.wallets)
}

func (s *Service) SyncWallet(address string) error {
	if address == "" {
		return nil
	}
	return nil
}
`)

	assert.Empty(t, violations)
}

// A function that already accepts a context is context-background's business.
func TestContextFirstIgnoresFunctionWithContextParam(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

import "context"

type Service struct{ repo Repo }

type Repo interface {
	Save(ctx context.Context, address string) error
}

func (s *Service) SyncWallet(ctx context.Context, address string) error {
	return s.repo.Save(context.Background(), address)
}
`)

	assert.Empty(t, violations)
}

// An entry point has to build the root context somewhere.
func TestContextFirstIgnoresEntryPoints(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

import "context"

type Repo interface {
	Save(ctx context.Context, address string) error
}

var repo Repo

func main() {
	_ = repo.Save(context.Background(), "addr")
}

func init() {
	_ = repo.Save(context.Background(), "addr")
}
`)

	assert.Empty(t, violations)
}

// A goroutine outliving the call cannot inherit the caller's context.
func TestContextFirstIgnoresBackgroundGoroutine(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

import "context"

type Service struct{ repo Repo }

type Repo interface {
	Save(ctx context.Context, address string) error
}

func (s *Service) StartWorker() {
	go func() {
		_ = s.repo.Save(context.Background(), "addr")
	}()
}
`)

	assert.Empty(t, violations)
}

// A context created and never passed anywhere cancels nothing downstream.
func TestContextFirstIgnoresUnusedContext(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

import "context"

func Placeholder() bool {
	ctx := context.Background()
	return ctx != nil
}
`)

	assert.Empty(t, violations)
}

// Repro from saga: a scheduler started here and stopped elsewhere keeps its own
// context, because the call that starts it does not own its lifetime.
func TestContextFirstIgnoresLongLivedServiceContext(t *testing.T) {
	violations := analyzeContextFirst(t, `package service

import "context"

type Scheduler interface {
	Run(ctx context.Context)
}

type Factory struct {
	scheduler Scheduler
	cancel    context.CancelFunc
}

func (f *Factory) StartScheduler() {
	schedulerCtx, schedulerCancel := context.WithCancel(context.Background())
	f.cancel = schedulerCancel
	f.scheduler.Run(schedulerCtx)
}
`)

	assert.Empty(t, violations)
}

// Repro from saga: graceful shutdown in package main builds its own timeout
// context because the context above it is already cancelled.
func TestContextFirstIgnoresPackageMain(t *testing.T) {
	violations := NewContextFirstRule().AnalyzeFile(rulestest.GoFile(t, "main.go", `package main

import (
	"context"
	"time"
)

type Server interface {
	Shutdown(ctx context.Context) error
}

func handleGracefulShutdown(server Server) error {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	return server.Shutdown(shutdownCtx)
}
`))

	assert.Empty(t, violations)
}

func TestContextFirstMetadata(t *testing.T) {
	rule := NewContextFirstRule()
	assert.Equal(t, "context-first", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}
