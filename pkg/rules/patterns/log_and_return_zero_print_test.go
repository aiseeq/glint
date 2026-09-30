package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func logAndReturnZeroLines(t *testing.T, source string) []int {
	t.Helper()
	ctx := rulestest.GoFile(t, "svc/svc.go", source)
	return violationLines(NewLogAndReturnZeroRule().AnalyzeFile(ctx))
}

// An unleveled print that says it reports an error is an error log: the zero
// returned after it is as silent as after logger.Error.
func TestLogAndReturnZero_PrintedErrorBeforeZero(t *testing.T) {
	const source = `package svc

import (
	"fmt"
	"log"
)

type Config struct{ URL, TestURL string }

type Response struct{ Token string }

func (c Config) DatabaseURL() string {
	if c.TestURL != "" {
		return c.TestURL
	}
	log.Printf("CRITICAL CONFIG ERROR: database URL not configured")
	return ""
}

func Register(gen func() (string, error)) *Response {
	addr, err := gen()
	if err != nil {
		fmt.Printf("❌ КРИТИЧЕСКАЯ ОШИБКА генерации адреса: %v\n", err)
		return nil
	}
	return &Response{Token: addr}
}

func Describe(name string) string {
	if name == "" {
		fmt.Printf("describing an unnamed item\n")
		return ""
	}
	return name
}
`
	assert.Equal(t, []int{17, 24}, logAndReturnZeroLines(t, source))
}

// A command function without an error result that logs the failure of its
// write and returns: its caller goes on as if the row had been written. A
// helper recording an audit entry after the action is not a command.
func TestLogAndReturnZero_VoidFunctionSwallowsWriteError(t *testing.T) {
	const source = `package svc

import "context"

type Logger interface{ Error(msg string, args ...any); Info(msg string, args ...any) }

type Repo interface {
	Create(ctx context.Context, v any) error
	Get(ctx context.Context, id string) (any, error)
}

type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (any, error)
}

type Svc struct {
	repo   Repo
	db     DB
	logger Logger
}

func (s *Svc) createTransfer(ctx context.Context, v any) {
	if err := s.repo.Create(ctx, v); err != nil {
		s.logger.Error("failed to create transfer", "error", err)
	} else {
		s.logger.Info("transfer created")
	}
}

func (s *Svc) ProcessDeposit(ctx context.Context, hash string) {
	_, err := s.db.ExecContext(ctx, "UPDATE deposits SET status = 'done' WHERE hash = $1", hash)
	if err != nil {
		s.logger.Error("failed to update deposit", "error", err)
		return
	}
	s.logger.Info("deposit processed")
}

func (s *Svc) warmCache(ctx context.Context, id string) {
	if _, err := s.repo.Get(ctx, id); err != nil {
		s.logger.Error("cache warm-up failed", "error", err)
	}
}

func (s *Svc) recordAudit(ctx context.Context, entry any) {
	if err := s.repo.Create(ctx, entry); err != nil {
		s.logger.Error("audit write failed", "error", err)
	}
}

func (s *Svc) sweep(ctx context.Context, items []any) {
	for _, v := range items {
		if err := s.repo.Create(ctx, v); err != nil {
			s.logger.Error("create failed", "error", err)
			continue
		}
	}
}
`
	assert.Equal(t, []int{23, 32}, logAndReturnZeroLines(t, source))
}
