package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The value of a failed call replaced after a log line: a zero, a literal, a
// zero constructor, a field of another value, a no-op object. The caller sees
// a plausible result and never learns the call failed.
func TestFallbackReturn_LoggedFallbackOfFailedResult(t *testing.T) {
	const source = `package svc

import (
	"fmt"
	"os"
)

type Decimal struct{ v int64 }

func ZeroDecimal() Decimal { return Decimal{} }

type Investment struct{ Amount Decimal }

type Logger interface{ Warn(msg string, args ...any); Error(msg string, args ...any) }

type Svc struct {
	logger Logger
	repo   interface {
		Count() (int, error)
		Total() (Decimal, error)
		Value(inv Investment) (Decimal, error)
		Transfers() (Decimal, error)
		Active() (bool, error)
	}
}

func (s *Svc) Stats(inv Investment) (int, Decimal, Decimal, Decimal, bool) {
	count, err := s.repo.Count()
	if err != nil {
		s.logger.Warn("count failed", "error", err)
		count = 0
	}
	total, err := s.repo.Total()
	if err != nil {
		s.logger.Warn("total failed", "error", err)
		total = ZeroDecimal()
	}
	value, err := s.repo.Value(inv)
	if err != nil {
		s.logger.Error("value failed")
		value = inv.Amount
	}
	transfers, err := s.repo.Transfers()
	if err != nil {
		s.logger.Warn(fmt.Sprintf("transfers failed, using zero: %v", err))
		transfers = Decimal{}
	}
	active, err := s.repo.Active()
	if err != nil {
		fmt.Fprintf(os.Stderr, "status unknown: %v\n", err)
		active = true
	}
	return count, total, value, transfers, active
}
`
	assert.Equal(t, []int{31, 36, 41, 46, 51}, fallbackReturnLines(t, source))
}

// A chain of fallbacks: the results of other calls are a failover, the no-op
// object at its end is a fallback, however deep in the branch it sits.
func TestFallbackReturn_FailoverChainEndingInNoOp(t *testing.T) {
	const source = `package svc

import (
	"fmt"
	"os"
)

type Log struct{}

func NewNop() *Log { return &Log{} }

func build(level int) (*Log, error) { return &Log{}, nil }

func Logger() *Log {
	log, err := build(0)
	if err != nil {
		backup, backupErr := build(1)
		if backupErr != nil {
			if basic, basicErr := build(2); basicErr == nil {
				log = basic
			} else {
				fmt.Fprintf(os.Stderr, "all loggers failed: %v %v %v\n", err, backupErr, basicErr)
				log = NewNop()
			}
		} else {
			log = backup
		}
	}
	return log
}
`
	assert.Equal(t, []int{23}, fallbackReturnLines(t, source))
}

// What a failed call may legitimately turn into: the result of another call,
// a report that carries the error, a retry.
func TestFallbackReturn_FailoverReportAndRetryAreNotFallbacks(t *testing.T) {
	const source = `package svc

type Logger interface{ Warn(msg string, args ...any) }

type Result struct {
	Value   int
	Message string
}

type Svc struct {
	logger  Logger
	primary func() (int, error)
	replica func() (int, error)
}

func (s *Svc) Read() int {
	v, err := s.primary()
	if err != nil {
		s.logger.Warn("primary failed, reading the replica", "error", err)
		v, _ = s.replica()
	}
	return v
}

func (s *Svc) Report() Result {
	var res Result
	v, err := s.primary()
	if err != nil {
		res.Message = err.Error()
		v = 0
	}
	res.Value = v
	return res
}

func (s *Svc) Retry() int {
	v, err := s.primary()
	if err != nil {
		s.logger.Warn("retrying", "error", err)
		v, err = s.primary()
	}
	if err != nil {
		return -1
	}
	return v
}
`
	assert.Empty(t, fallbackReturnLines(t, source))
}

// A comment that explains the fallback counts anywhere in the branch, above
// a multi-line log call too, in English or Russian.
func TestFallbackReturn_BranchCommentExplainsFallback(t *testing.T) {
	const source = `package svc

import "log/slog"

type Svc struct{ load func() ([]byte, error) }

func (s *Svc) Props() []byte {
	props, err := s.load()
	if err != nil {
		// best effort: analytics must not fail on malformed properties
		slog.Warn("marshal failed, storing an empty object",
			slog.String("kind", "props"),
			slog.String("error", err.Error()))
		props = []byte("{}")
	}
	return props
}

func (s *Svc) Payouts() []byte {
	payouts, err := s.load()
	if err != nil {
		// Явный failover: без выплат матчинг идёт по номиналам, о деградации говорит лог.
		slog.Error("payouts failed", slog.Any("error", err))
		payouts = nil
	}
	return payouts
}
`
	assert.Empty(t, fallbackReturnLines(t, source))
}

// A comment right above the call that explains the degradation counts like
// one in the branch: the reason is written where the call is made.
func TestFallbackReturn_CallCommentExplainsDegradation(t *testing.T) {
	const source = `package svc

import "log/slog"

type Manager struct{}

type Svc struct{ logger *slog.Logger }

func newManager() (*Manager, error) { return &Manager{}, nil }

func (s *Svc) Start() *Manager {
	// Без справочника демон работает как раньше, только по новостям
	manager, err := newManager()
	if err != nil {
		s.logger.Warn("filings disabled", "error", err)
	}
	return manager
}

func (s *Svc) Ancestors(load func() ([]int, error)) []int {
	// An incomplete chain still works: the window may belong to the part we have
	chain, err := load()
	if err != nil {
		s.logger.Warn("ancestry incomplete", "error", err)
	}
	return chain
}

func (s *Svc) Count(load func() (int, error)) int {
	// Получаем количество активных адресов
	count, err := load()
	if err != nil {
		s.logger.Warn("count failed", "error", err)
	}
	return count
}
`
	assert.Equal(t, []int{32}, fallbackReturnLines(t, source))
}
