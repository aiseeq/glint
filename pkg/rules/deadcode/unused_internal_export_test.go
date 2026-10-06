package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestUnusedInternalExportRule_Metadata(t *testing.T) {
	rule := NewUnusedInternalExportRule()
	assert.Equal(t, "unused-internal-export", rule.Name())
	assert.Equal(t, "deadcode", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

// Репро с ревью projectD 2026-08: в internal/config жила 51 экспортированная
// константа и кластер экспортированных функций, на которые не ссылался никто,
// кроме их собственных тестов. internal/-пакеты не импортируются извне модуля,
// поэтому «нет ссылок в модуле» означает мёртвый код.
func TestUnusedInternalExportRule_Detection(t *testing.T) {
	configSource := `package config

// DefaultUsedLimit используется соседним пакетом
const DefaultUsedLimit = 10

// DefaultDeadLimit не используется никем
const DefaultDeadLimit = 25

// DefaultTestOnlyLimit используется только тестом
const DefaultTestOnlyLimit = 99

// UsedHelper используется соседним пакетом
func UsedHelper() int { return DefaultUsedLimit }

// DeadHelper не используется никем
func DeadHelper() int { return 1 }

// internallyUsed зовёт internalCaller — приватные символы не наша забота
func internallyUsed() int { return 2 }

// InternallyCalled экспортирована, но используется в своём же пакете — жива
func InternallyCalled() int { return internallyUsed() }

func init() { _ = InternallyCalled() }
`
	configTest := `package config

import "testing"

func TestLimits(t *testing.T) {
	if DefaultTestOnlyLimit != 99 {
		t.Fatal("limit changed")
	}
}
`
	userSource := `package user

import "example.com/rulestest/internal/config"

// Limit отдаёт лимит
func Limit() int { return config.UsedHelper() }
`
	project := rulestest.Project(t, map[string]string{
		"go.mod":                         "module example.com/rulestest\n\ngo 1.24\n",
		"internal/config/config.go":      configSource,
		"internal/config/config_test.go": configTest,
		"internal/user/user.go":          userSource,
	})

	violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
	require.NoError(t, err)

	names := make(map[string]string)
	for _, v := range violations {
		symbol, ok := v.Context["symbol"].(string)
		require.True(t, ok, "context symbol must be a string")
		names[symbol] = v.Message
	}

	assert.Contains(t, names, "DefaultDeadLimit", "мёртвая константа должна быть найдена")
	assert.Contains(t, names, "DeadHelper", "мёртвая функция должна быть найдена")
	assert.Contains(t, names, "DefaultTestOnlyLimit", "константа только для тестов — мёртвая в production")
	assert.Contains(t, names["DefaultTestOnlyLimit"], "test", "сообщение должно упоминать test-only использование")

	assert.NotContains(t, names, "DefaultUsedLimit", "используемая константа — не находка")
	assert.NotContains(t, names, "UsedHelper", "используемая функция — не находка")
	assert.NotContains(t, names, "InternallyCalled", "символ, используемый в своём пакете, жив")
	assert.NotContains(t, names, "internallyUsed", "неэкспортированные символы — зона unused-symbol")
}

// Символы вне internal/ могут быть публичным API модуля — правило молчит.
func TestUnusedInternalExportRule_IgnoresPublicPackages(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"pkg/api/api.go": `package api

// PublicUnused может использоваться потребителями модуля
const PublicUnused = 1
`,
	})

	violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// Методы не проверяются: они могут реализовывать интерфейсы.
func TestUnusedInternalExportRule_SkipsMethods(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"internal/svc/svc.go": `package svc

// Service делает работу
type Service struct{}

// UnusedMethod нигде не зовётся, но может закрывать интерфейс
func (s *Service) UnusedMethod() {}

// Use держит тип живым
func Use() *Service { return &Service{} }

func init() { _ = Use() }
`,
	})

	violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// A type that only its own methods mention, and a function that only calls
// itself, are as dead as a constant nobody names: the self-reference is part
// of the declaration, not a use.
func TestUnusedInternalExportRule_IgnoresSelfReferences(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod": "module example.com/projecta\n\ngo 1.24\n",
		"internal/k/k.go": `package k

type Widget struct{ n int }

func (w *Widget) Size() int { return w.n }

func Countdown(n int) int {
	if n == 0 {
		return 0
	}
	return Countdown(n - 1)
}

const Lonely = 1
`,
	})

	violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
	require.NoError(t, err)

	var symbols []string
	for _, v := range violations {
		symbols = append(symbols, v.Context["symbol"].(string))
	}
	assert.ElementsMatch(t, []string{"Widget", "Countdown", "Lonely"}, symbols)
}

// Several constants declared on one line share file and line; their findings
// must still come out in the same order on every run.
func TestUnusedInternalExportRule_StableOrderOnOneLine(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod":          "module example.com/projecta\n\ngo 1.24\n",
		"internal/k/k.go": "package k\n\nconst A, B, C, D, E = 1, 2, 3, 4, 5\n",
	})

	for range 12 {
		violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
		require.NoError(t, err)
		var symbols []string
		for _, v := range violations {
			symbols = append(symbols, v.Context["symbol"].(string))
		}
		require.Equal(t, []string{"A", "B", "C", "D", "E"}, symbols)
	}
}

// An initializer outside internal/ that only tests call: production never
// runs it, and the getters it feeds answer as if it had.
func TestUnusedInternalExportRule_InitializerOnlyTestsCall(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"errors/config.go": `package errors

import "sync"

var (
	once sync.Once
	cfg  map[string]string
)

func InitErrorConfig(c map[string]string) { once.Do(func() { cfg = c }) }

func SetupDefaults() {}

func Message(code string) string { return cfg[code] }

func Format(code string) string { return "[" + code + "]" }
`,
		"errors/config_test.go": `package errors

import "testing"

func TestMessage(t *testing.T) {
	InitErrorConfig(map[string]string{"x": "y"})
	if Message("x") != "y" {
		t.Fatal("message")
	}
	_ = Format("x")
}
`,
		"app/main.go": `package app

import "example.com/rulestest/errors"

func Run() string { return errors.Message("x") }
`,
		"shared/testing/helpers.go": `package testing

func SetupTestConfig() map[string]string { return nil }

func InitStore() {}
`,
		"shared/testing/helpers_test.go": `package testing

import "testing"

func TestHelpers(t *testing.T) {
	_ = SetupTestConfig()
	InitStore()
}
`,
	})
	violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "InitErrorConfig")
	assert.Equal(t, 10, violations[0].Line)
}

// A package whose own files import "testing" exists for tests: production code
// cannot use it, so an export only tests call is its purpose, not dead code.
// An export that only its own package's tests call is still reported.
func TestUnusedInternalExportRule_SkipsTestSupportPackage(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"internal/dbhelp/dbhelp.go": `package dbhelp

import "testing"

// DSN returns the database a test runs against.
func DSN(t testing.TB) string {
	t.Helper()
	return "postgres://localhost/test"
}
`,
		"internal/plain/plain.go": `package plain

// Address is used by its own tests only.
func Address() string { return "localhost" }
`,
		"internal/plain/plain_test.go": `package plain

import "testing"

func TestAddress(t *testing.T) { _ = Address() }
`,
		"internal/store/store_test.go": `package store

import (
	"testing"

	"example.com/rulestest/internal/dbhelp"
)

func TestStore(t *testing.T) {
	_ = dbhelp.DSN(t)
}
`,
		"internal/store/store.go": "package store\n",
	})

	violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var symbols []string
	for _, v := range violations {
		symbols = append(symbols, v.Context["symbol"].(string))
	}
	assert.Equal(t, []string{"Address"}, symbols)
}

// Repro from a real project: a scenario harness in an internal package and the
// writer of a trace format were called only by the tests of other packages.
// A _test.go file of another package cannot import test code, so the export is
// the only place such a helper can live: those tests use it.
func TestUnusedInternalExportRule_OtherPackagesTestsUseExport(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"internal/harness/window.go": `package harness

// RunWindow replays a recorded window for a test.
func RunWindow(dir string) error { return nil }

// RunUnused is called by nobody.
func RunUnused(dir string) error { return nil }
`,
		"internal/trace/trace.go": `package trace

// Read parses a trace.
func Read(path string) ([]string, error) { return nil, nil }

// Write stores a trace; production only reads them.
func Write(path string, lines []string) error { return nil }

// Format is used by the tests of this package only.
func Format(lines []string) string { return "" }
`,
		"internal/trace/trace_test.go": `package trace

import "testing"

func TestFormat(t *testing.T) { _ = Format(nil) }
`,
		"internal/agent/agent.go": `package agent

import "example.com/rulestest/internal/trace"

func Load(path string) ([]string, error) { return trace.Read(path) }
`,
		"internal/agent/agent_test.go": `package agent

import (
	"testing"

	h "example.com/rulestest/internal/harness"
	"example.com/rulestest/internal/trace"
)

func TestLoad(t *testing.T) {
	if err := trace.Write("x", nil); err != nil {
		t.Fatal(err)
	}
	_ = h.RunWindow("x")
}
`,
	})

	violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var symbols []string
	for _, v := range violations {
		symbols = append(symbols, v.Context["symbol"].(string))
	}
	assert.ElementsMatch(t, []string{"RunUnused", "Format", "Load"}, symbols)
}
