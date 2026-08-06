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

// Репро с ревью ipop 2026-08: в internal/config жила 51 экспортированная
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
