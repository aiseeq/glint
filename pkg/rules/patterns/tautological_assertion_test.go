package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTautologicalAssertionRule_Metadata(t *testing.T) {
	rule := NewTautologicalAssertionRule()

	assert.Equal(t, "tautological-assertion", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestTautologicalAssertionRule_Go(t *testing.T) {
	rule := NewTautologicalAssertionRule()

	tests := []struct {
		name        string
		code        string
		expectKind  string
		expectMatch bool
	}{
		{
			name: "значение сравнивается само с собой",
			code: `package service

func TestBalances(t *testing.T) {
	portfolio := readBalance()
	require.Equal(t, portfolio, portfolio)
}
`,
			expectMatch: true,
			expectKind:  "self_comparison",
		},
		{
			name: "обе стороны получены одинаковым выражением",
			code: `package service

func TestBalances(t *testing.T) {
	assert.Equal(t, res.DisplayedBalance, res.DisplayedBalance)
}
`,
			expectMatch: true,
			expectKind:  "self_comparison",
		},
		{
			name: "утверждается константа",
			code: `package service

func TestPlaceholder(t *testing.T) {
	require.True(t, true)
}
`,
			expectMatch: true,
			expectKind:  "constant_assertion",
		},
		{
			name: "нормальное сравнение с ожидаемым значением",
			code: `package service

func TestBalances(t *testing.T) {
	require.Equal(t, "1495.48", readBalance())
}
`,
			expectMatch: false,
		},
		{
			name: "проверка вычисленного булева значения",
			code: `package service

func TestBalances(t *testing.T) {
	require.True(t, reconciles(snapshot, delta))
}
`,
			expectMatch: false,
		},
		{
			// Разные поля одного объекта — законное сравнение двух величин.
			name: "разные поля не считаются тавтологией",
			code: `package service

func TestBalances(t *testing.T) {
	require.Equal(t, res.TotalValue, res.AvailableBalance)
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createPatternContext(t, "service_test.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "ожидалась находка: %s", tt.name)
				assert.Equal(t, "tautological_assertion", violations[0].Context["pattern"])
				assert.Equal(t, tt.expectKind, violations[0].Context["kind"])
			} else {
				assert.Empty(t, violations, "находок быть не должно: %s", tt.name)
			}
		})
	}
}

func TestTautologicalAssertionRule_TypeScript(t *testing.T) {
	rule := NewTautologicalAssertionRule()

	tests := []struct {
		name        string
		code        string
		expectKind  string
		expectMatch bool
	}{
		{
			// Репро с ProjectA: регресс «в связке» сравнивал displayedBalance сам с собой и
			// оставался зелёным, пока экраны расходились.
			name: "значение сравнивается само с собой",
			code: `it('в связке', () => {
  const portfolio = parseFloat(res.displayedBalance)
  const withdrawal = parseFloat(res.displayedBalance)
  expect(withdrawal).toBe(portfolio)
})
`,
			expectMatch: true,
			expectKind:  "self_comparison",
		},
		{
			// Два вызова боевой функции — это может быть законная проверка идемпотентности.
			name: "два вызова одной функции не считаются тавтологией",
			code: `it('кэш отдаёт то же значение', () => {
  const first = cache.get('k')
  const second = cache.get('k')
  expect(second).toBe(first)
})
`,
			expectMatch: false,
		},
		{
			name: "буквально одно и то же выражение",
			code: `it('в связке', () => {
  expect(res.displayedBalance).toBe(res.displayedBalance)
})
`,
			expectMatch: true,
			expectKind:  "self_comparison",
		},
		{
			name: "заглушка на константе",
			code: `it('заглушка', () => {
  expect(true).toBe(true)
})
`,
			expectMatch: true,
			expectKind:  "constant_assertion",
		},
		{
			// Репро с ProjectA: SLA-тест пропускал сам себя, когда метрика была нулевой.
			name: "проверка пропускает сама себя",
			code: `it('availability', () => {
  if (data.availability > 0) {
    expect(data.availability).toBeGreaterThan(95)
  }
})
`,
			expectMatch: true,
			expectKind:  "self_skipping",
		},
		{
			name: "условие по другой величине — законная ветка",
			code: `it('availability', () => {
  if (isProduction) {
    expect(availability).toBeGreaterThan(99)
  }
})
`,
			expectMatch: false,
		},
		{
			name: "у ветки есть else — второй случай тоже проверяется",
			code: `it('availability', () => {
  if (availability > 0) {
    expect(availability).toBeGreaterThan(95)
  } else {
    expect(availability).toBe(0)
  }
})
`,
			expectMatch: false,
		},
		{
			name: "обычная проверка результата",
			code: `it('баланс', () => {
  expect(readBalance()).toBe('1495.48')
})
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTSContext("dashboard.test.ts", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "ожидалась находка: %s", tt.name)
				assert.Equal(t, tt.expectKind, violations[0].Context["kind"])
			} else {
				assert.Empty(t, violations, "находок быть не должно: %s", tt.name)
			}
		})
	}
}

// Боевой код правило не смотрит: утверждение вне теста — не утверждение.
func TestTautologicalAssertionRule_SkipsProductionCode(t *testing.T) {
	rule := NewTautologicalAssertionRule()
	ctx := createTSContext("dashboard.ts", "expect(true).toBe(true)\n")
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func createTSContext(path, code string) *core.FileContext {
	return &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}
}
