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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBalances(t *testing.T) {
	require.Equal(t, "1495.48", readBalance())
}
`,
			expectMatch: false,
		},
		{
			name: "проверка вычисленного булева значения",
			code: `package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBalances(t *testing.T) {
	require.Equal(t, res.TotalValue, res.AvailableBalance)
}
`,
			expectMatch: false,
		},
	}

	tests = append(tests, []struct {
		name        string
		code        string
		expectKind  string
		expectMatch bool
	}{
		{
			// testify always takes the testing handle first, whatever expression supplies it.
			name: "константа при t из suite",
			code: `package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSuiteLiteral(t *testing.T) {
	s := suiteT{t}
	assert.True(s.T(), true)
}
`,
			expectMatch: true,
			expectKind:  "constant_assertion",
		},
		{
			// Два вызова — проверка детерминизма, а не сравнение значения с собой.
			name: "два одинаковых вызова не тавтология",
			code: `package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeterministic(t *testing.T) {
	assert.Equal(t, Add(1, 2), Add(1, 2))
}
`,
			expectMatch: false,
		},
		{
			name: "локальная переменная assert — не testify",
			code: `package service

import "testing"

func TestLocal(t *testing.T) {
	assert := newChecker(t)
	assert.Equal(t, x, x)
}
`,
			expectMatch: false,
		},
		{
			name: "testify под алиасом",
			code: `package service

import (
	"testing"

	req "github.com/stretchr/testify/require"
)

func TestAliased(t *testing.T) {
	req.True(t, true)
}
`,
			expectMatch: true,
			expectKind:  "constant_assertion",
		},
	}...)

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

	tests = append(tests, []struct {
		name        string
		code        string
		expectKind  string
		expectMatch bool
	}{
		{
			// Имена из соседних тестов — разные значения: область видимости — сам тест.
			name: "переменные из разных тестов не сравниваются",
			code: `test('a', () => {
  const left = obj.value
  expect(left).toBe(1)
})

test('b', () => {
  const right = obj.value
  expect(right).toBe(1)
})

test('c', () => {
  const left = compute()
  const right = other()
  expect(left).toBe(right)
})
`,
			expectMatch: false,
		},
		{
			name: "переприсвоенная не чистым чтением переменная не тавтология",
			code: `it('c', () => {
  let left = obj.value
  const right = obj.value
  left = recompute(left)
  expect(left).toBe(right)
})
`,
			expectMatch: false,
		},
		{
			name: "if без скобок с throw — проверка ниже безусловная",
			code: `it('guard throws, assertion is unconditional', () => {
  const count = getCount()
  if (count > 5) throw new Error('too many')
  expect(count).toBe(3)
})

it('next', () => {
  expect(compute()).toBe(2)
})
`,
			expectMatch: false,
		},
		{
			// Реальный случай из комментария к правилу — однострочная ветка без скобок.
			name: "проверка в однострочной ветке пропускает сама себя",
			code: `it('availability', () => {
  if (availability > 0) expect(availability).toBeGreaterThan(95)
})
`,
			expectMatch: true,
			expectKind:  "self_skipping",
		},
		{
			name: "однострочная ветка с else на следующей строке",
			code: `it('availability', () => {
  if (availability > 0) expect(availability).toBeGreaterThan(95)
  else expect(availability).toBe(0)
})
`,
			expectMatch: false,
		},
		{
			name: "два одинаковых вызова не тавтология",
			code: `it('детерминизм', () => {
  expect(compute(1)).toBe(compute(1))
})
`,
			expectMatch: false,
		},
		{
			name: "проверка в комментарии не код",
			code: `it('x', () => {
  // expect(true).toBe(true)
  /* expect(a.b).toBe(a.b) */
  expect(readBalance()).toBe('1')
})
`,
			expectMatch: false,
		},
	}...)

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
