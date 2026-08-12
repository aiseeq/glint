package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// analyzeEmptyStructReturn парсит Go-исходник и прогоняет по нему правило.
func analyzeEmptyStructReturn(t *testing.T, path, code string) []*core.Violation {
	t.Helper()

	ctx := core.NewFileContext(path, ".", []byte(code), nil)
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ctx.SetGoAST(fset, astFile)

	return NewEmptyStructReturnRule().AnalyzeFile(ctx)
}

func TestEmptyStructReturnRule_Metadata(t *testing.T) {
	rule := NewEmptyStructReturnRule()

	assert.Equal(t, "empty-struct-return", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityCritical, rule.DefaultSeverity())
	assert.True(t, rules.HonorsSuppression(rule))
}

func TestEmptyStructReturnRule(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		code      string
		wantCount int
	}{
		{
			name:     "empty value object with nil error after err check",
			filename: "money/amount.go",
			code: `package money

func Parse(raw string) (Amount, error) {
	v, err := decimal.NewFromString(raw)
	if err != nil {
		return Amount{}, nil
	}
	return Amount{value: v}, nil
}
`,
			wantCount: 1,
		},
		{
			name:     "empty config after nil dependency guard",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load() (Config, error) {
	if l.source == nil {
		return Config{}, nil
	}
	return l.source.Read()
}
`,
			wantCount: 1,
		},
		{
			name:     "empty struct after comma-ok guard",
			filename: "cache/lookup.go",
			code: `package cache

func (c *Cache) Get(key string) (Entry, error) {
	entry, ok := c.items[key]
	if !ok {
		return Entry{}, nil
	}
	return entry, nil
}
`,
			wantCount: 1,
		},
		{
			name:     "qualified type from another package",
			filename: "billing/invoice.go",
			code: `package billing

func Build(id string) (pb.Invoice, error) {
	row, err := load(id)
	if err != nil {
		return pb.Invoice{}, nil
	}
	return convert(row), nil
}
`,
			wantCount: 1,
		},
		{
			name:     "yoda-style nil comparison is still an error guard",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load() (Config, error) {
	if nil == l.source {
		return Config{}, nil
	}
	return l.source.Read()
}
`,
			wantCount: 1,
		},
		{
			name:     "named error variable without nil comparison",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load(raw []byte) (Config, error) {
	parseErr := l.validate(raw)
	if parseErr != errNone {
		return Config{}, nil
	}
	return l.decode(raw)
}
`,
			wantCount: 1,
		},
		{
			name:     "several guards in one function are all reported",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load(path string) (Config, error) {
	if l.source == nil {
		return Config{}, nil
	}
	raw, err := l.source.Read(path)
	if err != nil {
		return Config{}, nil
	}
	return decode(raw)
}
`,
			wantCount: 2,
		},
		{
			name:     "guard in the else branch of an error check",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load(path string) (Config, error) {
	raw, err := l.source.Read(path)
	if err != nil {
		return Config{}, err
	} else {
		if !l.valid(raw) {
			return Config{}, nil
		}
	}
	return decode(raw)
}
`,
			wantCount: 1,
		},
		{
			name:     "error is propagated - correct code",
			filename: "money/amount.go",
			code: `package money

func Parse(raw string) (Amount, error) {
	v, err := decimal.NewFromString(raw)
	if err != nil {
		return Amount{}, err
	}
	return Amount{value: v}, nil
}
`,
			wantCount: 0,
		},
		{
			name:     "explicit error constructed - correct code",
			filename: "money/amount.go",
			code: `package money

func Parse(raw string) (Amount, error) {
	v, err := decimal.NewFromString(raw)
	if err != nil {
		return Amount{}, fmt.Errorf("parse amount %q: %w", raw, err)
	}
	return Amount{value: v}, nil
}
`,
			wantCount: 0,
		},
		{
			name:     "populated struct literal is not a degradation",
			filename: "money/amount.go",
			code: `package money

func Parse(raw string) (Amount, error) {
	v, err := decimal.NewFromString(raw)
	if err != nil {
		return Amount{value: decimal.Zero}, nil
	}
	return Amount{value: v}, nil
}
`,
			wantCount: 0,
		},
		{
			name:     "function without error result is out of scope",
			filename: "cache/lookup.go",
			code: `package cache

func (c *Cache) Get(key string) Entry {
	entry, ok := c.items[key]
	if !ok {
		return Entry{}
	}
	return entry
}
`,
			wantCount: 0,
		},
		{
			name:     "function without results is out of scope",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Reset() {
	if l.source == nil {
		return
	}
	l.source.Close()
}
`,
			wantCount: 0,
		},
		{
			name:     "zero time.Time is an allowed empty value",
			filename: "schedule/window.go",
			code: `package schedule

func (w *Window) Start() (time.Time, error) {
	if w.raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, w.raw)
}
`,
			wantCount: 0,
		},
		{
			name:     "anonymous struct literal has no reportable type name",
			filename: "api/probe.go",
			code: `package api

func Probe() (struct{}, error) {
	if !ready() {
		return struct{}{}, nil
	}
	return struct{}{}, nil
}
`,
			wantCount: 0,
		},
		{
			name:     "empty slice and map literals are not structs",
			filename: "api/list.go",
			code: `package api

func List(q string) ([]Item, error) {
	if q == "" {
		return []Item{}, nil
	}
	return search(q)
}

func Index(q string) (map[string]Item, error) {
	if q == "" {
		return map[string]Item{}, nil
	}
	return index(q)
}
`,
			wantCount: 0,
		},
		{
			name:     "single-result return has no error to hide",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load() (Config, error) {
	if l.source == nil {
		return Config{}
	}
	return l.source.Read()
}
`,
			wantCount: 0,
		},
		{
			// Правило смотрит только на return'ы внутри error/nil-guard'ов.
			// Безусловный `return Config{}, nil` в хвосте функции — граница текущего поведения.
			name:     "unguarded empty return at the tail is not detected",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load(path string) (Config, error) {
	raw, err := l.source.Read(path)
	if err != nil {
		return Config{}, err
	}
	return Config{}, nil
}
`,
			wantCount: 0,
		},
		{
			// Вложенный if с условием, не похожим на error/nil-check, обрывает обход:
			// return внутри него не проверяется. Граница текущего поведения.
			name:     "return under a non-guard nested condition is not detected",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load(path string) (Config, error) {
	raw, err := l.source.Read(path)
	if err != nil {
		if l.lenient {
			return Config{}, nil
		}
		return Config{}, err
	}
	return decode(raw)
}
`,
			wantCount: 0,
		},
		{
			// Ветка else обходится только когда условие внешнего if само является
			// error/nil-guard'ом. Иначе else-if пропускается. Граница текущего поведения.
			name:     "else-if guard under a non-guard if is not detected",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load(path string) (Config, error) {
	if l.mode == "fast" {
		return l.fast(path)
	} else if err := l.check(path); err != nil {
		return Config{}, nil
	}
	return decode(path)
}
`,
			wantCount: 0,
		},
		{
			// Тело for/switch не обходится вовсе.
			name:     "guard inside a loop body is out of scope",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) LoadAll(paths []string) (Config, error) {
	for _, p := range paths {
		raw, err := l.source.Read(p)
		if err != nil {
			return Config{}, nil
		}
		l.merge(raw)
	}
	return l.result, nil
}
`,
			wantCount: 0,
		},
		{
			name:     "nolint on the return line suppresses",
			filename: "config/loader.go",
			code: `package config

func (l *Loader) Load() (Config, error) {
	if l.source == nil {
		return Config{}, nil // nolint:empty-struct-return // no source means documented empty config
	}
	return l.source.Read()
}
`,
			wantCount: 0,
		},
		{
			name:     "test file is skipped",
			filename: "config/loader_test.go",
			code: `package config

func buildConfig() (Config, error) {
	if fixture == nil {
		return Config{}, nil
	}
	return fixture.Config, nil
}
`,
			wantCount: 0,
		},
		{
			name:     "test helper directory is skipped",
			filename: "internal/testutil/fixtures.go",
			code: `package testutil

func BuildConfig() (Config, error) {
	if fixture == nil {
		return Config{}, nil
	}
	return fixture.Config, nil
}
`,
			wantCount: 0,
		},
		{
			name:     "test_-prefixed file is skipped",
			filename: "config/test_fixtures.go",
			code: `package config

func BuildConfig() (Config, error) {
	if fixture == nil {
		return Config{}, nil
	}
	return fixture.Config, nil
}
`,
			wantCount: 0,
		},
		{
			name:     "testing.go helper file is skipped",
			filename: "config/testing.go",
			code: `package config

func BuildConfig() (Config, error) {
	if fixture == nil {
		return Config{}, nil
	}
	return fixture.Config, nil
}
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := analyzeEmptyStructReturn(t, tt.filename, tt.code)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}

// Находка указывает на строку return, называет тип и несёт подсказку —
// контракт вывода, который ломается молча при рефакторинге.
func TestEmptyStructReturnRule_ViolationShape(t *testing.T) {
	code := `package money

func Parse(raw string) (Amount, error) {
	v, err := decimal.NewFromString(raw)
	if err != nil {
		return Amount{}, nil
	}
	return Amount{value: v}, nil
}
`
	violations := analyzeEmptyStructReturn(t, "money/amount.go", code)
	require.Len(t, violations, 1)

	v := violations[0]
	assert.Equal(t, "money/amount.go", v.File)
	assert.Equal(t, 6, v.Line)
	assert.Equal(t, core.SeverityCritical, v.Severity)
	assert.Contains(t, v.Message, "Empty Amount{} returned with nil error")
	assert.Contains(t, v.Code, "return Amount{}, nil")
	assert.NotEmpty(t, v.Suggestion)
}

// Без Go-AST (TypeScript, конфиги) правило обязано молчать, а не паниковать.
func TestEmptyStructReturnRule_NoGoAST(t *testing.T) {
	rule := NewEmptyStructReturnRule()
	ctx := core.NewFileContext("frontend/src/loader.ts", ".", []byte("export const x = 1\n"), nil)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}
