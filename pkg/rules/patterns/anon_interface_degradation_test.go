package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// analyzeAnonDegradation парсит Go-исходник и прогоняет по нему правило.
func analyzeAnonDegradation(t *testing.T, path, code string) []*core.Violation {
	t.Helper()

	ctx := core.NewFileContext(path, ".", []byte(code), nil)
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ctx.SetGoAST(fset, astFile)

	return NewAnonInterfaceDegradationRule().AnalyzeFile(ctx)
}

func TestAnonInterfaceDegradationRule_Metadata(t *testing.T) {
	rule := NewAnonInterfaceDegradationRule()

	assert.Equal(t, "anon-interface-degradation", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityCritical, rule.DefaultSeverity())
	assert.True(t, rules.HonorsSuppression(rule))
}

func TestAnonInterfaceDegradationRule(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		code      string
		wantCount int
	}{
		{
			name:     "delegation to anonymous interface then zero duration",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if d.inner != nil {
		if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
			return v.Timeout()
		}
	}
	return 0
}
`,
			wantCount: 1,
		},
		{
			name:     "assertion directly in the if init then empty string",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Name() string {
	if v, ok := d.inner.(interface{ Name() string }); ok {
		return v.Name()
	}
	return ""
}
`,
			wantCount: 1,
		},
		{
			name:     "degradation to nil",
			filename: "registry.go",
			code: `package registry

func (r *Registry) Codec() Codec {
	if v, ok := r.backend.(interface{ Codec() Codec }); ok {
		return v.Codec()
	}
	return nil
}
`,
			wantCount: 1,
		},
		{
			name:     "degradation to empty composite literal",
			filename: "registry.go",
			code: `package registry

func (r *Registry) Limits() Limits {
	if v, ok := r.backend.(interface{ Limits() Limits }); ok {
		return v.Limits()
	}
	return Limits{}
}
`,
			wantCount: 1,
		},
		{
			name:     "degradation to negative sentinel",
			filename: "registry.go",
			code: `package registry

func (r *Registry) Weight() int {
	if v, ok := r.backend.(interface{ Weight() int }); ok {
		return v.Weight()
	}
	return -1
}
`,
			wantCount: 1,
		},
		{
			name:     "degradation to hardcoded duration expression",
			filename: "registry.go",
			code: `package registry

func (r *Registry) Timeout() time.Duration {
	if v, ok := r.backend.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return 5 * time.Second
}
`,
			wantCount: 1,
		},
		{
			name:     "assertion in else-if branch still counts",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if d.primary != nil {
		return d.primary.Timeout()
	} else if v, ok := d.fallback.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return 0
}
`,
			wantCount: 1,
		},
		{
			name:     "every degrading delegation in the file is reported",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Name() string {
	if v, ok := d.inner.(interface{ Name() string }); ok {
		return v.Name()
	}
	return ""
}

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return 0
}
`,
			wantCount: 2,
		},
		{
			name:     "assertion inside a plain else block still counts",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if d.inner == nil {
		return d.configuredTimeout()
	} else {
		if v, ok := d.fallback.(interface{ Timeout() time.Duration }); ok {
			return v.Timeout()
		}
	}
	return 0
}
`,
			wantCount: 1,
		},
		{
			name:     "named interface assertion is out of scope",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(TimeoutProvider); ok {
		return v.Timeout()
	}
	return 0
}
`,
			wantCount: 0,
		},
		{
			name:     "explicit error instead of silent degradation",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() (time.Duration, error) {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout(), nil
	}
	return 0, fmt.Errorf("inner %T does not implement Timeout", d.inner)
}
`,
			wantCount: 0,
		},
		{
			name:     "errors.New is an explicit error too",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() (time.Duration, error) {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout(), nil
	}
	return 0, errors.New("inner does not implement Timeout")
}
`,
			wantCount: 0,
		},
		{
			// isExplicitError матчит хвосты "New"/"Wrap"/"Errorf" без пакета, поэтому
			// любой конструктор с таким именем гасит находку. Известная переширь.
			name:     "any call named New in the results is taken for an explicit error",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Codec() (Codec, time.Duration) {
	if v, ok := d.inner.(interface{ Codec() Codec }); ok {
		return v.Codec(), 0
	}
	return registry.New(), 0
}
`,
			wantCount: 0,
		},
		{
			name:     "fallthrough delegates to a real call",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return d.configuredTimeout()
}
`,
			wantCount: 0,
		},
		{
			name:     "fallthrough returns a named constant",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return defaultTimeout
}
`,
			wantCount: 0,
		},
		{
			name:     "comma-ok map lookup in the if init is not a type assertion",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout(key string) time.Duration {
	if v, ok := d.overrides[key]; ok {
		return v
	}
	return 0
}
`,
			wantCount: 0,
		},
		{
			name:     "fallthrough computes a value instead of degrading",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return d.base + d.jitter
}
`,
			wantCount: 0,
		},
		{
			name:     "fallthrough returns a package-qualified constant",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return defaults.Timeout
}
`,
			wantCount: 0,
		},
		{
			name:     "bare return is not a degradation value",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Warm() {
	if v, ok := d.inner.(interface{ Warm() }); ok {
		v.Warm()
		return
	}
	return
}
`,
			wantCount: 0,
		},
		{
			name:     "no anonymous interface assertion at all",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if d.inner == nil {
		return 0
	}
	return d.inner.Timeout()
}
`,
			wantCount: 0,
		},
		{
			// Правило смотрит только на statement, непосредственно следующий за if.
			// Любая инструкция между ними прячет находку — граница текущего поведения.
			name:     "statement between assertion and degradation return hides the finding",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	d.logger.Warn("inner has no Timeout, degrading")
	return 0
}
`,
			wantCount: 0,
		},
		{
			// Обход идёт только по верхнеуровневым statement'ам тела функции:
			// тот же паттерн внутри for/switch не находится.
			name:     "pattern nested in a loop body is out of scope",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeouts() []time.Duration {
	var out []time.Duration
	for _, inner := range d.inners {
		if v, ok := inner.(interface{ Timeout() time.Duration }); ok {
			out = append(out, v.Timeout())
		}
		return nil
	}
	return out
}
`,
			wantCount: 0,
		},
		{
			name:     "nolint on the degradation line suppresses",
			filename: "dispatcher.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return 0 // nolint:anon-interface-degradation // zero means "no limit" by contract
}
`,
			wantCount: 0,
		},
		{
			name:     "test file is skipped",
			filename: "dispatcher_test.go",
			code: `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return 0
}
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := analyzeAnonDegradation(t, tt.filename, tt.code)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}

// Находка должна указывать на строку деградирующего return, а не на assertion,
// и нести код строки и подсказку — это контракт вывода, ломается молча при рефакторинге.
func TestAnonInterfaceDegradationRule_ViolationShape(t *testing.T) {
	code := `package dispatch

func (d *Dispatcher) Timeout() time.Duration {
	if v, ok := d.inner.(interface{ Timeout() time.Duration }); ok {
		return v.Timeout()
	}
	return 0
}
`
	violations := analyzeAnonDegradation(t, "dispatch/dispatcher.go", code)
	require.Len(t, violations, 1)

	v := violations[0]
	assert.Equal(t, "dispatch/dispatcher.go", v.File)
	assert.Equal(t, 7, v.Line)
	assert.Equal(t, core.SeverityCritical, v.Severity)
	assert.Contains(t, v.Message, "Silent degradation after anonymous interface assertion")
	assert.Contains(t, v.Code, "return 0")
	assert.NotEmpty(t, v.Suggestion)
}

// Без Go-AST (TypeScript, конфиги) правило обязано молчать, а не паниковать.
func TestAnonInterfaceDegradationRule_NoGoAST(t *testing.T) {
	rule := NewAnonInterfaceDegradationRule()
	ctx := core.NewFileContext("frontend/src/dispatcher.ts", ".", []byte("export const x = 1\n"), nil)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}
