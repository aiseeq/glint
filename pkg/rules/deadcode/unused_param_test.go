package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestUnusedParamRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
		wantParams     []string // expected unused param names
	}{
		{
			name: "all params used",
			code: `package main

func add(a, b int) int {
	return a + b
}`,
			wantViolations: 0,
		},
		{
			name: "one unused param",
			code: `package main

func greet(name string, unused int) string {
	return "Hello, " + name
}`,
			wantViolations: 1,
			wantParams:     []string{"unused"},
		},
		{
			name: "multiple unused params",
			code: `package main

func process(a, b, c int) int {
	return a
}`,
			wantViolations: 2,
			wantParams:     []string{"b", "c"},
		},
		{
			name: "blank identifier is ok",
			code: `package main

func handler(_ int, name string) string {
	return name
}`,
			wantViolations: 0,
		},
		{
			name: "blank context in a function nothing calls through a signature",
			code: `package main

import "context"

type settings struct{}

func classify(_ context.Context, name string) string {
	return name
}

func (s settings) effectiveAt(_ context.Context, day int) int {
	return day
}`,
			wantViolations: 2,
			wantParams:     []string{"_"},
		},
		{
			name: "blank context required by an interface or a function type",
			code: `package main

import "context"

type classifier interface{ Classify(ctx context.Context, name string) string }

type plain struct{}

func (plain) Classify(_ context.Context, name string) string { return name }

func register(fn func(context.Context, string) string) { _ = fn(context.Background(), "") }

func named(_ context.Context, name string) string { return name }

var _ classifier = plain{}

func wire() { register(named) }`,
			wantViolations: 0,
		},
		{
			name: "main function skipped",
			code: `package main

func main() {
	println("hello")
}`,
			wantViolations: 0,
		},
		{
			name: "init function skipped",
			code: `package main

func init() {
	println("init")
}`,
			wantViolations: 0,
		},
		{
			name: "method receiver not counted as param",
			code: `package main

type Server struct{}

func (s *Server) Start(port int) {
	println(port)
}`,
			wantViolations: 0,
		},
		{
			name: "no params",
			code: `package main

func noParams() int {
	return 42
}`,
			wantViolations: 0,
		},
		{
			name: "variadic param used",
			code: `package main

func sum(nums ...int) int {
	total := 0
	for _, n := range nums {
		total += n
	}
	return total
}`,
			wantViolations: 0,
		},
		{
			name: "variadic param unused",
			code: `package main

func ignoreAll(nums ...int) int {
	return 0
}`,
			wantViolations: 1,
			wantParams:     []string{"nums"},
		},
		{
			name: "closure uses param",
			code: `package main

func maker(x int) func() int {
	return func() int {
		return x
	}
}`,
			wantViolations: 0,
		},
		{
			name: "field name and literal key spelled like the param",
			code: `package main

type point struct{ x int }

func shadow(x int) point {
	p := point{x: 1}
	_ = p.x
	return p
}`,
			wantViolations: 1,
			wantParams:     []string{"x"},
		},
		{
			name: "method satisfying an imported interface",
			code: `package main

import (
	"fmt"
	"net/http"
)

type handler struct{}

func (handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}`,
			wantViolations: 0,
		},
		{
			name: "method satisfying an interface of the package",
			code: `package main

type Store interface{ Put(key string, value int) }

type memory struct{ last int }

func (m *memory) Put(key string, value int) { m.last = value }`,
			wantViolations: 0,
		},
		{
			name: "function passed as a value",
			code: `package main

import (
	"fmt"
	"net/http"
)

func health(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }

func register(mux *http.ServeMux) { mux.HandleFunc("/health", health) }`,
			wantViolations: 0,
		},
		{
			name: "method passed as a value",
			code: `package main

type job struct{}

func (j job) run(attempt int) {}

func schedule(f func(int)) { f(1) }

func start() { schedule(job{}.run) }`,
			wantViolations: 0,
		},
		{
			name: "method matching no interface",
			code: `package main

type job struct{}

func (j job) Run(attempt int) {}`,
			wantViolations: 1,
			wantParams:     []string{"attempt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := analyzeUnusedParams(t, map[string]string{"main.go": tt.code})

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)

			for _, param := range tt.wantParams {
				found := false
				for _, v := range violations {
					if v.Context["param"] == param {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected param '%s' in one of %d violations", param, len(violations))
			}
		})
	}
}

func analyzeUnusedParams(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewUnusedParamRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

// Findings carry the source line of the parameter, like the other rules of
// the package.
func TestUnusedParamIncludesCodeLine(t *testing.T) {
	violations := analyzeUnusedParams(t, map[string]string{"svc.go": `package main

func greet(name string, unused int) string {
	return "Hello, " + name
}`})
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Code, "func greet(name string, unused int) string {")
}

func TestUnusedParamSkipsTestFiles(t *testing.T) {
	violations := analyzeUnusedParams(t, map[string]string{
		"main.go": "package main\n\nfunc main() {}\n",
		"foo_test.go": `package main

import "testing"

func TestSomething(t *testing.T) { helperWith(1) }

func helperWith(unused int) {}
`,
	})
	assert.Empty(t, violations, "Should skip test files")
}

// Without type information a name tells nothing about which object an
// identifier refers to, so the rule stays silent rather than guess.
func TestUnusedParamSilentWithoutTypes(t *testing.T) {
	ctx := parseGoContext(t, "svc.go", "package main\n\nfunc greet(name string, unused int) string { return name }\n")
	assert.Empty(t, NewUnusedParamRule().AnalyzeFile(ctx))
}
