package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnusedParamRule()

			parser := core.NewParser()
			ctx := core.NewFileContext("/src/test.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)

			if tt.wantParams != nil {
				for i, v := range violations {
					if i < len(tt.wantParams) {
						assert.Contains(t, v.Message, tt.wantParams[i],
							"Expected param '%s' in message '%s'", tt.wantParams[i], v.Message)
					}
				}
			}
		})
	}
}

func TestUnusedParamSkipsTestFiles(t *testing.T) {
	rule := NewUnusedParamRule()

	code := `package main

func TestSomething(t *testing.T, unused int) {
	t.Log("test")
}`

	parser := core.NewParser()
	// Path contains _test.go - should be skipped
	ctx := core.NewFileContext("/src/foo_test.go", "/src", []byte(code), core.DefaultConfig())
	fset, astFile, err := parser.ParseGoFile("/src/foo_test.go", []byte(code))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	ctx.SetGoAST(fset, astFile)

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Should skip test files")
}

func TestUnusedParamSkipsNonGoFiles(t *testing.T) {
	rule := NewUnusedParamRule()

	ctx := core.NewFileContext("/src/file.ts", "/src", []byte("function foo(x) {}"), core.DefaultConfig())

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
