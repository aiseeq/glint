package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestUnusedSymbolsRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "unused private function",
			code: `package main

func main() {}

func unusedHelper() {}`,
			wantViolations: 1,
		},
		{
			name: "used private function",
			code: `package main

func main() {
	helper()
}

func helper() {}`,
			wantViolations: 0,
		},
		{
			name: "unused private type",
			code: `package main

type unusedType struct{}

func main() {}`,
			wantViolations: 1,
		},
		{
			name: "used private type",
			code: `package main

type myType struct{}

func main() {
	var _ myType
}`,
			wantViolations: 0,
		},
		{
			name: "unused private constant",
			code: `package main

const unusedConst = 42

func main() {}`,
			wantViolations: 1,
		},
		{
			name: "used private constant",
			code: `package main

const myConst = 42

func main() {
	_ = myConst
}`,
			wantViolations: 0,
		},
		{
			name: "unused private variable",
			code: `package main

var unusedVar = "hello"

func main() {}`,
			wantViolations: 1,
		},
		{
			name: "used private variable",
			code: `package main

var myVar = "hello"

func main() {
	println(myVar)
}`,
			wantViolations: 0,
		},
		{
			name: "exported function - skip",
			code: `package main

func main() {}

func ExportedHelper() {}`,
			wantViolations: 0,
		},
		{
			name: "exported type - skip",
			code: `package main

type ExportedType struct{}

func main() {}`,
			wantViolations: 0,
		},
		{
			name: "init function - skip",
			code: `package main

func init() {}

func main() {}`,
			wantViolations: 0,
		},
		{
			name: "method - skip (might implement interface)",
			code: `package main

type myType struct{}

func (m *myType) unusedMethod() {}

func main() {
	var _ myType
}`,
			wantViolations: 0,
		},
		{
			name: "blank identifier - skip",
			code: `package main

var _ = func() {}

func main() {}`,
			wantViolations: 0,
		},
		{
			name: "multiple unused symbols",
			code: `package main

func unusedFunc1() {}
func unusedFunc2() {}
type unusedType struct{}
const unusedConst = 1

func main() {}`,
			wantViolations: 4,
		},
		{
			name: "function used in another function",
			code: `package main

func helper1() {
	helper2()
}

func helper2() {}

func main() {
	helper1()
}`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnusedSymbolsRule()

			parser := core.NewParser()
			ctx := core.NewFileContext("/src/main.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/main.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)
		})
	}
}

func TestUnusedSymbolsRuleMetadata(t *testing.T) {
	rule := NewUnusedSymbolsRule()

	assert.Equal(t, "unused-symbol", rule.Name())
	assert.Equal(t, "deadcode", rule.Category())
	assert.Equal(t, core.SeverityLow, rule.DefaultSeverity())
}

func TestUnusedSymbolsSkipsTestFiles(t *testing.T) {
	rule := NewUnusedSymbolsRule()

	code := `package main

func unusedHelper() {}

func TestSomething(t *testing.T) {}`

	parser := core.NewParser()
	ctx := core.NewFileContext("/src/main_test.go", "/src", []byte(code), core.DefaultConfig())
	fset, astFile, err := parser.ParseGoFile("/src/main_test.go", []byte(code))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	ctx.SetGoAST(fset, astFile)

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Should skip test files")
}
