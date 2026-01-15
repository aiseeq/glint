package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestIgnoredErrorRule(t *testing.T) {
	rule := NewIgnoredErrorRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "Ignored file close error",
			code: `package main
func foo() {
	f, _ := os.Open("file.txt")
	_ = f
}`,
			expectedCount: 1,
		},
		{
			name: "Handled error",
			code: `package main
func foo() {
	f, err := os.Open("file.txt")
	if err != nil {
		return
	}
	_ = f
}`,
			expectedCount: 0,
		},
		{
			name: "Print functions are safe to ignore",
			code: `package main
import "fmt"
func foo() {
	n, _ := fmt.Println("hello")
	_ = n
}`,
			expectedCount: 0,
		},
		{
			name: "Multi-value with ignored error",
			code: `package main
func foo() {
	data, _ := json.Marshal(x)
	_ = data
}`,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use path without "/test" to avoid being skipped
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())

			// Parse Go AST
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/src/file.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestIgnoredErrorRuleNoAST(t *testing.T) {
	rule := NewIgnoredErrorRule()

	// Non-Go file should return no violations
	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("const x = 1"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
