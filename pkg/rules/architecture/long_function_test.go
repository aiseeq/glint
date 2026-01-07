package architecture

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestLongFunctionRule(t *testing.T) {
	rule := NewLongFunctionRule()
	rule.Configure(map[string]any{
		"max_lines": 10, // Low threshold for testing
	})

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "Short function - OK",
			code: `package main
func short() {
	x := 1
	y := 2
	_ = x + y
}`,
			expectedCount: 0,
		},
		{
			name:          "Long function - should flag",
			code:          generateLongFunction(15),
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/test/file.go", "/test", []byte(tt.code), core.DefaultConfig())

			// Parse Go AST
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/test/file.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount)
		})
	}
}

func generateLongFunction(lines int) string {
	var sb strings.Builder
	sb.WriteString("package main\n")
	sb.WriteString("func longFunc() {\n")
	for i := 0; i < lines; i++ {
		sb.WriteString("\t_ = ")
		sb.WriteString(itoa(i))
		sb.WriteString("\n")
	}
	sb.WriteString("}\n")
	return sb.String()
}

func TestLongFunctionRuleNoAST(t *testing.T) {
	rule := NewLongFunctionRule()

	// Non-Go file should return no violations
	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("const x = 1"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

func TestLongFunctionConfigure(t *testing.T) {
	rule := NewLongFunctionRule()

	err := rule.Configure(map[string]any{
		"max_lines": 100,
	})
	assert.NoError(t, err)
	assert.Equal(t, 100, rule.maxLines)
}
