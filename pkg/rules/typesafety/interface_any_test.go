package typesafety

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestInterfaceAnyRule(t *testing.T) {
	rule := NewInterfaceAnyRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name:          "interface{} in function param",
			code:          "func foo(x interface{}) {}",
			expectedCount: 1,
		},
		{
			name:          "map[string]interface{}",
			code:          "var m map[string]interface{}",
			expectedCount: 1,
		},
		{
			name:          "[]interface{}",
			code:          "var s []interface{}",
			expectedCount: 1,
		},
		{
			name:          "Using any - should not flag",
			code:          "func foo(x any) {}",
			expectedCount: 0,
		},
		{
			name:          "interface{} in string literal",
			code:          `fmt.Println("Use any instead of interface{}")`,
			expectedCount: 0,
		},
		{
			name:          "interface{} in comment",
			code:          "// Use any instead of interface{}",
			expectedCount: 0,
		},
		{
			name:          "JWT callback exception",
			code:          "func(token *jwt.Token) (interface{}, error) { return nil, nil }",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use /src/file.go to avoid IsTestFile() matching /test/
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestInterfaceAnyReportsMostSpecificPattern(t *testing.T) {
	rule := NewInterfaceAnyRule()

	// The message must be stable across runs and name the most specific
	// replacement, not whichever pattern happened to match first.
	ctx := core.NewFileContext("/src/file.go", "/src", []byte("var m map[string]interface{}"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)
	if assert.Len(t, violations, 1) {
		assert.Equal(t, "Use 'map[string]any' instead of 'map[string]interface{}' (Go 1.18+)", violations[0].Message)
	}
}

func TestInterfaceAnyFlagsPartialMigration(t *testing.T) {
	rule := NewInterfaceAnyRule()

	// 'any' elsewhere on the line must not excuse a remaining interface{}
	ctx := core.NewFileContext("/src/file.go", "/src", []byte("func F(a any, b interface{}) {}"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)
	assert.Len(t, violations, 1)
}

func TestInterfaceAnyNonGoFile(t *testing.T) {
	rule := NewInterfaceAnyRule()

	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("const x: any = 1"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

func TestInterfaceAnyIgnoresInlineComment(t *testing.T) {
	code := `package sample
var names = map[string]bool{
	"i": true, // interface{} receivers
}`
	ctx := core.NewFileContext("/src/sample.go", "/src", []byte(code), core.DefaultConfig())

	assert.Empty(t, NewInterfaceAnyRule().AnalyzeFile(ctx))
}
