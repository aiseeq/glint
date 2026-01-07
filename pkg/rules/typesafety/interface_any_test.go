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

func TestInterfaceAnyNonGoFile(t *testing.T) {
	rule := NewInterfaceAnyRule()

	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("const x: any = 1"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}
