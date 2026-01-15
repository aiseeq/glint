package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestMagicNumberRule(t *testing.T) {
	rule := NewMagicNumberRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "Magic number in function - should flag",
			code: `package main
func foo() {
	timeout := 4321
	_ = timeout
}`,
			expectedCount: 1,
		},
		{
			name: "Const declaration - OK",
			code: `package main
const timeout = 3600`,
			expectedCount: 0,
		},
		{
			name: "Small values 0, 1 - OK",
			code: `package main
func foo() {
	x := 0
	y := 1
	_ = x + y
}`,
			expectedCount: 0,
		},
		{
			name: "Common acceptable values - OK",
			code: `package main
func foo() {
	x := 100
	y := 1024
	_ = x + y
}`,
			expectedCount: 0,
		},
		{
			name: "Array size - OK",
			code: `package main
var arr [256]byte`,
			expectedCount: 0,
		},
		{
			name: "Slice index - OK",
			code: `package main
func foo(s []int) int {
	return s[3]
}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())

			// Parse Go AST - magic number rule requires AST
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

func TestMagicNumberRuleNoAST(t *testing.T) {
	rule := NewMagicNumberRule()

	// Without AST, rule should return no violations
	ctx := core.NewFileContext("/src/file.go", "/src", []byte("x := 3600"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

func TestMagicNumberRuleTestFile(t *testing.T) {
	rule := NewMagicNumberRule()

	// Test files should be skipped
	code := `package main
func TestFoo(t *testing.T) {
	expected := 3600
	_ = expected
}`
	ctx := core.NewFileContext("/src/file_test.go", "/src", []byte(code), core.DefaultConfig())

	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile("/src/file_test.go", []byte(code))
	if err == nil {
		ctx.SetGoAST(fset, astFile)
	}

	violations := rule.AnalyzeFile(ctx)
	assert.Empty(t, violations)
}

func TestMagicNumberConfigure(t *testing.T) {
	rule := NewMagicNumberRule()

	err := rule.Configure(map[string]any{
		"min_value": 10,
	})
	assert.NoError(t, err)
	assert.Equal(t, 10, rule.minValue)
}
