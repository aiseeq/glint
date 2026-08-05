package patterns

import (
	"go/ast"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestMagicNumberReportsInvalidIntegerLiteral(t *testing.T) {
	rule := NewMagicNumberRule()
	ctx := core.NewFileContext("/src/service.go", "/src", nil, core.DefaultConfig())

	assert.NotNil(t, rule.checkLiteral(ctx, &ast.BasicLit{Kind: token.INT, Value: "invalid"}, &litContexts{}))
}

// A uint64 constant is a perfectly valid Go literal that does not fit int64.
// Reporting it as "Invalid integer literal: value out of range" was a false
// positive on glint's own FNV offset basis.
func TestMagicNumberAcceptsUint64Literal(t *testing.T) {
	rule := NewMagicNumberRule()
	ctx := core.NewFileContext("/src/service.go", "/src", nil, core.DefaultConfig())

	assert.Nil(t, rule.checkLiteral(ctx, &ast.BasicLit{Kind: token.INT, Value: "14695981039346656037"}, &litContexts{}),
		"a uint64 algorithm constant is not a magic number and not an invalid literal")
}

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

// YAML/JSON decoders hand integers over as float64; the value is unambiguous
// and must be accepted, not silently ignored.
func TestMagicNumberConfigureAcceptsFloatMinValue(t *testing.T) {
	rule := NewMagicNumberRule()

	err := rule.Configure(map[string]any{
		"min_value": float64(10),
	})
	assert.NoError(t, err)
	assert.Equal(t, 10, rule.minValue)
}

// Ambiguous input is an error, not a silent fallback to the default.
func TestMagicNumberConfigureRejectsInvalidMinValue(t *testing.T) {
	for name, value := range map[string]any{
		"string":             "10",
		"bool":               true,
		"non-integral float": 10.5,
	} {
		t.Run(name, func(t *testing.T) {
			rule := NewMagicNumberRule()
			err := rule.Configure(map[string]any{"min_value": value})
			assert.Error(t, err)
			assert.Equal(t, 2, rule.minValue, "min_value must stay at default after a rejected setting")
		})
	}
}
