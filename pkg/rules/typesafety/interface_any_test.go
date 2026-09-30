package typesafety

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func interfaceAnyFindings(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewInterfaceAnyRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

func interfaceAnyInFile(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return interfaceAnyFindings(t, map[string]string{"sample/sample.go": source})
}

func TestInterfaceAnyRule(t *testing.T) {
	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name:          "interface{} in function param",
			code:          "package sample\n\nfunc foo(x interface{}) {}\n",
			expectedCount: 1,
		},
		{
			name:          "map[string]interface{}",
			code:          "package sample\n\nvar m map[string]interface{}\n",
			expectedCount: 1,
		},
		{
			name:          "[]interface{}",
			code:          "package sample\n\nvar s []interface{}\n",
			expectedCount: 1,
		},
		{
			name:          "Using any - should not flag",
			code:          "package sample\n\nfunc foo(x any) {}\n",
			expectedCount: 0,
		},
		{
			name:          "interface{} in string literal",
			code:          "package sample\n\nvar s = \"Use any instead of interface{}\"\n",
			expectedCount: 0,
		},
		{
			name:          "interface{} in comment",
			code:          "package sample\n\n// Use any instead of interface{}\nvar x = 1\n",
			expectedCount: 0,
		},
		{
			name:          "interface{} in raw string",
			code:          "package sample\n\nconst src = `\nvar x interface{}\n`\n",
			expectedCount: 0,
		},
		{
			name:          "interface with methods",
			code:          "package sample\n\ntype Namer interface{ Name() string }\n",
			expectedCount: 0,
		},
		{
			name:          "map[string]interface{} passed as argument",
			code:          "package sample\n\nimport \"fmt\"\n\nfunc F() { fmt.Println(map[string]interface{}{}) }\n",
			expectedCount: 1,
		},
		{
			name:          "every interface{} of a line",
			code:          "package sample\n\nvar f func(interface{}) interface{}\n",
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Len(t, interfaceAnyInFile(t, tt.code), tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestInterfaceAnyReportsMostSpecificPattern(t *testing.T) {
	// The message must be stable across runs and name the most specific
	// replacement, not whichever pattern happened to match first.
	violations := interfaceAnyInFile(t, "package sample\n\nvar m map[string]interface{}\n")
	if assert.Len(t, violations, 1) {
		assert.Equal(t, "Use 'map[string]any' instead of 'map[string]interface{}' (Go 1.18+)", violations[0].Message)
	}
}

// The column points at interface{} itself, so the fixer rewrites that one.
func TestInterfaceAnyReportsColumn(t *testing.T) {
	violations := interfaceAnyInFile(t, "package sample\n\nfunc F(a any, b interface{}) {}\n")
	require.Len(t, violations, 1)
	assert.Equal(t, 3, violations[0].Line)
	assert.Equal(t, 17, violations[0].Column)
}

func TestInterfaceAnyFlagsPartialMigration(t *testing.T) {
	// 'any' elsewhere on the line must not excuse a remaining interface{}
	assert.Len(t, interfaceAnyInFile(t, "package sample\n\nfunc F(a any, b interface{}) {}\n"), 1)
}

func TestInterfaceAnyIgnoresInlineComment(t *testing.T) {
	code := `package sample

var names = map[string]bool{
	"i": true, // interface{} receivers
}
`
	assert.Empty(t, interfaceAnyInFile(t, code))
}

func TestInterfaceAnyJWTCallbackException(t *testing.T) {
	violations := interfaceAnyFindings(t, map[string]string{
		"jwt/jwt.go": "package jwt\n\n// Token is a token.\ntype Token struct{}\n",
		"sample/sample.go": `package sample

import "example.com/rulestest/jwt"

type Token struct{}

var keyfunc = func(token *Token) (interface{}, error) { return nil, nil }

var _ = func(token *jwt.Token) (interface{}, error) { return nil, nil }
`,
	})
	lines := make([]int, 0, len(violations))
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{7}, lines, "the jwt callback line is the documented exception")
}

// A module older than Go 1.18 has no any: suggesting it would not compile.
func TestInterfaceAnySilentBeforeGo118(t *testing.T) {
	violations := interfaceAnyFindings(t, map[string]string{
		"go.mod":      "module example.com/projecta\n\ngo 1.16\n",
		"p/p.go":      "package p\n\n// V holds a value.\nvar V interface{}\n",
		"p/p_test.go": "package p\n\nvar w interface{}\n",
		"p/other.go":  "package p\n\nvar U = V\n",
	})
	assert.Empty(t, violations)
}

// Test files have no type information; their module still decides.
func TestInterfaceAnyReportsTestFileOfNewModule(t *testing.T) {
	violations := interfaceAnyFindings(t, map[string]string{
		"p/p.go":      "package p\n\nvar V any\n",
		"p/p_test.go": "package p\n\nvar w interface{}\n",
	})
	require.Len(t, violations, 1)
	assert.Equal(t, "p/p_test.go", violations[0].File)
}

// A package declaring its own any cannot take the predeclared one.
func TestInterfaceAnySilentWhenAnyIsShadowed(t *testing.T) {
	violations := interfaceAnyFindings(t, map[string]string{
		"p/types.go": "package p\n\ntype any = int\n",
		"p/p.go":     "package p\n\nvar V interface{}\n",
	})
	assert.Empty(t, violations)
}

func TestInterfaceAnyNonGoFile(t *testing.T) {
	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("const x: any = 1"), core.DefaultConfig())
	assert.Empty(t, NewInterfaceAnyRule().AnalyzeFile(ctx))
}
