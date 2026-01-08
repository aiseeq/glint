package typesafety

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeAssertionRule_Metadata(t *testing.T) {
	rule := NewTypeAssertionRule()

	assert.Equal(t, "type-assertion", rule.Name())
	assert.Equal(t, "typesafety", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestTypeAssertionRule_UnsafeAssertions(t *testing.T) {
	rule := NewTypeAssertionRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "unsafe single assignment",
			code: `package main

func example(x interface{}) {
	v := x.(string)
	_ = v
}
`,
			expectMatch: true,
		},
		{
			name: "safe comma-ok assignment",
			code: `package main

func example(x interface{}) {
	v, ok := x.(string)
	if ok {
		_ = v
	}
}
`,
			expectMatch: false,
		},
		{
			name: "unsafe var declaration",
			code: `package main

func example(x interface{}) {
	var v = x.(string)
	_ = v
}
`,
			expectMatch: true,
		},
		{
			name: "safe type switch",
			code: `package main

func example(x interface{}) {
	switch v := x.(type) {
	case string:
		_ = v
	}
}
`,
			expectMatch: false,
		},
		{
			name: "multiple unsafe assertions",
			code: `package main

func example(x interface{}) {
	a := x.(string)
	b := x.(int)
	_, _ = a, b
}
`,
			expectMatch: true, // Will find at least one
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTypeAssertionContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "unsafe_type_assertion", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestTypeAssertionRule_TestFilesExcluded(t *testing.T) {
	rule := NewTypeAssertionRule()

	code := `package main

func example(x interface{}) {
	v := x.(string)
	_ = v
}
`
	ctx := createTypeAssertionContext(t, "service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

func TestTypeAssertionRule_NonGoFilesExcluded(t *testing.T) {
	rule := NewTypeAssertionRule()

	ctx := &core.FileContext{
		Path:    "/backend/file.ts",
		RelPath: "backend/file.ts",
		Lines:   []string{"const v = x as string;"},
		Content: []byte("const v = x as string;"),
	}
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Non-Go files should be excluded")
}

// Helper function
func createTypeAssertionContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitLines(code),
		Content: []byte(code),
	}

	// Parse Go AST for Go files
	if len(code) > 0 && path != "" && (len(path) > 3 && path[len(path)-3:] == ".go") {
		parser := core.NewParser()
		fset, ast, err := parser.ParseGoFile(path, []byte(code))
		if err != nil {
			t.Fatalf("Failed to parse Go code: %v", err)
		}
		ctx.SetGoAST(fset, ast)
	}

	return ctx
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
