package typesafety

import (
	"go/parser"
	"go/token"
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
		{
			name: "unsafe assertion in return",
			code: `package main

func example(x interface{}) string {
	return x.(string)
}
`,
			expectMatch: true,
		},
		{
			name: "unsafe assertion as call argument",
			code: `package main

func sink(s string) {}

func example(x interface{}) {
	sink(x.(string))
}
`,
			expectMatch: true,
		},
		{
			name: "unsafe assertions in multi-value assignment",
			code: `package main

func example(x, y interface{}) {
	a, b := x.(string), y.(int)
	_, _ = a, b
}
`,
			expectMatch: true,
		},
		{
			name: "safe comma-ok in if statement",
			code: `package main

func example(x interface{}) {
	if v, ok := x.(string); ok {
		_ = v
	}
}
`,
			expectMatch: false,
		},
		{
			name: "safe comma-ok var declaration",
			code: `package main

func example(x interface{}) {
	var v, ok = x.(string)
	_, _ = v, ok
}
`,
			expectMatch: false,
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

// token.Pos is an offset into the shared file set; counting newlines in the
// file's own content reported the wrong line as soon as a set held more than
// one file.
func TestTypeAssertionReportsRealLineWithSharedFileSet(t *testing.T) {
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "filler.go", "package filler\n\n// padding\n", parser.ParseComments); err != nil {
		t.Fatalf("parse filler: %v", err)
	}

	code := `package svc

import "fmt"

func Describe(v any) string {
	fmt.Println("before")
	name := v.(string)
	return name
}
`
	astFile, err := parser.ParseFile(fset, "svc.go", code, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx := core.NewFileContext("svc.go", ".", []byte(code), nil)
	ctx.SetGoAST(fset, astFile)

	violations := NewTypeAssertionRule().AnalyzeFile(ctx)
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1", len(violations))
	}
	if violations[0].Line != 7 {
		t.Fatalf("got line %d, want 7 — the position was resolved against the wrong file", violations[0].Line)
	}
}
