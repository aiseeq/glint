package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringConcatRule_Metadata(t *testing.T) {
	rule := NewStringConcatRule()

	assert.Equal(t, "string-concat", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestStringConcatRule_Detection(t *testing.T) {
	rule := NewStringConcatRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "string concat with +=",
			code: `package main

func example() {
	result := ""
	for i := 0; i < 10; i++ {
		result += "item"
	}
}
`,
			expectMatch: true,
		},
		{
			name: "string concat with = and +",
			code: `package main

func example() {
	result := ""
	for i := 0; i < 10; i++ {
		result = result + "item"
	}
}
`,
			expectMatch: true,
		},
		{
			name: "string builder",
			code: `package main

import "strings"

func example() {
	var sb strings.Builder
	for i := 0; i < 10; i++ {
		sb.WriteString("item")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "concat outside loop",
			code: `package main

func example() {
	result := "hello" + " " + "world"
	_ = result
}
`,
			expectMatch: false,
		},
		{
			name: "range loop concat with variable only",
			code: `package main

func example() {
	result := ""
	items := []string{"a", "b", "c"}
	for _, item := range items {
		result += item
	}
}
`,
			expectMatch: false, // Conservative: variables not flagged to avoid false positives
		},
		{
			name: "range loop concat with literal",
			code: `package main

func example() {
	result := ""
	items := []string{"a", "b", "c"}
	for _, item := range items {
		result += item + ", "
	}
}
`,
			expectMatch: true, // String literal triggers detection
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createConcatContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "string_concat_loop", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createConcatContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitConcatLines(code),
		Content: []byte(code),
	}

	if len(path) > 3 && path[len(path)-3:] == ".go" {
		parser := core.NewParser()
		fset, ast, err := parser.ParseGoFile(path, []byte(code))
		if err != nil {
			t.Fatalf("Failed to parse Go code: %v", err)
		}
		ctx.SetGoAST(fset, ast)
	}

	return ctx
}

func splitConcatLines(s string) []string {
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
