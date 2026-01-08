package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppendAssignRule_Metadata(t *testing.T) {
	rule := NewAppendAssignRule()

	assert.Equal(t, "append-assign", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestAppendAssignRule_Detection(t *testing.T) {
	rule := NewAppendAssignRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "append without assignment",
			code: `package main

func example() {
	slice := []int{1, 2, 3}
	append(slice, 4)
}
`,
			expectMatch: true,
		},
		{
			name: "append with assignment",
			code: `package main

func example() {
	slice := []int{1, 2, 3}
	slice = append(slice, 4)
}
`,
			expectMatch: false,
		},
		{
			name: "append with short assignment",
			code: `package main

func example() {
	slice := append([]int{}, 1, 2, 3)
	_ = slice
}
`,
			expectMatch: false,
		},
		{
			name: "append in return",
			code: `package main

func example() []int {
	slice := []int{1, 2, 3}
	return append(slice, 4)
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createAppendContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "append_no_assign", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createAppendContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitAppendLines(code),
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

func splitAppendLines(s string) []string {
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
