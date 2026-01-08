package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRangeValPointerRule_Metadata(t *testing.T) {
	rule := NewRangeValPointerRule()

	assert.Equal(t, "range-val-pointer", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestRangeValPointerRule_Detection(t *testing.T) {
	rule := NewRangeValPointerRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "pointer to range value",
			code: `package main

func example() {
	items := []Item{{}, {}}
	var ptrs []*Item
	for _, item := range items {
		ptrs = append(ptrs, &item)
	}
}

type Item struct{}
`,
			expectMatch: true,
		},
		{
			name: "pointer to range key",
			code: `package main

func example() {
	items := []int{1, 2, 3}
	var ptrs []*int
	for i := range items {
		ptrs = append(ptrs, &i)
	}
}
`,
			expectMatch: true,
		},
		{
			name: "pointer to local copy",
			code: `package main

func example() {
	items := []Item{{}, {}}
	var ptrs []*Item
	for _, item := range items {
		copy := item
		ptrs = append(ptrs, &copy)
	}
}

type Item struct{}
`,
			expectMatch: false,
		},
		{
			name: "pointer to slice element",
			code: `package main

func example() {
	items := []Item{{}, {}}
	var ptrs []*Item
	for i := range items {
		ptrs = append(ptrs, &items[i])
	}
}

type Item struct{}
`,
			expectMatch: false,
		},
		{
			name: "no pointer usage",
			code: `package main

func example() {
	items := []int{1, 2, 3}
	sum := 0
	for _, item := range items {
		sum += item
	}
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createRangeContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "range_val_pointer", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createRangeContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitRangeLines(code),
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

func splitRangeLines(s string) []string {
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
