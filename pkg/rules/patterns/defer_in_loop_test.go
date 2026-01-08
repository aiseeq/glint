package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeferInLoopRule_Metadata(t *testing.T) {
	rule := NewDeferInLoopRule()

	assert.Equal(t, "defer-in-loop", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestDeferInLoopRule_Detection(t *testing.T) {
	rule := NewDeferInLoopRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "defer in for loop",
			code: `package main

func example() {
	for i := 0; i < 10; i++ {
		f, _ := os.Open("file")
		defer f.Close()
	}
}
`,
			expectMatch: true,
		},
		{
			name: "defer in range loop",
			code: `package main

func example() {
	files := []string{"a", "b", "c"}
	for _, name := range files {
		f, _ := os.Open(name)
		defer f.Close()
	}
}
`,
			expectMatch: true,
		},
		{
			name: "defer outside loop",
			code: `package main

func example() {
	f, _ := os.Open("file")
	defer f.Close()
	for i := 0; i < 10; i++ {
		// do something
	}
}
`,
			expectMatch: false,
		},
		{
			name: "defer in anonymous function inside loop",
			code: `package main

func example() {
	for i := 0; i < 10; i++ {
		func() {
			f, _ := os.Open("file")
			defer f.Close()
		}()
	}
}
`,
			expectMatch: false, // OK - defer is in its own function scope
		},
		{
			name: "nested loops with defer",
			code: `package main

func example() {
	for i := 0; i < 10; i++ {
		for j := 0; j < 10; j++ {
			f, _ := os.Open("file")
			defer f.Close()
		}
	}
}
`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createDeferContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "defer_in_loop", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestDeferInLoopRule_TestFilesExcluded(t *testing.T) {
	rule := NewDeferInLoopRule()

	code := `package main

func example() {
	for i := 0; i < 10; i++ {
		defer func() {}()
	}
}
`
	ctx := createDeferContext(t, "service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

// Helper function
func createDeferContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitDeferLines(code),
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

func splitDeferLines(s string) []string {
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
