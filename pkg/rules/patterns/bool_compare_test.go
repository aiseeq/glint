package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoolCompareRule_Metadata(t *testing.T) {
	rule := NewBoolCompareRule()

	assert.Equal(t, "bool-compare", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityLow, rule.DefaultSeverity())
}

func TestBoolCompareRule_Detection(t *testing.T) {
	rule := NewBoolCompareRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
		suggestion  string
	}{
		{
			name: "x == true",
			code: `package main

func example() {
	var enabled bool
	if enabled == true {
		println("enabled")
	}
}
`,
			expectMatch: true,
			suggestion:  "Use 'x' instead of 'x == true'",
		},
		{
			name: "x == false",
			code: `package main

func example() {
	var disabled bool
	if disabled == false {
		println("not disabled")
	}
}
`,
			expectMatch: true,
			suggestion:  "Use '!x' instead of 'x == false'",
		},
		{
			name: "x != true",
			code: `package main

func example() {
	var active bool
	if active != true {
		println("inactive")
	}
}
`,
			expectMatch: true,
			suggestion:  "Use '!x' instead of 'x != true'",
		},
		{
			name: "x != false",
			code: `package main

func example() {
	var valid bool
	if valid != false {
		println("valid")
	}
}
`,
			expectMatch: true,
			suggestion:  "Use 'x' instead of 'x != false'",
		},
		{
			name: "true == x",
			code: `package main

func example() {
	var enabled bool
	if true == enabled {
		println("enabled")
	}
}
`,
			expectMatch: true,
			suggestion:  "Use 'x' instead of 'x == true'",
		},
		{
			name: "false != x",
			code: `package main

func example() {
	var valid bool
	if false != valid {
		println("valid")
	}
}
`,
			expectMatch: true,
			suggestion:  "Use 'x' instead of 'x != false'",
		},
		{
			name: "simple boolean condition",
			code: `package main

func example() {
	var enabled bool
	if enabled {
		println("enabled")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "negated boolean",
			code: `package main

func example() {
	var disabled bool
	if !disabled {
		println("not disabled")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "comparison with variable",
			code: `package main

func example() {
	var a, b bool
	if a == b {
		println("equal")
	}
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createBoolCompareContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "bool_compare", violations[0].Context["pattern"])
				if tt.suggestion != "" {
					assert.Equal(t, tt.suggestion, violations[0].Suggestion)
				}
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createBoolCompareContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitBoolCompareLines(code),
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

func splitBoolCompareLines(s string) []string {
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
