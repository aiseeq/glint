package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReturnNilErrorRule_Metadata(t *testing.T) {
	rule := NewReturnNilErrorRule()

	assert.Equal(t, "return-nil-error", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestReturnNilErrorRule_Detection(t *testing.T) {
	rule := NewReturnNilErrorRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "nil nil return",
			code: `package main

func example() (*User, error) {
	if something {
		return nil, nil
	}
	return &User{}, nil
}
`,
			expectMatch: true,
		},
		{
			name: "proper error return",
			code: `package main

import "errors"

func example() (*User, error) {
	if something {
		return nil, errors.New("error")
	}
	return &User{}, nil
}
`,
			expectMatch: false,
		},
		{
			name: "proper value return",
			code: `package main

func example() (*User, error) {
	return &User{}, nil
}
`,
			expectMatch: false,
		},
		{
			name: "single return value",
			code: `package main

func example() error {
	return nil
}
`,
			expectMatch: false,
		},
		{
			name: "three return values with nil nil",
			code: `package main

func example() (int, *User, error) {
	return 0, nil, nil
}
`,
			expectMatch: false, // Only checks 2-value returns
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createReturnNilContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "nil_nil_return", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestReturnNilErrorRule_TestFilesExcluded(t *testing.T) {
	rule := NewReturnNilErrorRule()

	code := `package main

func example() (*User, error) {
	return nil, nil
}
`
	ctx := createReturnNilContext(t, "service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

// Helper function
func createReturnNilContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitReturnNilLines(code),
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

func splitReturnNilLines(s string) []string {
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
