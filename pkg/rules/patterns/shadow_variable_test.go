package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShadowVariableRule_Metadata(t *testing.T) {
	rule := NewShadowVariableRule()

	assert.Equal(t, "shadow-variable", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestShadowVariableRule_Detection(t *testing.T) {
	rule := NewShadowVariableRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "shadow parameter with meaningful name",
			code: `package main

func example(user *User) {
	if true {
		user := getAdmin()
		_ = user
	}
}

func getAdmin() *User { return nil }
type User struct{}
`,
			expectMatch: true,
		},
		{
			name: "err shadow is allowed",
			code: `package main

func example(err error) {
	if true {
		err := doSomething()
		_ = err
	}
}

func doSomething() error { return nil }
`,
			expectMatch: false, // err is safe to shadow
		},
		{
			name: "no shadow",
			code: `package main

func example(err error) {
	if true {
		err2 := doSomething()
		_ = err2
	}
}

func doSomething() error { return nil }
`,
			expectMatch: false,
		},
		{
			name: "shadow in range with meaningful name",
			code: `package main

func example(item *Item) {
	items := []*Item{{}, {}}
	for _, item := range items {
		_ = item
	}
}

type Item struct{}
`,
			expectMatch: true,
		},
		{
			name: "i shadow in range is allowed",
			code: `package main

func example(i int) {
	items := []int{1, 2, 3}
	for i := range items {
		_ = i
	}
}
`,
			expectMatch: false, // i is safe to shadow
		},
		{
			name: "shadow receiver",
			code: `package main

type T struct{}

func (t *T) Method() {
	t := "shadowed"
	_ = t
}
`,
			expectMatch: true,
		},
		{
			name: "underscore ignored",
			code: `package main

func example(_ error) {
	_ = doSomething()
}

func doSomething() error { return nil }
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createShadowContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "shadow_variable", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestShadowVariableRule_TestFilesExcluded(t *testing.T) {
	rule := NewShadowVariableRule()

	code := `package main

func example(err error) {
	err := doSomething()
	_ = err
}

func doSomething() error { return nil }
`
	ctx := createShadowContext(t, "service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

// Helper function
func createShadowContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitShadowLines(code),
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

func splitShadowLines(s string) []string {
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
