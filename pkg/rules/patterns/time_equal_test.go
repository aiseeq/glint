package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimeEqualRule_Metadata(t *testing.T) {
	rule := NewTimeEqualRule()

	assert.Equal(t, "time-equal", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestTimeEqualRule_Detection(t *testing.T) {
	rule := NewTimeEqualRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "time.Time == comparison",
			code: `package main

import "time"

func example(t1, t2 time.Time) bool {
	return t1 == t2
}
`,
			expectMatch: true,
		},
		{
			name: "time.Time != comparison",
			code: `package main

import "time"

func example(t1, t2 time.Time) bool {
	return t1 != t2
}
`,
			expectMatch: true,
		},
		{
			name: "time.Now() comparison",
			code: `package main

import "time"

func example() bool {
	t := time.Now()
	return t == time.Now()
}
`,
			expectMatch: true,
		},
		{
			name: "proper .Equal() usage",
			code: `package main

import "time"

func example(t1, t2 time.Time) bool {
	return t1.Equal(t2)
}
`,
			expectMatch: false,
		},
		{
			name: "field comparison",
			code: `package main

import "time"

type Event struct {
	CreatedAt time.Time
}

func example(e1, e2 Event) bool {
	return e1.CreatedAt == e2.CreatedAt
}
`,
			expectMatch: true,
		},
		{
			name: "no time import",
			code: `package main

func example() bool {
	t1 := 1
	t2 := 2
	return t1 == t2
}
`,
			expectMatch: false,
		},
		{
			name: "string comparison",
			code: `package main

import "time"

func example() bool {
	s1 := "hello"
	s2 := "world"
	_ = time.Now() // just to have time import
	return s1 == s2
}
`,
			expectMatch: false,
		},
		{
			name: "type inference from var declaration",
			code: `package main

import "time"

func example() bool {
	var created time.Time
	var updated time.Time
	return created == updated
}
`,
			expectMatch: true,
		},
		{
			name: "type inference from time.Parse",
			code: `package main

import "time"

func example() bool {
	parsed, _ := time.Parse("2006-01-02", "2025-01-08")
	now := time.Now()
	return parsed == now
}
`,
			expectMatch: true,
		},
		{
			name: "custom named time variable",
			code: `package main

import "time"

func example() bool {
	var myTimestamp time.Time
	var anotherTime time.Time
	return myTimestamp == anotherTime
}
`,
			expectMatch: true, // Type inference detects time.Time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTimeEqualContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "time_equal", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createTimeEqualContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitTimeEqualLines(code),
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

func splitTimeEqualLines(s string) []string {
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
