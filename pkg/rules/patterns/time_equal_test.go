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
			name: "int64 Timestamp field comparison is not a time comparison",
			code: `package main

import "time"

type Event struct {
	Timestamp int64
}

func example(a, b Event) bool {
	_ = time.Now()
	return a.Timestamp == b.Timestamp
}
`,
			expectMatch: false,
		},
		{
			name: "string Date field comparison",
			code: `package main

import "time"

type FinancialTransaction struct {
	Date string
}

func example(tx FinancialTransaction) bool {
	_ = time.Now()
	return tx.Date == ""
}
`,
			expectMatch: false,
		},
		{
			name: "string date parameter shadows date time in another function",
			code: `package main

import "time"

func record(txDate string) bool {
	date, _ := time.Parse("2006-01-02", txDate)
	return date == time.Now()
}

func lookup(date string) bool {
	return date == ""
}
`,
			expectMatch: true,
		},
		{
			name: "string date parameter is not time comparison",
			code: `package main

import "time"

func record(txDate string) bool {
	date, _ := time.Parse("2006-01-02", txDate)
	_ = date
	return txDate == ""
}

func lookup(date string) bool {
	return date == ""
}
`,
			expectMatch: false,
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
			name: "io EOF sentinel comparison with time import",
			code: `package main

import (
	"io"
	"time"
)

func example(err error) bool {
	_ = time.Now()
	return err == io.EOF
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
			untyped := rule.AnalyzeFile(ctx)
			typed := runRuleOnFiles(t, rule, map[string]string{"svc/service.go": tt.code})

			for mode, violations := range map[string][]*core.Violation{"untyped": untyped, "typed": typed} {
				if tt.expectMatch {
					require.NotEmpty(t, violations, "%s: expected violation for: %s", mode, tt.name)
					assert.Equal(t, "time_equal", violations[0].Context["pattern"])
				} else {
					assert.Empty(t, violations, "%s: expected no violations for: %s", mode, tt.name)
				}
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

// A field or variable declared in a sibling file is judged by its declared
// type. The name fallback called an int64 CreatedAt a time.Time, and the
// suggested .Equal() does not compile on an int64.
func TestTimeEqualUsesDeclaredTypeFromSiblingFile(t *testing.T) {
	violations := runRuleOnFiles(t, NewTimeEqualRule(), map[string]string{
		"events/model.go": `package events

type Event struct {
	CreatedAt int64
}

var deadline, timestamp int64
`,
		"events/check.go": `package events

import "time"

func same(a, b Event) bool {
	_ = time.Now()
	return a.CreatedAt == b.CreatedAt
}

func expired() bool {
	return deadline == timestamp
}
`,
	})
	require.Empty(t, violations)
}

// A time.Time declared in a sibling file is still a time.Time, whatever the
// name of the field and whether or not the comparing file imports time.
func TestTimeEqualReportsTimeFieldFromSiblingFile(t *testing.T) {
	violations := runRuleOnFiles(t, NewTimeEqualRule(), map[string]string{
		"events/model.go": `package events

import "time"

type Event struct {
	At time.Time
}
`,
		"events/check.go": `package events

func same(a, b Event) bool {
	return a.At == b.At
}
`,
	})
	require.Len(t, violations, 1)
	assert.Equal(t, "events/check.go", violations[0].File)
}

// Without type information an operand the file does not declare is unknown:
// the rule stays silent rather than guess a time.Time from the name.
func TestTimeEqualUntypedUndeclaredOperandIsSilent(t *testing.T) {
	violations := runRuleOnBrokenFiles(t, NewTimeEqualRule(), map[string]string{
		"events/model.go": "package events\n\ntype Event struct {\n\tCreatedAt int64\n}\n\nvar timestamp int64\n",
		"events/check.go": `package events

import "time"

func same(a, b Event) bool {
	_ = time.Now()
	return a.CreatedAt == b.CreatedAt
}

func expired(deadline int64) bool {
	return deadline == timestamp
}

func broken() int { return "not an int" }
`,
	})
	require.Empty(t, violations)
}
