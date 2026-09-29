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
			untyped := rule.AnalyzeFile(ctx)
			typed := runRuleOnFiles(t, rule, map[string]string{"svc/service.go": tt.code})

			for mode, violations := range map[string][]*core.Violation{"untyped": untyped, "typed": typed} {
				if tt.expectMatch {
					require.NotEmpty(t, violations, "%s: expected violation for: %s", mode, tt.name)
					assert.Equal(t, "bool_compare", violations[0].Context["pattern"])
					if tt.suggestion != "" {
						assert.Equal(t, tt.suggestion, violations[0].Suggestion)
					}
				} else {
					assert.Empty(t, violations, "%s: expected no violations for: %s", mode, tt.name)
				}
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

// Repro from glint's own fixer: a value read out of a map[string]any has to be
// compared against true — it cannot be used as a condition on its own.
func TestBoolCompareIgnoresNonBoolOperand(t *testing.T) {
	code := `package svc

type Violation struct {
	Context map[string]any
}

func skip(v *Violation) bool {
	if exception, ok := v.Context["exception"]; ok && exception == true {
		return true
	}
	return false
}
`
	ctx := createBoolCompareContext(t, "svc.go", code)
	violations := NewBoolCompareRule().AnalyzeFile(ctx)
	if len(violations) != 0 {
		t.Fatalf("expected no findings, got %d: %s", len(violations), violations[0].Suggestion)
	}
}

func TestBoolCompareStillReportsBoolVariable(t *testing.T) {
	code := `package svc

func check(enabled bool) bool {
	if enabled == true {
		return true
	}
	return false
}
`
	ctx := createBoolCompareContext(t, "svc.go", code)
	if violations := NewBoolCompareRule().AnalyzeFile(ctx); len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
}

// An operand declared in a sibling file is judged by its declared type. An
// undeclared name used to count as a bool, and the autofix turned
// `mode == true` on an any into `mode`, which does not compile.
func TestBoolCompareUsesDeclaredTypeFromSiblingFile(t *testing.T) {
	violations := runRuleOnFiles(t, NewBoolCompareRule(), map[string]string{
		"flags/state.go": `package flags

var mode any = true

var settings = map[string]any{"debug": true}
`,
		"flags/check.go": `package flags

func on() bool {
	return mode == true
}

func debug() bool {
	return settings["debug"] == true
}
`,
	})
	require.Empty(t, violations)
}

// A bool declared in a sibling file, a bool field and a bool call result are
// still redundant comparisons.
func TestBoolCompareReportsBoolFromSiblingFile(t *testing.T) {
	violations := runRuleOnFiles(t, NewBoolCompareRule(), map[string]string{
		"flags/state.go": `package flags

var verbose bool

type Options struct{ Quiet bool }

func enabled() bool { return verbose }
`,
		"flags/check.go": `package flags

func loud(o Options) bool {
	return verbose == true && o.Quiet == false && enabled() != false
}
`,
	})
	require.Len(t, violations, 3)
}

// Without type information an operand the file does not declare is unknown:
// the rule stays silent rather than count it as a bool.
func TestBoolCompareUntypedUndeclaredOperandIsSilent(t *testing.T) {
	violations := runRuleOnBrokenFiles(t, NewBoolCompareRule(), map[string]string{
		"flags/state.go": "package flags\n\nvar mode any = true\n",
		"flags/check.go": `package flags

func on() bool {
	return mode == true
}

func broken() int { return "not an int" }
`,
	})
	require.Empty(t, violations)
}
