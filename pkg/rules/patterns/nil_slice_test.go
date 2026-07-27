package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNilSliceRule_Metadata(t *testing.T) {
	rule := NewNilSliceRule()

	assert.Equal(t, "nil-slice", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityLow, rule.DefaultSeverity())
}

func TestNilSliceRule_Detection(t *testing.T) {
	rule := NewNilSliceRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "slice == nil",
			code: `package main

func example() {
	var items []string
	if items == nil {
		println("empty")
	}
}
`,
			expectMatch: true,
		},
		{
			name: "slice != nil",
			code: `package main

func example() {
	var results []int
	if results != nil {
		println("has results")
	}
}
`,
			expectMatch: true,
		},
		{
			name: "nil == slice",
			code: `package main

func example() {
	var items []string
	if nil == items {
		println("empty")
	}
}
`,
			expectMatch: true,
		},
		{
			name: "len check instead",
			code: `package main

func example() {
	var items []string
	if len(items) == 0 {
		println("empty")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "non-slice nil check",
			code: `package main

func example() {
	var ptr *int
	if ptr == nil {
		println("nil pointer")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "plural pointer parameter is not a slice",
			code: `package main

import "math/big"

func amount(tokens *big.Int) {
	if tokens == nil {
		return
	}
}
`,
			expectMatch: false,
		},
		{
			name: "err nil check",
			code: `package main

func example() {
	var err error
	if err == nil {
		println("no error")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "field access slice keeps nil semantics",
			code: `package main

type Data struct {
	Items []string
}

func example() {
	var d Data
	if d.Items == nil {
		println("no items")
	}
}
`,
			expectMatch: false,
		},
		{
			name: "slice with List suffix - detected by type inference",
			code: `package main

func example() {
	var userList []string
	if userList == nil {
		println("empty")
	}
}
`,
			expectMatch: true, // Type inference detects it's a slice
		},
		{
			name: "make slice",
			code: `package main

func example() {
	data := make([]byte, 0)
	if data == nil {
		println("empty")
	}
}
`,
			expectMatch: false, // Conservative: make() inference not fully supported yet
		},
		{
			name: "function param slice",
			code: `package main

func example(myData []string) {
	if myData == nil {
		println("empty")
	}
}
`,
			expectMatch: true, // Type inference from function parameter
		},
		{
			name: "composite literal slice",
			code: `package main

func example() {
	nums := []int{1, 2, 3}
	if nums == nil {
		println("empty")
	}
}
`,
			expectMatch: true, // Type inference from composite literal
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createNilSliceContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "nil_slice_compare", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createNilSliceContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitNilSliceLines(code),
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

func splitNilSliceLines(s string) []string {
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

// Real repros from glint's own sources: a name from the "looks like a slice"
// list can just as well be a pointer or an unknown type. Guessing by name when
// the file actually declares the variable produced false positives.
func TestNilSliceIgnoresDeclaredVariablesOfUnknownType(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			name: "pointer field named results",
			code: `package svc

import "go/ast"

func hasSingleResult(fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil {
		return false
	}
	return len(results.List) == 1
}
`,
		},
		{
			name: "pointer parameter named fields",
			code: `package svc

import "go/ast"

func declare(fields *ast.FieldList) {
	if fields == nil {
		return
	}
	_ = fields.List
}
`,
		},
		{
			name: "regexp submatch keeps its documented nil contract",
			code: `package svc

import "regexp"

func find(pattern *regexp.Regexp, content string) string {
	matches := pattern.FindStringSubmatch(content)
	if matches == nil {
		return ""
	}
	return matches[0]
}
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := createNilSliceContext(t, "svc.go", tc.code)
			violations := NewNilSliceRule().AnalyzeFile(ctx)
			if len(violations) != 0 {
				t.Fatalf("expected no findings, got %d: %s", len(violations), violations[0].Suggestion)
			}
		})
	}
}

// A genuine nil-slice comparison must still be reported.
func TestNilSliceStillReportsDeclaredSlice(t *testing.T) {
	ctx := createNilSliceContext(t, "svc.go", `package svc

func process() int {
	items := []string{}
	if items == nil {
		return 0
	}
	return len(items)
}
`)

	violations := NewNilSliceRule().AnalyzeFile(ctx)
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
}
