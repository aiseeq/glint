package gorules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestCheckedCatchAllWordInRegexpPattern(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "gen.go", "package gen\nimport \"regexp\"\nvar re = regexp.MustCompile(`\\bunknown\\b`)\n", 0)
	require.NoError(t, err)

	require.True(t, checkedCatchAllWordsAST([]*ast.File{file})["unknown"])
}

func TestCodegenCatchAllTypeWithoutReport(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{name: "default catch-all", code: `package sample
import "go/ast"
type Type int
type Mapping struct { Output string }
var mappings = map[Type]Mapping{}
func convert(t Type, _ ast.Expr) string {
	mapping, ok := mappings[t]
	if !ok { return "any" }
	return mapping.Output
}`, want: 1},
		{name: "package-wide catch-all", code: `package sample
import "go/ast"
var _ ast.Expr
type Mapping struct { DefaultType string }
var mappings = map[string]Mapping{"alpha": {DefaultType: "unknown"}}`, want: 1},
		{name: "reported fallback", code: `package sample
import "go/ast"
type Type int
type Mapping struct { Output string }
var mappings = map[Type]Mapping{}
func convert(t Type, _ ast.Expr) (string, error) {
	mapping, ok := mappings[t]
	if !ok { return "unknown", ErrUnsupported }
	return mapping.Output, nil
}
var ErrUnsupported error`, want: 0},
		{name: "ordinary registry lookup", code: `package registry
type Key string
type Meta struct{ Category string }
var registry = map[Key]Meta{}
func (k Key) Category() string {
	if m, ok := registry[k]; ok { return m.Category }
	return "unknown"
}`, want: 0},
		{name: "ordinary slice lookup", code: `package stats
var outcomes = map[string][]string{}
func result(tool, out string) string {
	for _, r := range outcomes[tool] { if r == out { return r } }
	return "unknown"
}`, want: 0},
		{name: "checked unknown but unchecked any", code: "package gen\nimport (\"go/ast\"; \"regexp\")\nvar catchAll = regexp.MustCompile(`\\bunknown\\b`)\nvar mappings = map[string]Mapping{\"alpha\": {DefaultType: \"unknown\"}, \"beta\": {DefaultType: \"any\"}}\ntype Mapping struct{ DefaultType string }\nfunc convert(pkg string, _ ast.Expr) string {\n\tm, ok := mappings[pkg]\n\tif !ok { return \"unknown\" }\n\treturn m.DefaultType\n}\nfunc check(out string) error { if catchAll.MatchString(out) { return errUnknown }; return nil }\nvar errUnknown error", want: 1},
		{name: "specific default", code: `package sample
func convert(t Type) string { switch t { default: return "Record" } }
type Type int`, want: 0},
		{name: "specific package mapping", code: `package sample
type Mapping struct { DefaultType string }
var mappings = map[string]Mapping{"alpha": {DefaultType: "{{TYPE_NAME}}"}}`, want: 0},
		{name: "unrelated any constant", code: `package sample
const fallback = "any"`, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCodegenCatchAllTypeWithoutReportRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{"sample/sample.go": tt.code}))
			require.NoError(t, err)
			require.Len(t, got, tt.want)
		})
	}
}
