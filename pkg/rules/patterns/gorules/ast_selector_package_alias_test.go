package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestASTSelectorPackageResolvedByAliasRule(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{
			name: "selector name reaches same package map parameter",
			files: map[string]string{"convert.go": `package sample
import (
 "go/ast"
 "strings"
)
var packageMap = map[string]string{"alpha": "alpha"}
func lookup(candidate string) string { return packageMap[candidate] }
func adapt(candidate string) string { local := strings.ToLower(candidate); return lookup(local) }
func convert(node ast.Node) string {
 switch node := node.(type) {
 case *ast.SelectorExpr:
  if ident, ok := node.X.(*ast.Ident); ok { return adapt(ident.Name) }
 }
 return ""
}`},
			want: 1,
		},
		{
			name: "successful selector assertion reaches string comparison",
			files: map[string]string{"convert.go": `package sample
import "go/ast"
func convert(node ast.Node) bool {
 if selector, ok := node.(*ast.SelectorExpr); ok {
  if ident, ok := selector.X.(*ast.Ident); ok { return ident.Name == "alpha" }
 }
 return false
}`},
			want: 1,
		},
		{
			name: "imports are used to build package resolution map",
			files: map[string]string{"convert.go": `package sample
import "go/ast"
var packageMap = map[string]string{}
func populate(file *ast.File) { for _, spec := range file.Imports { name := spec.Path.Value; if spec.Name != nil { name = spec.Name.Name }; packageMap[name] = spec.Path.Value } }
func lookup(candidate string) string { return packageMap[candidate] }
func convert(node ast.Node, file *ast.File) string {
 populate(file)
 switch node := node.(type) {
 case *ast.SelectorExpr:
  if ident, ok := node.X.(*ast.Ident); ok { return lookup(ident.Name) }
 }
 return ""
}`},
			want: 0,
		},
		{
			name: "types package name resolution is used",
			files: map[string]string{"convert.go": `package sample
import (
 "go/ast"
 "go/types"
)
var packageMap = map[string]string{}
func lookup(candidate string, info *types.Info, ident *ast.Ident) string {
 if _, ok := info.Uses[ident].(*types.PkgName); ok { return candidate }
 return packageMap[candidate]
}
func convert(node ast.Node, info *types.Info) string {
 switch node := node.(type) {
 case *ast.SelectorExpr:
  if ident, ok := node.X.(*ast.Ident); ok { return lookup(ident.Name, info, ident) }
 }
 return ""
}`},
			want: 0,
		},
		{
			name: "selector only used for printing",
			files: map[string]string{"convert.go": `package sample
import (
 "fmt"
 "go/ast"
)
func convert(node ast.Node) string {
 switch node := node.(type) {
 case *ast.SelectorExpr:
  if ident, ok := node.X.(*ast.Ident); ok { return fmt.Sprintf("%s.%s", ident.Name, node.Sel.Name) }
 }
 return ""
}`},
			want: 0,
		},
		{
			name: "selector named function does not index a map",
			files: map[string]string{"convert.go": `package sample
import "go/ast"
func convertSelector(candidate string) string { return candidate }
func convert(node ast.Node) string {
 switch node := node.(type) {
 case *ast.SelectorExpr:
  if ident, ok := node.X.(*ast.Ident); ok { return convertSelector(ident.Name) }
 }
 return ""
}`},
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			violations, err := NewASTSelectorPackageResolvedByAliasRule().AnalyzeGoProject(rulestest.Project(t, tc.files))
			require.NoError(t, err)
			require.Len(t, violations, tc.want)
			if tc.want > 0 {
				require.Equal(t, core.SeverityMedium, violations[0].Severity)
			}
		})
	}
}
