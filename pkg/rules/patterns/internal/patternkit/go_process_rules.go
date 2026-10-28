package patternkit

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// ReturnsNonNilError reports whether the branch returns something other than
// nil as its last result, or panics or exits.
func ReturnsNonNilError(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) > 0 && !helpers.IsNilIdent(node.Results[len(node.Results)-1]) {
				found = true
			}
		case *ast.CallExpr:
			if IsIdent(node.Fun, "panic") || strings.HasSuffix(types.ExprString(node.Fun), "Exit") || strings.HasSuffix(types.ExprString(node.Fun), "Fatal") {
				found = true
			}
		}
		return !found
	})
	return found
}
