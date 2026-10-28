package patternkit

import (
	"go/ast"
	"go/types"
)

// RequestBody returns the source of the request expression when expr is
// <request>.Body of an *http.Request, "" otherwise.
func RequestBody(info *types.Info, expr ast.Expr) string {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Body" || !IsPointerToNamedType(info.TypeOf(sel.X), "net/http", "Request") {
		return ""
	}
	return types.ExprString(sel.X)
}
