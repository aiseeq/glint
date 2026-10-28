package patternkit

import (
	"go/ast"
	"go/types"
)

// FromClock reports time.Now() or a method chain on it (UTC, In, Add...).
func FromClock(info *types.Info, expr ast.Expr) bool {
	for {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if fn, ok := info.Uses[sel.Sel].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "time" && fn.Name() == "Now" {
			return true
		}
		expr = sel.X
	}
}
