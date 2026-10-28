package patternkit

import (
	"go/ast"
	"go/types"
)

// RootedInParam reports an expression reading a parameter (b.Changes, wallet).
func RootedInParam(info *types.Info, expr ast.Expr, params map[types.Object]bool) bool {
	for {
		switch e := ast.Unparen(expr).(type) {
		case *ast.Ident:
			return params[info.ObjectOf(e)]
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		default:
			return false
		}
	}
}
