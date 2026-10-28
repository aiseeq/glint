package patternkit

import (
	"go/ast"
)

// LastName is the name of x, a.b.x or a.x().
func LastName(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.CallExpr:
		return LastName(e.Fun)
	}
	return ""
}
