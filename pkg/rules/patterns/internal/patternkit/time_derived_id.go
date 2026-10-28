package patternkit

import (
	"go/ast"
)

// AssignedName returns the name an assignment writes: x or s.X.
func AssignedName(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}
