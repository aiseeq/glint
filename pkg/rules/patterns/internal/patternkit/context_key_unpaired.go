package patternkit

import (
	"go/ast"
)

// KeyName returns the identifier a key expression names: Key or pkg.Key.
func KeyName(key ast.Expr) string {
	switch expr := ast.Unparen(key).(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		return expr.Sel.Name
	}
	return ""
}
