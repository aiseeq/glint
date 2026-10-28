package patternkit

import (
	"go/ast"
)

// FuncExprName returns the name a function expression spells: f, x.f,
// pkg.f, f[T].
func FuncExprName(fun ast.Expr) string {
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.IndexExpr:
		return FuncExprName(f.X)
	case *ast.IndexListExpr:
		return FuncExprName(f.X)
	}
	return ""
}
