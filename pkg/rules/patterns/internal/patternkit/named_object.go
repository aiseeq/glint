package patternkit

import (
	"go/ast"
	"go/types"
)

// NamedObject is the object a function expression names: the function or
// variable of an identifier, the selected function, method or field of a
// selector. go/types records a selection's object as the use of its name, so
// Uses answers for both. Any other expression names nothing.
func NamedObject(info *types.Info, expr ast.Expr) types.Object {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return info.Uses[e]
	case *ast.SelectorExpr:
		return info.Uses[e.Sel]
	}
	return nil
}
