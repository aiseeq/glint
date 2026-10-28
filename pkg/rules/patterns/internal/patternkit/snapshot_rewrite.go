package patternkit

import (
	"go/ast"
	"go/types"
)

// RootObject returns the variable a selector chain starts from: s in s.hist.
func RootObject(info *types.Info, e ast.Expr) types.Object {
	for {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			return info.Uses[x]
		case *ast.SelectorExpr:
			e = x.X
		default:
			return nil
		}
	}
}
