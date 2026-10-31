package patternkit

import "go/ast"

// CalleeIdent returns the identifier at the end of a direct or selector call.
func CalleeIdent(call *ast.CallExpr) *ast.Ident {
	if call == nil {
		return nil
	}
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		return fun
	case *ast.SelectorExpr:
		return fun.Sel
	default:
		return nil
	}
}
