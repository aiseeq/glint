package helpers

import (
	"go/ast"
	"go/types"
)

// IsNilValue reports the nil identifier or a conversion of it, (*T)(nil).
// Without type information only a conversion to a written pointer type is
// recognized: F(nil) may be a call.
func IsNilValue(expr ast.Expr, info *types.Info) bool {
	expr = ast.Unparen(expr)
	if isNil(expr) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !isNil(ast.Unparen(call.Args[0])) {
		return false
	}
	if info != nil {
		tv, ok := info.Types[call.Fun]
		return ok && tv.IsType()
	}
	paren, ok := call.Fun.(*ast.ParenExpr)
	if !ok {
		return false
	}
	_, ok = paren.X.(*ast.StarExpr)
	return ok
}

func isNil(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}
