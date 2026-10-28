package patternkit

import (
	"go/ast"
	"go/types"
)

// IsIdentOf reports the variable itself.
func IsIdentOf(info *types.Info, expr ast.Expr, obj types.Object) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && info.ObjectOf(ident) == obj
}
