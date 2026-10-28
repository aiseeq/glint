package patternkit

import (
	"go/ast"
	"go/types"
)

// IsObjectIdent reports an identifier naming obj.
func IsObjectIdent(info *types.Info, expr ast.Expr, obj types.Object) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && info.Uses[ident] == obj
}
