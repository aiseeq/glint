package patternkit

import (
	"go/ast"
	"go/types"
)

// IsBuiltinCall reports whether the call is to a Go builtin.
func IsBuiltinCall(info *types.Info, call *ast.CallExpr) bool {
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	_, builtin := info.Uses[ident].(*types.Builtin)
	return builtin
}
