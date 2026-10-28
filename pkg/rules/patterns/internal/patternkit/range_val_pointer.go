package patternkit

import (
	"go/ast"
	"go/types"
)

func IsAppendCall(call *ast.CallExpr, info *types.Info) bool {
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	builtin, ok := info.Uses[ident].(*types.Builtin)
	return ok && builtin.Name() == "append"
}
