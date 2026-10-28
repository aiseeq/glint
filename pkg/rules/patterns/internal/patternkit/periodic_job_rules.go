package patternkit

import (
	"go/ast"
	"go/types"
)

// TakesContext reports a call handed a context.Context.
func TakesContext(info *types.Info, call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if IsNamedType(info.TypeOf(arg), "context", "Context") {
			return true
		}
	}
	return false
}
