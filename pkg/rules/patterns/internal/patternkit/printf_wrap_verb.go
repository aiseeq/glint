package patternkit

import (
	"go/ast"
)

// CalledName is the name of the called function or method.
func CalledName(call *ast.CallExpr) string {
	return FuncExprName(call.Fun)
}
