package patternkit

import (
	"go/ast"
)

// LastIsReturn reports a block ending in a return.
func LastIsReturn(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	_, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	return ok
}
