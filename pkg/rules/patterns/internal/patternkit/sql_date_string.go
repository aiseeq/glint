package patternkit

import (
	"go/ast"
	"go/types"
)

// SingleAssignment returns the value of a local variable assigned exactly
// once in the function, nil otherwise.
func SingleAssignment(info *types.Info, fn *ast.FuncDecl, v *types.Var) ast.Expr {
	var value ast.Expr
	count := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && info.ObjectOf(id) == v {
				count++
				if len(assign.Lhs) == len(assign.Rhs) {
					value = assign.Rhs[i]
				}
			}
		}
		return true
	})
	if count != 1 {
		return nil
	}
	return value
}
