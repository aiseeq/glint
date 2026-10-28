package patternkit

import (
	"go/ast"
)

// AssignsName reports whether the assignment binds the named variable.
func AssignsName(assign *ast.AssignStmt, name string) bool {
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name == name {
			return true
		}
	}
	return false
}

// AssignedCall returns the call on the right-hand side of an assignment.
func AssignedCall(assign *ast.AssignStmt) *ast.CallExpr {
	if len(assign.Rhs) != 1 {
		return nil
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil
	}
	return call
}
