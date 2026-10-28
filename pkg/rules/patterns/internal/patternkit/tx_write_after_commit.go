package patternkit

import (
	"go/ast"
)

// StatementCall is the call a statement makes at its top: an expression
// statement, the right side of an assignment, the init of an if.
func StatementCall(stmt ast.Stmt) *ast.CallExpr {
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		call, _ := s.X.(*ast.CallExpr)
		return call
	case *ast.AssignStmt:
		if len(s.Rhs) == 1 {
			call, _ := s.Rhs[0].(*ast.CallExpr)
			return call
		}
	case *ast.IfStmt:
		if s.Init != nil {
			return StatementCall(s.Init)
		}
	}
	return nil
}
