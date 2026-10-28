package patternkit

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// ExecuteChecked returns the call of a statement whose error the next branch
// tests — if err := call; err != nil {...}, or err := call followed by
// if err != nil {...} — with that branch.
func ExecuteChecked(list []ast.Stmt, i int, stmt ast.Stmt) (*ast.CallExpr, *ast.BlockStmt) {
	if check, ok := stmt.(*ast.IfStmt); ok && check.Init != nil {
		if call := StmtCall(check.Init); call != nil && checksErrNotNil(check.Cond) {
			return call, check.Body
		}
		return nil, nil
	}
	call := StmtCall(stmt)
	if call == nil || i+1 >= len(list) {
		return nil, nil
	}
	check, ok := list[i+1].(*ast.IfStmt)
	if !ok || check.Init != nil || !checksErrNotNil(check.Cond) {
		return nil, nil
	}
	return call, check.Body
}

// StmtCall returns the call of `err := call` or `err = call`.
func StmtCall(stmt ast.Stmt) *ast.CallExpr {
	if assign, ok := stmt.(*ast.AssignStmt); ok {
		return AssignedCall(assign)
	}
	return nil
}

// checksErrNotNil reports a condition `<ident> != nil`.
func checksErrNotNil(cond ast.Expr) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ || !helpers.IsNilIdent(ast.Unparen(bin.Y)) {
		return false
	}
	_, ok = ast.Unparen(bin.X).(*ast.Ident)
	return ok
}
