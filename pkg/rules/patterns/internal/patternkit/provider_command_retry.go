package patternkit

import (
	"go/ast"
)

// BlockBranches reports whether a statement of the block, or of a block or if
// nested in it, satisfies match.
func BlockBranches(block *ast.BlockStmt, match func(ast.Stmt) bool) bool {
	for _, stmt := range block.List {
		switch current := stmt.(type) {
		case *ast.BlockStmt:
			if BlockBranches(current, match) {
				return true
			}
		case *ast.IfStmt:
			if BlockBranches(current.Body, match) {
				return true
			}
			if elseBlock, ok := current.Else.(*ast.BlockStmt); ok && BlockBranches(elseBlock, match) {
				return true
			}
		default:
			if match(stmt) {
				return true
			}
		}
	}
	return false
}

func CalledFunctionName(expression ast.Expr) string {
	switch function := ast.Unparen(expression).(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

func IsTrueLiteral(expression ast.Expr) bool {
	ident, ok := ast.Unparen(expression).(*ast.Ident)
	return ok && ident.Name == "true"
}
