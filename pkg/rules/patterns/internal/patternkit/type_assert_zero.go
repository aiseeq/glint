package patternkit

import (
	"go/ast"
)

// ForEachStmtList calls visit with every statement list of a body, outside
// function literals.
func ForEachStmtList(body *ast.BlockStmt, visit func([]ast.Stmt)) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.BlockStmt:
			visit(node.List)
		case *ast.CaseClause:
			visit(node.Body)
		case *ast.CommClause:
			visit(node.Body)
		}
		return true
	})
}
