package patternkit

import (
	"go/ast"
	"go/types"
)

// ValueAssignments maps the local variables of a body to every expression
// assigned to them one to one (v := e, v = e, var v = e).
func ValueAssignments(info *types.Info, body *ast.BlockStmt) map[types.Object][]ast.Expr {
	assigned := make(map[types.Object][]ast.Expr)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
					if obj := info.ObjectOf(ident); obj != nil {
						assigned[obj] = append(assigned[obj], node.Rhs[i])
					}
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) != len(node.Values) {
				return true
			}
			for i, name := range node.Names {
				if obj := info.ObjectOf(name); obj != nil {
					assigned[obj] = append(assigned[obj], node.Values[i])
				}
			}
		}
		return true
	})
	return assigned
}
