package patternkit

import (
	"go/ast"
)

// FunctionBodies returns the bodies of a file's functions and function
// literals; each is analyzed on its own.
func FunctionBodies(file *ast.File) []*ast.BlockStmt {
	var bodies []*ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncDecl:
			if n.Body != nil {
				bodies = append(bodies, n.Body)
			}
		case *ast.FuncLit:
			bodies = append(bodies, n.Body)
		}
		return true
	})
	return bodies
}
