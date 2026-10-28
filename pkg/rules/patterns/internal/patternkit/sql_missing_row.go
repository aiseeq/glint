package patternkit

import (
	"go/ast"
)

// ErrorFunctions returns the bodies of the file's functions whose last
// result is an error.
func ErrorFunctions(file *ast.File) []*ast.BlockStmt {
	var bodies []*ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		var typ *ast.FuncType
		var body *ast.BlockStmt
		switch f := n.(type) {
		case *ast.FuncDecl:
			typ, body = f.Type, f.Body
		case *ast.FuncLit:
			typ, body = f.Type, f.Body
		default:
			return true
		}
		if body == nil || typ.Results == nil || len(typ.Results.List) == 0 {
			return true
		}
		if id, ok := typ.Results.List[len(typ.Results.List)-1].Type.(*ast.Ident); ok && id.Name == "error" {
			bodies = append(bodies, body)
		}
		return true
	})
	return bodies
}

// BlockLeaves reports a block that returns or jumps: the flow after it
// depends on the count.
func BlockLeaves(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		switch stmt.(type) {
		case *ast.ReturnStmt, *ast.BranchStmt:
			return true
		}
	}
	return false
}
