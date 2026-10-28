package patternkit

import (
	"go/ast"
)

// Terminates reports whether a block always leaves the enclosing flow: тогда проверка
// `if x == nil { ... }` работает как гарантия для всего кода ниже.
func Terminates(block *ast.BlockStmt) bool {
	if block == nil || len(block.List) == 0 {
		return false
	}
	switch last := block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return last.Tok.String() == "continue" || last.Tok.String() == "break"
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		return name == "panic" || name == "Fatal" || name == "Fatalf" || name == "Exit"
	default:
		return false
	}
}
