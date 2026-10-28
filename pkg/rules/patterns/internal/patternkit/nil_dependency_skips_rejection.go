package patternkit

import (
	"go/ast"
	"strings"
)

// RejectsRequest reports a branch whose own statements return a non-nil
// error or answer the request with an HTTP error; a failure of nested work
// (if err != nil { return err }) is not the branch rejecting.
func RejectsRequest(body *ast.BlockStmt) bool {
	found := false
	for _, stmt := range body.List {
		found = found || rejectingStatement(stmt)
	}
	return found
}

// rejectingStatement reports a return of a non-nil error or an http.Error
// call.
func rejectingStatement(stmt ast.Stmt) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit, *ast.BlockStmt, *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) > 0 {
				last := ast.Unparen(node.Results[len(node.Results)-1])
				if ident, ok := last.(*ast.Ident); !ok || ident.Name == "err" || strings.HasPrefix(ident.Name, "Err") {
					_, literal := last.(*ast.BasicLit)
					found = found || (!literal && !IsTrueLiteral(last) && !IsFalseLiteral(last))
				}
			}
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
