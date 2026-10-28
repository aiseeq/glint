package patternkit

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// IsLoggerStmt reports a statement that is a bare logger call at any level.
func IsLoggerStmt(stmt ast.Stmt) bool {
	exprStmt, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	return ok && helpers.IsLoggerCall(call)
}

// HasResponseWriterParam reports whether any parameter is an
// http.ResponseWriter — such functions report failures via the response.
func HasResponseWriterParam(params *ast.FieldList) bool {
	if params == nil {
		return false
	}
	for _, field := range params.List {
		if sel, ok := field.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "ResponseWriter" {
			return true
		}
	}
	return false
}

// ForEachOwnStatementList visits every statement list (blocks, case bodies)
// of the function body, pruning nested function literals.
func ForEachOwnStatementList(body *ast.BlockStmt, visit func([]ast.Stmt)) {
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

// IsWriteCall reports a method call whose name starts with a write verb.
func IsWriteCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return helpers.IsWriteName(sel.Sel.Name)
}

// IsZeroValueExpr matches "", 0, 0.0, nil and empty composite literals.
func IsZeroValueExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Value == `""` || e.Value == "0" || e.Value == "0.0" || e.Value == "``"
	case *ast.Ident:
		return e.Name == "nil"
	case *ast.CompositeLit:
		return len(e.Elts) == 0
	}
	return false
}
