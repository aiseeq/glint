package patternkit

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

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

// IsZeroValueExpr matches zero literals and values whose type information
// proves that they are zero.
func IsZeroValueExpr(expr ast.Expr, typeInfo ...*types.Info) bool {
	expr = ast.Unparen(expr)
	if len(typeInfo) > 0 && typeInfo[0] != nil {
		if value, ok := typeInfo[0].Types[expr]; ok && value.Value != nil {
			return isZeroConstant(value.Value)
		}
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return e.Value == `""` || e.Value == "``"
		}
		value := constant.MakeFromLiteral(e.Value, e.Kind, 0)
		return isZeroConstant(value)
	case *ast.Ident:
		return e.Name == "nil"
	case *ast.CompositeLit:
		return len(e.Elts) == 0
	case *ast.UnaryExpr:
		value := zeroConstant(e)
		return isZeroConstant(value)
	case *ast.CallExpr:
		value := zeroConstant(e)
		return isZeroConstant(value)
	}
	return false
}

func isZeroConstant(value constant.Value) bool {
	if value == nil {
		return false
	}
	switch value.Kind() {
	case constant.Bool:
		return !constant.BoolVal(value)
	case constant.String:
		return constant.StringVal(value) == ""
	case constant.Int, constant.Float:
		return constant.Sign(value) == 0
	case constant.Complex:
		return constant.Sign(constant.Real(value)) == 0 && constant.Sign(constant.Imag(value)) == 0
	}
	return false
}

func zeroConstant(expr ast.Expr) constant.Value {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return constant.MakeFromLiteral(e.Value, e.Kind, 0)
	case *ast.UnaryExpr:
		if e.Op != token.ADD && e.Op != token.SUB && e.Op != token.XOR {
			return nil
		}
		value := zeroConstant(e.X)
		if value == nil || value.Kind() == constant.Unknown {
			return nil
		}
		return constant.UnaryOp(e.Op, value, 0)
	case *ast.CallExpr:
		if len(e.Args) == 1 {
			if ident, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
				if typ, ok := types.Universe.Lookup(ident.Name).(*types.TypeName); ok {
					if _, ok := typ.Type().Underlying().(*types.Basic); ok {
						return zeroConstant(e.Args[0])
					}
				}
			}
		}
	}
	return nil
}
