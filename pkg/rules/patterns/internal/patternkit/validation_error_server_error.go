package patternkit

import (
	"go/ast"
	"go/token"
)

// Addressed returns x of &x, and expr itself otherwise.
func Addressed(expr ast.Expr) ast.Expr {
	if unary, ok := ast.Unparen(expr).(*ast.UnaryExpr); ok && unary.Op == token.AND {
		return unary.X
	}
	return expr
}
