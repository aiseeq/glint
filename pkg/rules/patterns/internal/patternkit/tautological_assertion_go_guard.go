package patternkit

import (
	"go/ast"
	"go/token"
)

// FlattenAnd splits a && b && c into its operands.
func FlattenAnd(expr ast.Expr) []ast.Expr {
	if bin, ok := ast.Unparen(expr).(*ast.BinaryExpr); ok && bin.Op == token.LAND {
		return append(FlattenAnd(bin.X), FlattenAnd(bin.Y)...)
	}
	return []ast.Expr{expr}
}
