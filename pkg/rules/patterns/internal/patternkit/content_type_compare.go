package patternkit

import (
	"go/ast"
)

// LiteralText returns the value of a string literal expression.
func LiteralText(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return "", false
	}
	return GoStringLiteral(lit)
}
