package patternkit

import (
	"fmt"
	"go/ast"
	"go/token"
)

// IsIdent reports whether the expression is exactly the named identifier,
// parentheses aside. An empty name matches nothing: callers pass the name of a
// binding that may be absent (a blank range key, for one).
func IsIdent(expr ast.Expr, name string) bool {
	if expr == nil || name == "" {
		return false
	}
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && ident.Name == name
}

func IsIntLiteral(expr ast.Expr, value int) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == fmt.Sprint(value)
}
