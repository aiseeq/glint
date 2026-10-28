package patternkit

import (
	"go/ast"
)

func IsFalseLiteral(expr ast.Expr) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && ident.Name == "false"
}
