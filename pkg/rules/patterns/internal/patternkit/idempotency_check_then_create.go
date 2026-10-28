package patternkit

import (
	"go/ast"
)

func IsIdentNamedExpr(expr ast.Expr, name string) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && id.Name == name
}
