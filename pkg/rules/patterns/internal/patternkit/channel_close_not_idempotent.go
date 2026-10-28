package patternkit

import (
	"go/ast"
)

// ReceiverField returns the field name of recv.field, "" for anything else.
func ReceiverField(expr ast.Expr, recv string) string {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if id, ok := sel.X.(*ast.Ident); ok && id.Name == recv {
		return sel.Sel.Name
	}
	return ""
}
