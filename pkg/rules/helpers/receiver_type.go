package helpers

import "go/ast"

// ReceiverTypeName returns the name of the type a method receiver expression
// is built on, unwrapping pointer and generic receivers (*Box[T], Pair[K, V]),
// or "" when the expression has no such base identifier.
func ReceiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return ReceiverTypeName(t.X)
	case *ast.IndexExpr:
		return ReceiverTypeName(t.X)
	case *ast.IndexListExpr:
		return ReceiverTypeName(t.X)
	case *ast.ParenExpr:
		return ReceiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}
