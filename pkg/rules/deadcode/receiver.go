package deadcode

import "go/ast"

// receiverTypeName extracts the type name of a method receiver. It unwraps
// pointer receivers and generic receivers (Box[T], Pair[K, V]), so the
// finding names the method as "Box.Close" rather than ".Close".
func receiverTypeName(field *ast.Field) string {
	return typeExprName(field.Type)
}

// typeExprName returns the identifier a receiver type expression is built
// on, or "" when the expression has no such base identifier.
func typeExprName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return typeExprName(t.X)
	case *ast.IndexExpr:
		return typeExprName(t.X)
	case *ast.IndexListExpr:
		return typeExprName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}
