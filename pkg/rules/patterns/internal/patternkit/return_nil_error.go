package patternkit

import (
	"go/ast"
	"go/token"
)

// TestsNoRows reports a condition that holds when the error is ErrNoRows.
func TestsNoRows(cond ast.Expr) bool {
	switch c := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		switch c.Op {
		case token.LOR:
			return TestsNoRows(c.X) || TestsNoRows(c.Y)
		case token.EQL:
			return NamesNoRows(c.X) || NamesNoRows(c.Y)
		}
	case *ast.CallExpr:
		sel, ok := c.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Is" && len(c.Args) == 2 && NamesNoRows(c.Args[1])
	}
	return false
}

// NamesNoRows reports <pkg>.ErrNoRows (database/sql, pgx).
func NamesNoRows(expr ast.Expr) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "ErrNoRows"
}
