package patternkit

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// ForEachOwnStatement walks all statements inside node, pruning nested
// function literals: their statements belong to the closure, not to the
// enclosing function.
func ForEachOwnStatement(node ast.Node, visit func(ast.Stmt)) {
	ast.Inspect(node, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if stmt, ok := n.(ast.Stmt); ok {
			visit(stmt)
		}
		return true
	})
}

// InspectOwn visits the nodes inside node like ast.Inspect, without entering
// nested function literals: they belong to the closure.
func InspectOwn(node ast.Node, visit func(ast.Node) bool) {
	ast.Inspect(node, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		return visit(n)
	})
}

// FlattenOr flattens a ||-chain into its operands.
func FlattenOr(expr ast.Expr) []ast.Expr {
	if be, ok := expr.(*ast.BinaryExpr); ok && be.Op == token.LOR {
		return append(FlattenOr(be.X), FlattenOr(be.Y)...)
	}
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return FlattenOr(paren.X)
	}
	return []ast.Expr{expr}
}

// ErrNotNilName matches `<errVar> != nil` (or reversed) where the variable
// name looks like an error, returning the name.
func ErrNotNilName(expr ast.Expr) (string, bool) {
	be, ok := expr.(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return "", false
	}
	for _, pair := range [][2]ast.Expr{{be.X, be.Y}, {be.Y, be.X}} {
		if !helpers.IsNilIdent(pair[1]) {
			continue
		}
		if name, ok := ErrLikeName(pair[0]); ok {
			return name, true
		}
	}
	return "", false
}

// ErrLikeName extracts the identifier name from an expression when it looks
// like an error variable (err, dbErr, loadError, resp.Err, ...).
func ErrLikeName(expr ast.Expr) (string, bool) {
	var name string
	switch e := expr.(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	default:
		return "", false
	}
	if IsErrorVarName(name) {
		return name, true
	}
	return "", false
}
