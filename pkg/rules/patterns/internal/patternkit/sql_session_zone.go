package patternkit

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// TextOperand reports an expression glued into a string or handed to fmt or
// a logger, judged by syntax.
func TextOperand(parents map[ast.Node]ast.Node, expr ast.Expr) bool {
	switch parent := parents[expr].(type) {
	case *ast.ParenExpr:
		return TextOperand(parents, parent)
	case *ast.BinaryExpr:
		return parent.Op == token.ADD
	case *ast.CallExpr:
		if helpers.IsLoggerCall(parent) {
			return true
		}
		// fmt's formatting, a slog attribute (slog.String("day", d)).
		sel, ok := parent.Fun.(*ast.SelectorExpr)
		return ok && (helpers.IsIdentNamed(sel.X, "fmt") || helpers.IsIdentNamed(sel.X, "slog"))
	}
	return false
}
