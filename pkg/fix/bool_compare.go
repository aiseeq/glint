package fix

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
)

// BoolCompareFixer fixes redundant boolean comparisons
type BoolCompareFixer struct{}

// NewBoolCompareFixer creates the fixer
func NewBoolCompareFixer() *BoolCompareFixer {
	return &BoolCompareFixer{}
}

// RuleName returns the rule name
func (f *BoolCompareFixer) RuleName() string {
	return "bool-compare"
}

// CanFix reports whether the violation pins the comparison it is about: the
// column tells it apart from other comparisons on the same line.
func (f *BoolCompareFixer) CanFix(v *core.Violation) bool {
	return v != nil && v.Rule == "bool-compare" && v.Column > 0
}

// GenerateFix rewrites the comparison the violation points to. The operand is
// taken from the syntax tree, so the rewrite keeps the operand whole
// (`n > 0 == false` becomes `!(n > 0)`) and never cuts a name in two.
func (f *BoolCompareFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix {
	if ctx == nil || ctx.GoAST == nil || !f.CanFix(v) {
		return nil
	}

	var comparison *ast.BinaryExpr
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if comparison != nil {
			return false
		}
		binary, ok := n.(*ast.BinaryExpr)
		if ok && violationPosition(ctx, v, binary) && (binary.Op == token.EQL || binary.Op == token.NEQ) {
			comparison = binary
			return false
		}
		return true
	})
	if comparison == nil {
		return nil
	}

	operand, literal := boolComparisonOperand(comparison)
	if operand == nil {
		return nil
	}
	negate := (comparison.Op == token.EQL) == (literal == "false")

	replacement, ok := sourceOf(ctx, operand)
	if !ok {
		return nil
	}
	if negate {
		replacement, ok = negatedSource(ctx, operand)
		if !ok {
			return nil
		}
	}

	fix, ok := nodeFix(ctx, comparison.Pos(), comparison.End(), replacement)
	if !ok {
		return nil
	}
	fix.Message = "Simplify boolean comparison"
	fix.RuleName = "bool-compare"
	fix.Violation = v
	return []*Fix{fix}
}

// boolComparisonOperand returns the side of the comparison that is not the
// true/false literal, and the literal.
func boolComparisonOperand(comparison *ast.BinaryExpr) (ast.Expr, string) {
	if literal, ok := boolLiteral(comparison.Y); ok {
		return comparison.X, literal
	}
	if literal, ok := boolLiteral(comparison.X); ok {
		return comparison.Y, literal
	}
	return nil, ""
}

func boolLiteral(expr ast.Expr) (string, bool) {
	ident, ok := expr.(*ast.Ident)
	if !ok || (ident.Name != "true" && ident.Name != "false") {
		return "", false
	}
	return ident.Name, true
}

// negatedSource spells the negation of the operand. A negation is undone
// rather than doubled; an operand that is not a unary expression is put in
// parentheses, because `!` binds tighter than every binary operator.
func negatedSource(ctx *core.FileContext, operand ast.Expr) (string, bool) {
	if unary, ok := operand.(*ast.UnaryExpr); ok && unary.Op == token.NOT {
		return sourceOf(ctx, unary.X)
	}
	text, ok := sourceOf(ctx, operand)
	if !ok {
		return "", false
	}
	switch operand.(type) {
	case *ast.Ident, *ast.SelectorExpr, *ast.CallExpr, *ast.IndexExpr, *ast.IndexListExpr,
		*ast.ParenExpr, *ast.StarExpr, *ast.UnaryExpr, *ast.TypeAssertExpr:
		return "!" + text, true
	}
	return "!(" + text + ")", true
}

func init() {
	DefaultRegistry.Register(NewBoolCompareFixer())
}
