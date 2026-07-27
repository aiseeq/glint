package patterns

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewBoolCompareRule())
}

// BoolCompareRule detects redundant boolean comparisons
type BoolCompareRule struct {
	*rules.BaseRule
}

// NewBoolCompareRule creates the rule
func NewBoolCompareRule() *BoolCompareRule {
	return &BoolCompareRule{
		BaseRule: rules.NewBaseRule(
			"bool-compare",
			"patterns",
			"Detects redundant boolean comparisons (x == true, x == false)",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks for redundant boolean comparisons
func (r *BoolCompareRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	typeInferrer := NewTypeInferrer(ctx.GoAST)

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}

		// Check for == true, == false, != true, != false
		if binary.Op != token.EQL && binary.Op != token.NEQ {
			return true
		}

		var boolLit *ast.Ident
		var other ast.Expr

		// Check right side for true/false
		if ident, ok := binary.Y.(*ast.Ident); ok {
			if ident.Name == "true" || ident.Name == "false" {
				boolLit = ident
				other = binary.X
			}
		}

		// Check left side for true/false
		if boolLit == nil {
			if ident, ok := binary.X.(*ast.Ident); ok {
				if ident.Name == "true" || ident.Name == "false" {
					boolLit = ident
					other = binary.Y
				}
			}
		}

		if boolLit == nil {
			return true
		}

		// Comparing a non-bool operand against true/false is not redundant:
		// a value read out of a map[string]any cannot be used as a condition
		// on its own.
		if !r.isKnownBool(other, typeInferrer) {
			return true
		}

		line := r.getLineFromNode(ctx, binary)
		var suggestion string

		if binary.Op == token.EQL {
			if boolLit.Name == "true" {
				suggestion = "Use 'x' instead of 'x == true'"
			} else {
				suggestion = "Use '!x' instead of 'x == false'"
			}
		} else { // NEQ
			if boolLit.Name == "true" {
				suggestion = "Use '!x' instead of 'x != true'"
			} else {
				suggestion = "Use 'x' instead of 'x != false'"
			}
		}

		v := r.CreateViolation(ctx.RelPath, line, "Redundant boolean comparison")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion(suggestion)
		v.WithContext("pattern", "bool_compare")
		v.WithContext("compared_to", boolLit.Name)

		violations = append(violations, v)

		return true
	})

	return violations
}

func (r *BoolCompareRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	return ctx.LineFor(node)
}

// isKnownBool reports whether the operand compared against true/false is
// itself a boolean. Names the file declares but whose type cannot be resolved
// (a map[string]any lookup, an unknown call) are left alone: rewriting those
// comparisons would not compile.
func (r *BoolCompareRule) isKnownBool(expr ast.Expr, inferrer *TypeInferrer) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		if info, ok := inferrer.GetType(e.Name); ok {
			return info.TypeName == "bool"
		}
		return !inferrer.IsDeclared(e.Name)
	case *ast.BinaryExpr:
		// Comparisons and logical operators always produce a bool.
		return true
	case *ast.UnaryExpr:
		return e.Op == token.NOT
	case *ast.ParenExpr:
		return r.isKnownBool(e.X, inferrer)
	}
	// Selectors and calls: no type information here, keep the finding.
	return true
}
