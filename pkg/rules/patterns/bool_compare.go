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
		_ = other // Could be used for more specific messages

		violations = append(violations, v)

		return true
	})

	return violations
}

func (r *BoolCompareRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	if node == nil {
		return 1
	}

	pos := node.Pos()
	if pos == 0 {
		return 1
	}

	offset := int(pos) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}

	line := 1
	for i := 0; i < offset && i < len(ctx.Content); i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}
