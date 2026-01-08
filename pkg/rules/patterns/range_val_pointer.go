package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRangeValPointerRule())
}

// RangeValPointerRule detects taking address of range loop variable
type RangeValPointerRule struct {
	*rules.BaseRule
}

// NewRangeValPointerRule creates the rule
func NewRangeValPointerRule() *RangeValPointerRule {
	return &RangeValPointerRule{
		BaseRule: rules.NewBaseRule(
			"range-val-pointer",
			"patterns",
			"Detects taking address of range loop variable (all pointers point to same address)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for pointer to range variable
func (r *RangeValPointerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		rangeStmt, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}

		// Get range variable names
		rangeVars := make(map[string]bool)
		if rangeStmt.Key != nil {
			if ident, ok := rangeStmt.Key.(*ast.Ident); ok && ident.Name != "_" {
				rangeVars[ident.Name] = true
			}
		}
		if rangeStmt.Value != nil {
			if ident, ok := rangeStmt.Value.(*ast.Ident); ok && ident.Name != "_" {
				rangeVars[ident.Name] = true
			}
		}

		if len(rangeVars) == 0 {
			return true
		}

		// Check for &variable inside the loop body
		ast.Inspect(rangeStmt.Body, func(inner ast.Node) bool {
			unary, ok := inner.(*ast.UnaryExpr)
			if !ok {
				return true
			}

			// Check if it's address-of operator
			if unary.Op.String() != "&" {
				return true
			}

			// Check if operand is a range variable
			if ident, ok := unary.X.(*ast.Ident); ok {
				if rangeVars[ident.Name] {
					line := r.getLineFromNode(ctx, unary)
					v := r.CreateViolation(ctx.RelPath, line, "Taking address of range variable '"+ident.Name+"' - all iterations share same address")
					v.WithCode(ctx.GetLine(line))
					v.WithSuggestion("Create a local copy: copy := " + ident.Name + "; use &copy")
					v.WithContext("pattern", "range_val_pointer")
					v.WithContext("variable", ident.Name)
					violations = append(violations, v)
				}
			}

			return true
		})

		return true
	})

	return violations
}

func (r *RangeValPointerRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
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
