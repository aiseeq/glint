package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewAppendAssignRule())
}

// AppendAssignRule detects append() calls without assignment
type AppendAssignRule struct {
	*rules.BaseRule
}

// NewAppendAssignRule creates the rule
func NewAppendAssignRule() *AppendAssignRule {
	return &AppendAssignRule{
		BaseRule: rules.NewBaseRule(
			"append-assign",
			"patterns",
			"Detects append() without assignment (result is discarded)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for append without assignment
func (r *AppendAssignRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Look for expression statements (not assignments)
		exprStmt, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}

		// Check if it's a call expression
		callExpr, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check if it's append()
		if r.isAppendCall(callExpr) {
			line := r.getLineFromNode(ctx, exprStmt)
			v := r.CreateViolation(ctx.RelPath, line, "append() result is not assigned - slice is not modified")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Assign the result: slice = append(slice, item)")
			v.WithContext("pattern", "append_no_assign")
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

func (r *AppendAssignRule) isAppendCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "append"
}

func (r *AppendAssignRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
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
