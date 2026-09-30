package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewAppendAssignRule())
}

// AppendAssignRule detects an append() whose result is thrown away: assigned
// to the blank identifier (`_ = append(xs, v)`, the form that compiles), or a
// bare append statement, which the compiler rejects and which only reaches the
// rule in a file that does not build.
type AppendAssignRule struct {
	*rules.BaseRule
}

// NewAppendAssignRule creates the rule
func NewAppendAssignRule() *AppendAssignRule {
	return &AppendAssignRule{
		BaseRule: rules.NewBaseRule(
			"append-assign",
			"patterns",
			"Detects append() whose result is discarded (assigned to _ or used as a bare statement)",
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
	report := func(node ast.Node) {
		line := ctx.LineFor(node)
		v := r.CreateViolation(ctx.RelPath, line, "append() result is not assigned - slice is not modified")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Assign the result: slice = append(slice, item)")
		v.WithContext("pattern", "append_no_assign")
		violations = append(violations, v)
	}

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ExprStmt:
			if call, ok := node.X.(*ast.CallExpr); ok && r.isAppendCall(call) {
				report(node)
			}
		case *ast.AssignStmt:
			r.checkBlankTargets(node.Lhs, node.Rhs, report)
		case *ast.ValueSpec:
			names := make([]ast.Expr, len(node.Names))
			for i, name := range node.Names {
				names[i] = name
			}
			r.checkBlankTargets(names, node.Values, report)
		}
		return true
	})

	return violations
}

// checkBlankTargets reports an append whose value goes to the blank
// identifier.
func (r *AppendAssignRule) checkBlankTargets(lhs, rhs []ast.Expr, report func(ast.Node)) {
	if len(lhs) != len(rhs) {
		return
	}
	for i, value := range rhs {
		call, ok := ast.Unparen(value).(*ast.CallExpr)
		if !ok || !r.isAppendCall(call) {
			continue
		}
		if target, ok := lhs[i].(*ast.Ident); ok && target.Name == "_" {
			report(value)
		}
	}
}

func (r *AppendAssignRule) isAppendCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "append"
}
