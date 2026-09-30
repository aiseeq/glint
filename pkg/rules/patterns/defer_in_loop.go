package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeferInLoopRule())
}

// DeferInLoopRule detects defer statements inside loops
type DeferInLoopRule struct {
	*rules.BaseRule
}

// NewDeferInLoopRule creates the rule
func NewDeferInLoopRule() *DeferInLoopRule {
	return &DeferInLoopRule{
		BaseRule: rules.NewBaseRule(
			"defer-in-loop",
			"patterns",
			"Detects defer statements inside loops (resource leak risk)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for defer inside loops
func (r *DeferInLoopRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	// walk visits node with the number of loops around it inside the current
	// function. A function literal is a function of its own: its body starts
	// at depth zero, so `for … { func() { defer … }() }` is the per-iteration
	// idiom, while a loop inside any closure is checked like any other loop.
	var walk func(node ast.Node, loopDepth int)
	walk = func(node ast.Node, loopDepth int) {
		ast.Inspect(node, func(n ast.Node) bool {
			if n == node {
				return true
			}
			switch stmt := n.(type) {
			case *ast.FuncLit:
				walk(stmt.Body, 0)
				return false
			case *ast.ForStmt:
				walkIfPresent(walk, stmt.Init, loopDepth)
				walkIfPresent(walk, stmt.Cond, loopDepth)
				walkIfPresent(walk, stmt.Post, loopDepth)
				walk(stmt.Body, loopDepth+1)
				return false
			case *ast.RangeStmt:
				walkIfPresent(walk, stmt.X, loopDepth)
				walk(stmt.Body, loopDepth+1)
				return false
			case *ast.DeferStmt:
				if loopDepth > 0 {
					line := ctx.LineFor(stmt)
					v := r.CreateViolation(ctx.RelPath, line, "defer inside loop - resources won't be released until function returns")
					v.WithCode(ctx.GetLine(line))
					v.WithSuggestion("Move defer outside the loop or use immediate function call")
					v.WithContext("pattern", "defer_in_loop")
					violations = append(violations, v)
				}
			}
			return true
		})
	}

	walk(ctx.GoAST, 0)

	return violations
}

// walkIfPresent walks an optional loop header part.
func walkIfPresent(walk func(ast.Node, int), node ast.Node, loopDepth int) {
	if node == nil {
		return
	}
	walk(node, loopDepth)
}
