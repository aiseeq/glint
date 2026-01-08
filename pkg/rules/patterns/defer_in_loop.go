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
	loopDepth := 0

	var inspect func(n ast.Node) bool
	inspect = func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			loopDepth++
			ast.Inspect(n, func(child ast.Node) bool {
				if child == n {
					return true // Skip the loop node itself
				}
				// Don't recurse into nested functions
				if _, ok := child.(*ast.FuncLit); ok {
					return false
				}
				return inspect(child)
			})
			loopDepth--
			return false // Already handled children

		case *ast.DeferStmt:
			if loopDepth > 0 {
				line := r.getLineFromNode(ctx, stmt)
				v := r.CreateViolation(ctx.RelPath, line, "defer inside loop - resources won't be released until function returns")
				v.WithCode(ctx.GetLine(line))
				v.WithSuggestion("Move defer outside the loop or use immediate function call")
				v.WithContext("pattern", "defer_in_loop")
				violations = append(violations, v)
			}

		case *ast.FuncLit:
			// Anonymous functions have their own defer scope
			return false
		}
		return true
	}

	ast.Inspect(ctx.GoAST, inspect)

	return violations
}

func (r *DeferInLoopRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
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
