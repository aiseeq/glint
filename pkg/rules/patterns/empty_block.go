package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEmptyBlockRule())
}

// EmptyBlockRule detects empty if/for/switch blocks
type EmptyBlockRule struct {
	*rules.BaseRule
}

// NewEmptyBlockRule creates the rule
func NewEmptyBlockRule() *EmptyBlockRule {
	return &EmptyBlockRule{
		BaseRule: rules.NewBaseRule(
			"empty-block",
			"patterns",
			"Detects empty if, for, switch, and select blocks",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks for empty blocks
func (r *EmptyBlockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.IfStmt:
			if isEmptyBlock(stmt.Body) {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line, "Empty if block")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Add code or remove empty block")
				violations = append(violations, v)
			}
			// Check else block
			if stmt.Else != nil {
				if block, ok := stmt.Else.(*ast.BlockStmt); ok && isEmptyBlock(block) {
					pos := ctx.GoFileSet.Position(block.Pos())
					v := r.CreateViolation(ctx.RelPath, pos.Line, "Empty else block")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Add code or remove empty else block")
					violations = append(violations, v)
				}
			}

		case *ast.ForStmt:
			if isEmptyBlock(stmt.Body) {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line, "Empty for block")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Add code or remove empty loop")
				violations = append(violations, v)
			}

		case *ast.RangeStmt:
			if isEmptyBlock(stmt.Body) {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line, "Empty range block")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Add code or remove empty loop")
				violations = append(violations, v)
			}

		case *ast.SwitchStmt:
			if stmt.Body != nil && len(stmt.Body.List) == 0 {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line, "Empty switch block")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Add cases or remove empty switch")
				violations = append(violations, v)
			}

		case *ast.SelectStmt:
			if stmt.Body != nil && len(stmt.Body.List) == 0 {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line, "Empty select block")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Add cases or remove empty select")
				violations = append(violations, v)
			}
		}
		return true
	})

	return violations
}

func isEmptyBlock(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	return len(block.List) == 0
}
