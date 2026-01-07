package patterns

import (
	"go/ast"
	"go/token"

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
			violations = r.checkIfStmt(ctx, stmt, violations)
		case *ast.ForStmt:
			violations = r.checkBlock(ctx, stmt.Body, stmt.Pos(), "for", violations)
		case *ast.RangeStmt:
			violations = r.checkBlock(ctx, stmt.Body, stmt.Pos(), "range", violations)
		case *ast.SwitchStmt:
			violations = r.checkSwitchStmt(ctx, stmt, violations)
		case *ast.SelectStmt:
			violations = r.checkSelectStmt(ctx, stmt, violations)
		}
		return true
	})

	return violations
}

func (r *EmptyBlockRule) checkIfStmt(ctx *core.FileContext, stmt *ast.IfStmt, violations []*core.Violation) []*core.Violation {
	if isEmptyBlock(stmt.Body) {
		violations = r.checkBlock(ctx, stmt.Body, stmt.Pos(), "if", violations)
	}
	if stmt.Else != nil {
		if block, ok := stmt.Else.(*ast.BlockStmt); ok && isEmptyBlock(block) {
			violations = r.checkBlock(ctx, block, block.Pos(), "else", violations)
		}
	}
	return violations
}

func (r *EmptyBlockRule) checkSwitchStmt(ctx *core.FileContext, stmt *ast.SwitchStmt, violations []*core.Violation) []*core.Violation {
	if stmt.Body != nil && len(stmt.Body.List) == 0 {
		return r.checkBlock(ctx, stmt.Body, stmt.Pos(), "switch", violations)
	}
	return violations
}

func (r *EmptyBlockRule) checkSelectStmt(ctx *core.FileContext, stmt *ast.SelectStmt, violations []*core.Violation) []*core.Violation {
	if stmt.Body != nil && len(stmt.Body.List) == 0 {
		return r.checkBlock(ctx, stmt.Body, stmt.Pos(), "select", violations)
	}
	return violations
}

func (r *EmptyBlockRule) checkBlock(ctx *core.FileContext, block *ast.BlockStmt, nodePos token.Pos, blockType string, violations []*core.Violation) []*core.Violation {
	if !isEmptyBlock(block) {
		return violations
	}
	pos := ctx.GoFileSet.Position(nodePos)
	v := r.CreateViolation(ctx.RelPath, pos.Line, "Empty "+blockType+" block")
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Add code or remove empty block")
	return append(violations, v)
}

func isEmptyBlock(block *ast.BlockStmt) bool {
	return block != nil && len(block.List) == 0
}
