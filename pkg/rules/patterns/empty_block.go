package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEmptyBlockRule())
}

// EmptyBlockRule detects empty if/else/for/range/switch blocks.
//
// Two empty bodies are idioms, not leftovers: `select {}` blocks forever on
// purpose, and `for range ch {}` drains a channel (or runs a range-over-func
// iterator) for its side effect. A range loop with no variables is reported
// only when its operand is known not to be a channel or an iterator: through
// types, or, in a file without type information, a literal operand.
type EmptyBlockRule struct {
	*rules.BaseRule
}

// NewEmptyBlockRule creates the rule
func NewEmptyBlockRule() *EmptyBlockRule {
	return &EmptyBlockRule{
		BaseRule: rules.NewBaseRule(
			"empty-block",
			"patterns",
			"Detects empty if, else, for, range and switch blocks (select {} and channel-draining range loops are idioms)",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *EmptyBlockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *EmptyBlockRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every Go file; range operands are judged by their type
// where the file was type-checked.
func (r *EmptyBlockRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks for empty blocks. info is nil for a file without type information.
func (r *EmptyBlockRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
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
			if !isDrainLoop(stmt, info) {
				violations = r.checkBlock(ctx, stmt.Body, stmt.Pos(), "range", violations)
			}
		case *ast.SwitchStmt:
			violations = r.checkSwitchStmt(ctx, stmt, violations)
		}
		return true
	})

	return violations
}

// isDrainLoop reports whether an empty-bodied range loop may exist for the
// receive itself: no loop variables (or only _), over a channel or a
// range-over-func iterator. Without types only a literal operand is known not
// to be one, and anything else is left alone.
func isDrainLoop(stmt *ast.RangeStmt, info *types.Info) bool {
	if !isBlankOrNil(stmt.Key) || stmt.Value != nil {
		return false
	}
	if info != nil {
		if typ := info.TypeOf(stmt.X); typ != nil {
			switch typ.Underlying().(type) {
			case *types.Chan, *types.Signature:
				return true
			}
			return false
		}
	}
	switch stmt.X.(type) {
	case *ast.CompositeLit, *ast.BasicLit:
		return false
	}
	return true
}

func isBlankOrNil(expr ast.Expr) bool {
	if expr == nil {
		return true
	}
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "_"
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
