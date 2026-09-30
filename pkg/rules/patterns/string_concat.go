package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewStringConcatRule())
}

// StringConcatRule detects string concatenation in loops
type StringConcatRule struct {
	*rules.BaseRule
}

// NewStringConcatRule creates the rule
func NewStringConcatRule() *StringConcatRule {
	return &StringConcatRule{
		BaseRule: rules.NewBaseRule(
			"string-concat",
			"patterns",
			"Detects string concatenation in loops (use strings.Builder)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: only concatenations
// with a string literal are known to be string concatenations.
func (r *StringConcatRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *StringConcatRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information the accumulator
// is judged by its type.
func (r *StringConcatRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks for string concatenation in loops. info is nil for a file
// without type information.
func (r *StringConcatRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Check for loops
		switch loop := n.(type) {
		case *ast.ForStmt:
			r.checkLoop(ctx, info, loop.Body, &violations)
		case *ast.RangeStmt:
			r.checkLoop(ctx, info, loop.Body, &violations)
		}

		return true
	})

	return violations
}

func (r *StringConcatRule) checkLoop(ctx *core.FileContext, info *types.Info, body *ast.BlockStmt, violations *[]*core.Violation) {
	if body == nil {
		return
	}

	ast.Inspect(body, func(n ast.Node) bool {
		// Skip nested function literals
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}

		// Look for s += "..." or s = s + "..."
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		// Check for += with string
		if assign.Tok == token.ADD_ASSIGN {
			if len(assign.Lhs) == 1 && len(assign.Rhs) == 1 && r.isStringAccumulation(info, assign.Lhs[0], assign.Rhs[0]) {
				if !r.variableResetBefore(body, assign) {
					r.reportConcatViolation(ctx, assign, violations)
				}
			}
			return true
		}

		// Check for s = s + "..."
		if assign.Tok == token.ASSIGN && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 {
			if r.isAssignPlusPattern(info, assign) {
				if !r.variableResetBefore(body, assign) {
					r.reportConcatViolation(ctx, assign, violations)
				}
			}
		}

		return true
	})
}

func (r *StringConcatRule) variableResetBefore(body *ast.BlockStmt, target *ast.AssignStmt) bool {
	targetIdent, ok := target.Lhs[0].(*ast.Ident)
	if !ok {
		return false
	}

	reset := false
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		block, ok := n.(*ast.BlockStmt)
		if !ok || block.Pos() > target.Pos() || block.End() < target.End() {
			return true
		}
		for _, stmt := range block.List {
			if stmt.End() >= target.Pos() {
				break
			}
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || (assign.Tok != token.DEFINE && assign.Tok != token.ASSIGN) {
				continue
			}
			for _, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name == targetIdent.Name {
					reset = true
					return false
				}
			}
		}
		return !reset
	})
	return reset
}

// isAssignPlusPattern matches `s = s + x` on a string accumulator.
func (r *StringConcatRule) isAssignPlusPattern(info *types.Info, assign *ast.AssignStmt) bool {
	binary, ok := assign.Rhs[0].(*ast.BinaryExpr)
	if !ok || binary.Op != token.ADD {
		return false
	}
	if types.ExprString(assign.Lhs[0]) != types.ExprString(binary.X) {
		return false
	}
	if info != nil {
		return isStringKind(info.TypeOf(assign.Lhs[0]))
	}
	return isStringBasicLit(binary.Y)
}

func (r *StringConcatRule) reportConcatViolation(ctx *core.FileContext, assign *ast.AssignStmt, violations *[]*core.Violation) {
	line := ctx.LineFor(assign)
	v := r.CreateViolation(ctx.RelPath, line, "String concatenation in loop - use strings.Builder")
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Use var sb strings.Builder; sb.WriteString(...)")
	v.WithContext("pattern", "string_concat_loop")
	*violations = append(*violations, v)
}

// isStringAccumulation reports `lhs += rhs` on a string. With type
// information the type of the accumulator decides; without it only a string
// literal on the right says the operands are strings.
func (r *StringConcatRule) isStringAccumulation(info *types.Info, lhs, rhs ast.Expr) bool {
	if info != nil {
		return isStringKind(info.TypeOf(lhs))
	}
	if isStringBasicLit(rhs) {
		return true
	}
	binary, ok := rhs.(*ast.BinaryExpr)
	return ok && binary.Op == token.ADD && (isStringBasicLit(binary.X) || isStringBasicLit(binary.Y))
}

func isStringBasicLit(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// isStringKind reports a string type, named string types included.
func isStringKind(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsString != 0
}
