package patterns

import (
	"go/ast"
	"go/token"

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

// AnalyzeFile checks for string concatenation in loops
func (r *StringConcatRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
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
			r.checkLoop(ctx, loop.Body, &violations)
		case *ast.RangeStmt:
			r.checkLoop(ctx, loop.Body, &violations)
		}

		return true
	})

	return violations
}

func (r *StringConcatRule) checkLoop(ctx *core.FileContext, body *ast.BlockStmt, violations *[]*core.Violation) {
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
			if len(assign.Lhs) == 1 && len(assign.Rhs) == 1 && r.isStringConcat(assign.Rhs[0]) {
				r.reportConcatViolation(ctx, assign, violations)
			}
			return true
		}

		// Check for s = s + "..."
		if assign.Tok == token.ASSIGN && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 {
			if r.isAssignPlusPattern(assign) {
				r.reportConcatViolation(ctx, assign, violations)
			}
		}

		return true
	})
}

func (r *StringConcatRule) isAssignPlusPattern(assign *ast.AssignStmt) bool {
	binary, ok := assign.Rhs[0].(*ast.BinaryExpr)
	if !ok || binary.Op != token.ADD {
		return false
	}

	lhsIdent, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return false
	}

	rhsIdent, ok := binary.X.(*ast.Ident)
	if !ok {
		return false
	}

	return lhsIdent.Name == rhsIdent.Name && r.isStringExpr(binary.Y)
}

func (r *StringConcatRule) reportConcatViolation(ctx *core.FileContext, assign *ast.AssignStmt, violations *[]*core.Violation) {
	line := r.getLineFromNode(ctx, assign)
	v := r.CreateViolation(ctx.RelPath, line, "String concatenation in loop - use strings.Builder")
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Use var sb strings.Builder; sb.WriteString(...)")
	v.WithContext("pattern", "string_concat_loop")
	*violations = append(*violations, v)
}

func (r *StringConcatRule) isStringConcat(expr ast.Expr) bool {
	// Check for string literal
	if lit, ok := expr.(*ast.BasicLit); ok {
		return lit.Kind == token.STRING
	}

	// Check for variable (could be string)
	if _, ok := expr.(*ast.Ident); ok {
		return true // Could be string, will have some false positives
	}

	// Check for binary expression with +
	if binary, ok := expr.(*ast.BinaryExpr); ok {
		return binary.Op == token.ADD
	}

	return false
}

func (r *StringConcatRule) isStringExpr(expr ast.Expr) bool {
	// Check for string literal
	if lit, ok := expr.(*ast.BasicLit); ok {
		return lit.Kind == token.STRING
	}

	// Check for string conversion or function call
	return true // Be conservative
}

func (r *StringConcatRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
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
