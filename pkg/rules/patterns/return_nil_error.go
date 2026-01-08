package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReturnNilErrorRule())
}

// ReturnNilErrorRule detects functions returning (nil, nil) which is often a bug
type ReturnNilErrorRule struct {
	*rules.BaseRule
}

// NewReturnNilErrorRule creates the rule
func NewReturnNilErrorRule() *ReturnNilErrorRule {
	return &ReturnNilErrorRule{
		BaseRule: rules.NewBaseRule(
			"return-nil-error",
			"patterns",
			"Detects (nil, nil) returns which often indicate missing error handling",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for (nil, nil) returns
func (r *ReturnNilErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		// Check if function returns (T, error) pattern
		if !r.hasErrorReturn(fn) {
			return true
		}

		// Find return statements with (nil, nil)
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			ret, ok := inner.(*ast.ReturnStmt)
			if !ok {
				return true
			}

			if r.isNilNilReturn(ret) {
				line := r.getLineFromNode(ctx, ret)
				v := r.CreateViolation(ctx.RelPath, line, "Returning (nil, nil) - possible missing error")
				v.WithCode(ctx.GetLine(line))
				v.WithSuggestion("Return an error or a valid value, not both nil")
				v.WithContext("pattern", "nil_nil_return")
				violations = append(violations, v)
			}

			return true
		})

		return true
	})

	return violations
}

// hasErrorReturn checks if function has error as last return type
func (r *ReturnNilErrorRule) hasErrorReturn(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) < 2 {
		return false
	}

	// Check last return type is error
	lastResult := fn.Type.Results.List[len(fn.Type.Results.List)-1]
	ident, ok := lastResult.Type.(*ast.Ident)
	if !ok {
		return false
	}

	return ident.Name == "error"
}

// isNilNilReturn checks if return statement returns (nil, nil)
func (r *ReturnNilErrorRule) isNilNilReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) != 2 {
		return false
	}

	// Check both values are nil
	for _, result := range ret.Results {
		if !r.isNil(result) {
			return false
		}
	}

	return true
}

func (r *ReturnNilErrorRule) isNil(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "nil"
}

func (r *ReturnNilErrorRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
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
