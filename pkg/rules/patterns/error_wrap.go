package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorWrapRule())
}

// ErrorWrapRule detects errors returned without context wrapping
type ErrorWrapRule struct {
	*rules.BaseRule
}

// NewErrorWrapRule creates the rule
func NewErrorWrapRule() *ErrorWrapRule {
	return &ErrorWrapRule{
		BaseRule: rules.NewBaseRule(
			"error-wrap",
			"patterns",
			"Detects errors returned without adding context (should use fmt.Errorf with %w)",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks for unwrapped error returns
func (r *ErrorWrapRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Check if function returns error
		if !r.returnsError(fn) {
			return true
		}

		// Find if-err-return patterns
		for _, stmt := range fn.Body.List {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}

			// Check for if err != nil pattern
			if !r.isErrCheck(ifStmt.Cond) {
				continue
			}

			// Check body for bare return err
			for _, bodyStmt := range ifStmt.Body.List {
				retStmt, ok := bodyStmt.(*ast.ReturnStmt)
				if !ok {
					continue
				}

				if r.isBareErrorReturn(retStmt) {
					pos := ctx.PositionFor(retStmt)
					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Error returned without context; consider wrapping with fmt.Errorf")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Use fmt.Errorf(\"context: %w\", err) to add context")
					violations = append(violations, v)
				}
			}
		}

		return true
	})

	return violations
}

// returnsError checks if function has error in return types
func (r *ErrorWrapRule) returnsError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}

	for _, result := range fn.Type.Results.List {
		if ident, ok := result.Type.(*ast.Ident); ok {
			if ident.Name == "error" {
				return true
			}
		}
	}

	return false
}

// isErrCheck checks for err != nil
func (r *ErrorWrapRule) isErrCheck(cond ast.Expr) bool {
	binExpr, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}

	// Check for err != nil
	ident, ok := binExpr.X.(*ast.Ident)
	if !ok {
		return false
	}

	if ident.Name != "err" {
		return false
	}

	nilIdent, ok := binExpr.Y.(*ast.Ident)
	if !ok {
		return false
	}

	return nilIdent.Name == "nil"
}

// isBareErrorReturn checks if return statement just returns err without wrapping
func (r *ErrorWrapRule) isBareErrorReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}

	// Check last result (error is usually last)
	lastResult := ret.Results[len(ret.Results)-1]

	// Check for bare err identifier
	ident, ok := lastResult.(*ast.Ident)
	if !ok {
		return false
	}

	return ident.Name == "err"
}
