package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorStringCompareRule())
}

// ErrorStringCompareRule detects error comparisons using string matching
type ErrorStringCompareRule struct {
	*rules.BaseRule
}

// NewErrorStringCompareRule creates the rule
func NewErrorStringCompareRule() *ErrorStringCompareRule {
	return &ErrorStringCompareRule{
		BaseRule: rules.NewBaseRule(
			"error-string-compare",
			"patterns",
			"Detects error comparisons using strings instead of errors.Is/errors.As",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *ErrorStringCompareRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ErrorStringCompareRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; the receiver of .Error() is judged by
// its type.
func (r *ErrorStringCompareRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks for error string comparisons. info is nil for a file without
// type information: then only a receiver the file declares as error counts.
func (r *ErrorStringCompareRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil || ctx.IsTestFile() {
		return nil
	}

	var inferrer *TypeInferrer
	if info == nil {
		inferrer = NewTypeInferrer(ctx.GoAST)
	}
	isErrorString := func(expr ast.Expr) bool { return isErrorStringCall(expr, info, inferrer) }

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Check for err.Error() == "string" or strings.Contains(err.Error(), "...")
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				// Check for err.Error() == "string"
				if isErrorString(node.X) || isErrorString(node.Y) {
					pos := ctx.PositionFor(node)
					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Comparing error using .Error() string; use errors.Is or errors.As instead")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Use errors.Is(err, targetErr) or errors.As(err, &target) for error comparison")
					violations = append(violations, v)
				}

				// Check for errorMsg == "" or errMsg == "something"
				if r.isErrorMessageVarComparison(node.X, node.Y) || r.isErrorMessageVarComparison(node.Y, node.X) {
					pos := ctx.PositionFor(node)
					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Comparing error message variable with string; antipattern")
					v.Severity = core.SeverityHigh
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Use typed errors and errors.Is() instead of comparing error message strings")
					violations = append(violations, v)
				}
			}

		case *ast.CallExpr:
			// Check strings.Contains(err.Error(), "...")
			if r.isStringsContainsErrorCall(node, isErrorString) {
				pos := ctx.PositionFor(node)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Using strings.Contains on error message; fragile and may break")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Define sentinel errors or use errors.Is/errors.As")
				violations = append(violations, v)
			}
		}

		return true
	})

	return violations
}

// isErrorStringCall checks if expression is x.Error() on an error value: by
// its type when type information is there, otherwise by the type the file
// declares for the receiver. A receiver the file says nothing about is
// unknown and not reported.
func isErrorStringCall(expr ast.Expr, info *types.Info, inferrer *TypeInferrer) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Error" {
		return false
	}
	if info != nil {
		return isErrorValue(sel.X, info)
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	typ, known := inferrer.GetType(ident.Name)
	return known && typ.TypeName == "error"
}

// isErrorMessageVarComparison checks if identifier is errorMsg/errMsg compared with string
func (r *ErrorStringCompareRule) isErrorMessageVarComparison(varExpr, strExpr ast.Expr) bool {
	// Check if varExpr is an identifier that looks like error message variable
	ident, ok := varExpr.(*ast.Ident)
	if !ok {
		return false
	}

	// Common error message variable names
	name := ident.Name
	isErrorMsgVar := name == "errorMsg" || name == "errMsg" || name == "errorMessage" ||
		name == "errMessage" || name == "errorStr" || name == "errStr" ||
		name == "errText" || name == "errorText"

	if !isErrorMsgVar {
		return false
	}

	// Check if strExpr is a non-empty string literal: an empty-message check
	// (errMsg == "") chooses a text for a message that never came, it
	// compares nothing against an error's wording.
	lit, isString := strExpr.(*ast.BasicLit)
	return isString && lit.Kind == token.STRING && lit.Value != `""` && lit.Value != "``"
}

// isStringsContainsErrorCall checks for strings.Contains(err.Error(), "...")
func (r *ErrorStringCompareRule) isStringsContainsErrorCall(call *ast.CallExpr, isErrorString func(ast.Expr) bool) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Check for strings.Contains
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "strings" {
		return false
	}

	if sel.Sel.Name != "Contains" && sel.Sel.Name != "HasPrefix" && sel.Sel.Name != "HasSuffix" {
		return false
	}

	// Check if first argument is err.Error()
	if len(call.Args) < 1 {
		return false
	}

	return isErrorString(call.Args[0])
}
