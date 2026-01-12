package patterns

import (
	"go/ast"
	"go/token"

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

// AnalyzeFile checks for error string comparisons
func (r *ErrorStringCompareRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Check for err.Error() == "string" or strings.Contains(err.Error(), "...")
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				// Check for err.Error() == "string"
				if r.isErrorStringCall(node.X) || r.isErrorStringCall(node.Y) {
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
			if r.isStringsContainsErrorCall(node) {
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

// isErrorStringCall checks if expression is err.Error()
func (r *ErrorStringCompareRule) isErrorStringCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Check if method is .Error()
	if sel.Sel.Name != "Error" {
		return false
	}

	// Check if receiver looks like an error variable
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	// Common error variable names
	name := ident.Name
	return name == "err" || name == "error" || name == "e" ||
		len(name) > 3 && name[len(name)-3:] == "Err"
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

	// Check if strExpr is a string literal
	_, isString := strExpr.(*ast.BasicLit)
	return isString
}

// isStringsContainsErrorCall checks for strings.Contains(err.Error(), "...")
func (r *ErrorStringCompareRule) isStringsContainsErrorCall(call *ast.CallExpr) bool {
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

	return r.isErrorStringCall(call.Args[0])
}
