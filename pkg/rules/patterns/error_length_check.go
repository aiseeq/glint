package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorLengthCheckRule())
}

// ErrorLengthCheckRule detects dangerous patterns where error type is determined by string length
// This is an anti-pattern because:
// - Any error message of certain length will be misclassified
// - Error message length depends on driver version, locale, etc.
// - Real errors get masked as different error types
type ErrorLengthCheckRule struct {
	*rules.BaseRule
}

// NewErrorLengthCheckRule creates the rule
func NewErrorLengthCheckRule() *ErrorLengthCheckRule {
	return &ErrorLengthCheckRule{
		BaseRule: rules.NewBaseRule(
			"error-length-check",
			"patterns",
			"Detects dangerous patterns where error type is guessed by message length",
			core.SeverityCritical,
		),
	}
}

// AnalyzeFile checks for error length check patterns
func (r *ErrorLengthCheckRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	// Skip test files
	if ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation
	reportedLines := make(map[int]bool)

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		var v *core.Violation

		switch node := n.(type) {
		case *ast.ReturnStmt:
			// Check for: return len(errMsg) >= X && len(errMsg) <= Y (highest priority)
			v = r.checkReturnLengthCondition(ctx, node)

		case *ast.IfStmt:
			// Check for complex conditions like: len(errMsg) >= 30 && len(errMsg) <= 300
			v = r.checkComplexLengthCondition(ctx, node)

		case *ast.BinaryExpr:
			// Check for simple len(errMsg) >= N comparisons (lowest priority)
			v = r.checkLengthComparison(ctx, node)
		}

		// Deduplicate by line number
		if v != nil && !reportedLines[v.Line] {
			reportedLines[v.Line] = true
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

// checkLengthComparison checks for len(errMsg) compared with numeric constant
func (r *ErrorLengthCheckRule) checkLengthComparison(ctx *core.FileContext, expr *ast.BinaryExpr) *core.Violation {
	// Only check comparison operators
	if !isComparisonOp(expr.Op) {
		return nil
	}

	// Check if either side is len(errorVariable)
	var lenCall *ast.CallExpr
	var numLit *ast.BasicLit

	if call := r.extractLenCall(expr.X); call != nil {
		lenCall = call
		if lit, ok := expr.Y.(*ast.BasicLit); ok && lit.Kind == token.INT {
			numLit = lit
		}
	} else if call := r.extractLenCall(expr.Y); call != nil {
		lenCall = call
		if lit, ok := expr.X.(*ast.BasicLit); ok && lit.Kind == token.INT {
			numLit = lit
		}
	}

	if lenCall == nil || numLit == nil {
		return nil
	}

	// Check if len() argument is error-related
	if !r.isErrorRelatedArg(lenCall) {
		return nil
	}

	pos := ctx.PositionFor(expr)
	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Error type determined by message length - fragile and will misclassify errors")
	v.Severity = core.SeverityCritical
	v.WithCode(ctx.GetLine(pos.Line))
	v.WithSuggestion("Use errors.Is(), errors.As(), or typed error codes (e.g., pq.Error.Code) instead")
	v.WithContext("pattern", "error_length_check")
	return v
}

// checkComplexLengthCondition checks for conditions like: len(errMsg) >= 30 && len(errMsg) <= 300
func (r *ErrorLengthCheckRule) checkComplexLengthCondition(ctx *core.FileContext, stmt *ast.IfStmt) *core.Violation {
	if stmt.Cond == nil {
		return nil
	}

	// Look for && or || with multiple length checks
	if binExpr, ok := stmt.Cond.(*ast.BinaryExpr); ok {
		if binExpr.Op == token.LAND || binExpr.Op == token.LOR {
			leftHasLen := r.hasErrorLengthCheck(binExpr.X)
			rightHasLen := r.hasErrorLengthCheck(binExpr.Y)

			if leftHasLen && rightHasLen {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Error classification by length range - any error in this length range will be misclassified")
				v.Severity = core.SeverityCritical
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Use typed errors: errors.As(err, &pqErr) and check pqErr.Code for PostgreSQL errors")
				v.WithContext("pattern", "error_length_range")
				return v
			}
		}
	}

	return nil
}

// checkReturnLengthCondition checks for: return len(errMsg) >= X && len(errMsg) <= Y
func (r *ErrorLengthCheckRule) checkReturnLengthCondition(ctx *core.FileContext, stmt *ast.ReturnStmt) *core.Violation {
	for _, result := range stmt.Results {
		if binExpr, ok := result.(*ast.BinaryExpr); ok {
			if binExpr.Op == token.LAND || binExpr.Op == token.LOR {
				leftHasLen := r.hasErrorLengthCheck(binExpr.X)
				rightHasLen := r.hasErrorLengthCheck(binExpr.Y)

				if leftHasLen && rightHasLen {
					pos := ctx.PositionFor(stmt)
					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Returning boolean based on error message length - this is random guessing, not error detection")
					v.Severity = core.SeverityCritical
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Return false and let caller handle unknown errors, or use proper error type checking")
					v.WithContext("pattern", "return_length_check")
					return v
				}
			}
		}
	}
	return nil
}

// hasErrorLengthCheck checks if expression contains len(errorVar) comparison
func (r *ErrorLengthCheckRule) hasErrorLengthCheck(expr ast.Expr) bool {
	binExpr, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}

	if !isComparisonOp(binExpr.Op) {
		return false
	}

	// Check left side for len(errorVar)
	if call := r.extractLenCall(binExpr.X); call != nil {
		if r.isErrorRelatedArg(call) {
			return true
		}
	}

	// Check right side for len(errorVar)
	if call := r.extractLenCall(binExpr.Y); call != nil {
		if r.isErrorRelatedArg(call) {
			return true
		}
	}

	return false
}

// extractLenCall extracts len() call from expression
func (r *ErrorLengthCheckRule) extractLenCall(expr ast.Expr) *ast.CallExpr {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil
	}

	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return nil
	}

	if ident.Name == "len" && len(call.Args) == 1 {
		return call
	}

	return nil
}

// isErrorRelatedArg checks if len() argument is error MESSAGE string
// Returns true only for patterns like len(errMsg), len(errorMessage), len(err.Error())
// Returns false for error slices like len(errors), len(errorList)
func (r *ErrorLengthCheckRule) isErrorRelatedArg(call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}

	arg := call.Args[0]

	// Case 1: len(errMsg) - variable name indicates error MESSAGE string
	if ident, ok := arg.(*ast.Ident); ok {
		name := strings.ToLower(ident.Name)

		// Skip plural forms (error slices, not error message strings)
		if strings.HasSuffix(name, "errors") ||
			strings.HasSuffix(name, "errs") ||
			strings.HasSuffix(name, "messages") ||
			strings.HasSuffix(name, "list") {
			return false
		}

		// Only match singular error message variable names
		// errMsg, errorMessage, errorStr, errText, errString
		return name == "errmsg" ||
			name == "errormsg" ||
			name == "errormessage" ||
			name == "errmessage" ||
			name == "errorstr" ||
			name == "errstr" ||
			name == "errtext" ||
			name == "errortext" ||
			name == "errstring" ||
			name == "errorstring"
	}

	// Case 2: len(err.Error()) - method call to .Error() which returns string
	if callExpr, ok := arg.(*ast.CallExpr); ok {
		if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
			// Check for .Error() method
			if sel.Sel.Name == "Error" {
				return true
			}
		}
	}

	return false
}

// isComparisonOp checks if operator is a comparison
func isComparisonOp(op token.Token) bool {
	return op == token.LSS || op == token.LEQ ||
		op == token.GTR || op == token.GEQ ||
		op == token.EQL || op == token.NEQ
}
