package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSilentErrorHandlingRule())
}

// SilentErrorHandlingRule detects error checks that don't log or propagate the error
// This implements CLAUDE.md principle: "Log all errors, never ignore silently"
// Catches: if err != nil { return X } without logging or returning the error
type SilentErrorHandlingRule struct {
	*rules.BaseRule
}

// NewSilentErrorHandlingRule creates the rule
func NewSilentErrorHandlingRule() *SilentErrorHandlingRule {
	return &SilentErrorHandlingRule{
		BaseRule: rules.NewBaseRule(
			"silent-error-handling",
			"patterns",
			"Detects error checks that neither log nor propagate the error",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for silent error handling
func (r *SilentErrorHandlingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	// Skip test utility files
	pathLower := strings.ToLower(ctx.RelPath)
	if strings.Contains(pathLower, "/test") || strings.Contains(pathLower, "test_") ||
		strings.HasSuffix(pathLower, "/test.go") || strings.HasSuffix(pathLower, "/testing.go") {
		return nil
	}

	var violations []*core.Violation

	// Track current function context for (T, bool) and predicate pattern detection
	var currentFunc *ast.FuncDecl
	var funcReturnsValueBool bool
	var funcIsBoolPredicate bool

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Track function declarations
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			currentFunc = funcDecl
			funcReturnsValueBool = r.functionReturnsValueBool(funcDecl)
			funcIsBoolPredicate = r.functionIsBoolPredicate(funcDecl)
			return true
		}

		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}

		// Check if this is err != nil
		if !r.isErrNotNilCheck(ifStmt.Cond) {
			return true
		}

		// Check if the if body handles the error properly
		// For (T, bool) functions, returning false is acceptable error handling
		if !r.bodyHandlesError(ifStmt.Body, funcReturnsValueBool) {
			pos := ctx.PositionFor(ifStmt)
			lineContent := ctx.GetLine(pos.Line)

			// Skip if has nolint
			if strings.Contains(lineContent, "nolint") {
				return true
			}

			// Skip if we're in a function returning (T, bool) and return includes false
			if funcReturnsValueBool && r.bodyReturnsFalse(ifStmt.Body) {
				return true
			}

			// Skip if we're in a predicate function (IsEmpty, IsValid, etc.)
			// Converting error to true/false is acceptable for predicates
			if funcIsBoolPredicate && r.bodyReturnsBool(ifStmt.Body) {
				return true
			}

			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Error check without logging or error propagation")
			v.WithCode(lineContent)
			v.WithSuggestion("Add logging or return the error to make failure visible")
			violations = append(violations, v)
		}

		return true
	})

	// Clear function context to avoid leaking between files
	_ = currentFunc // silence unused warning

	return violations
}

// isErrNotNilCheck detects `if err != nil` patterns
func (r *SilentErrorHandlingRule) isErrNotNilCheck(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}

	// Check if comparing to nil
	yNil, yIsNil := bin.Y.(*ast.Ident)
	if !yIsNil || yNil.Name != "nil" {
		return false
	}

	// Check if X is err or *err variable
	xIdent, xIsIdent := bin.X.(*ast.Ident)
	if !xIsIdent {
		return false
	}

	nameLower := strings.ToLower(xIdent.Name)
	return nameLower == "err" || strings.HasSuffix(nameLower, "err") || strings.HasSuffix(nameLower, "error")
}

// bodyHandlesError checks if the if body logs or propagates error
func (r *SilentErrorHandlingRule) bodyHandlesError(body *ast.BlockStmt, funcReturnsValueBool bool) bool {
	if body == nil {
		return false
	}

	for _, stmt := range body.List {
		if r.stmtHandlesError(stmt, funcReturnsValueBool) {
			return true
		}
	}

	return false
}

// functionReturnsValueBool checks if function returns (T, bool) pattern
func (r *SilentErrorHandlingRule) functionReturnsValueBool(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Type == nil || fn.Type.Results == nil {
		return false
	}

	results := fn.Type.Results.List
	if len(results) < 2 {
		return false
	}

	// Check if last return type is bool
	lastResult := results[len(results)-1]
	if ident, ok := lastResult.Type.(*ast.Ident); ok {
		return ident.Name == "bool"
	}

	return false
}

// functionIsBoolPredicate checks if function is a predicate returning only bool
// For predicates (IsEmpty, IsValid, HasX, CanX, etc.), converting error to bool is acceptable
func (r *SilentErrorHandlingRule) functionIsBoolPredicate(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Type == nil || fn.Type.Results == nil {
		return false
	}

	results := fn.Type.Results.List

	// Must return exactly one value
	if len(results) != 1 {
		return false
	}

	// Must be bool
	if ident, ok := results[0].Type.(*ast.Ident); ok {
		if ident.Name != "bool" {
			return false
		}
	} else {
		return false
	}

	// Function name must be a predicate pattern
	if fn.Name == nil {
		return false
	}
	nameLower := strings.ToLower(fn.Name.Name)

	predicatePatterns := []string{
		"is", "has", "can", "should", "must", "check", "verify", "validate",
		"contains", "exists", "empty", "valid", "equal", "match",
	}

	for _, pattern := range predicatePatterns {
		if strings.HasPrefix(nameLower, pattern) || strings.Contains(nameLower, pattern) {
			return true
		}
	}

	return false
}

// bodyReturnsFalse checks if the body contains return with false
func (r *SilentErrorHandlingRule) bodyReturnsFalse(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}

	for _, stmt := range body.List {
		if retStmt, ok := stmt.(*ast.ReturnStmt); ok {
			for _, result := range retStmt.Results {
				if ident, ok := result.(*ast.Ident); ok {
					if ident.Name == "false" {
						return true
					}
				}
			}
		}
	}

	return false
}

// bodyReturnsBool checks if the body contains return with true or false
func (r *SilentErrorHandlingRule) bodyReturnsBool(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}

	for _, stmt := range body.List {
		if retStmt, ok := stmt.(*ast.ReturnStmt); ok {
			for _, result := range retStmt.Results {
				if ident, ok := result.(*ast.Ident); ok {
					if ident.Name == "true" || ident.Name == "false" {
						return true
					}
				}
			}
		}
	}

	return false
}

// stmtHandlesError checks if a statement handles error
func (r *SilentErrorHandlingRule) stmtHandlesError(stmt ast.Stmt, funcReturnsValueBool bool) bool {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		// Check if return includes error
		for _, result := range s.Results {
			if r.exprReferencesError(result) {
				return true
			}
		}

	case *ast.ExprStmt:
		// Check for logging calls
		if call, ok := s.X.(*ast.CallExpr); ok {
			if r.isLoggingCall(call) {
				return true
			}
			// Check for panic
			if r.isPanicCall(call) {
				return true
			}
		}

	case *ast.IfStmt:
		// Nested if might handle error
		if r.bodyHandlesError(s.Body, funcReturnsValueBool) {
			return true
		}

	case *ast.BlockStmt:
		for _, inner := range s.List {
			if r.stmtHandlesError(inner, funcReturnsValueBool) {
				return true
			}
		}
	}

	return false
}

// exprReferencesError checks if expression references err variable or creates an error
func (r *SilentErrorHandlingRule) exprReferencesError(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		nameLower := strings.ToLower(e.Name)
		return nameLower == "err" || strings.HasSuffix(nameLower, "err") || strings.HasSuffix(nameLower, "error")

	case *ast.CallExpr:
		funcName := core.ExtractFullFunctionName(e)
		funcNameLower := strings.ToLower(funcName)

		// Any error-creating function is error propagation
		// errors.New(), fmt.Errorf(), errors.Wrap(), custom.NewError(), etc.
		errorCreatingPatterns := []string{
			"errorf", "wrap", "wrapf", "new", "newerror",
			"error", "fail", "makeerror", "createerror",
		}
		for _, pattern := range errorCreatingPatterns {
			if strings.Contains(funcNameLower, pattern) {
				return true
			}
		}

		// Also check if err is passed as argument (for Wrap patterns)
		for _, arg := range e.Args {
			if r.exprReferencesError(arg) {
				return true
			}
		}
	}

	return false
}

// isLoggingCall checks if call is a logging function
func (r *SilentErrorHandlingRule) isLoggingCall(call *ast.CallExpr) bool {
	funcName := core.ExtractFullFunctionName(call)
	funcNameLower := strings.ToLower(funcName)

	// Common logging patterns
	loggingPatterns := []string{
		"log.", "logger.", "logging.",
		"error", "warn", "info", "debug",
		"errorf", "warnf", "infof", "debugf",
		"errorstructured", "warnstructured", "infostructured",
		"printf", "println",
		"slog.",
		"record", // recordFailure, recordError, etc.
		"report", // reportError, etc.
		"notify", // notifyError, etc.
	}

	for _, pattern := range loggingPatterns {
		if strings.Contains(funcNameLower, pattern) {
			return true
		}
	}

	return false
}

// isPanicCall checks if call is panic
func (r *SilentErrorHandlingRule) isPanicCall(call *ast.CallExpr) bool {
	if ident, ok := call.Fun.(*ast.Ident); ok {
		return ident.Name == "panic"
	}
	return false
}
