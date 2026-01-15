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

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}

		// Check if this is err != nil
		if !r.isErrNotNilCheck(ifStmt.Cond) {
			return true
		}

		// Check if the if body handles the error properly
		if !r.bodyHandlesError(ifStmt.Body) {
			pos := ctx.PositionFor(ifStmt)
			lineContent := ctx.GetLine(pos.Line)

			// Skip if has nolint
			if strings.Contains(lineContent, "nolint") {
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
func (r *SilentErrorHandlingRule) bodyHandlesError(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}

	for _, stmt := range body.List {
		if r.stmtHandlesError(stmt) {
			return true
		}
	}

	return false
}

// stmtHandlesError checks if a statement handles error
func (r *SilentErrorHandlingRule) stmtHandlesError(stmt ast.Stmt) bool {
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
		if r.bodyHandlesError(s.Body) {
			return true
		}

	case *ast.BlockStmt:
		for _, inner := range s.List {
			if r.stmtHandlesError(inner) {
				return true
			}
		}
	}

	return false
}

// exprReferencesError checks if expression references err variable
func (r *SilentErrorHandlingRule) exprReferencesError(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		nameLower := strings.ToLower(e.Name)
		return nameLower == "err" || strings.HasSuffix(nameLower, "err") || strings.HasSuffix(nameLower, "error")

	case *ast.CallExpr:
		// fmt.Errorf("...: %w", err) or errors.Wrap(err, ...)
		funcName := core.ExtractFullFunctionName(e)
		if strings.Contains(funcName, "Errorf") || strings.Contains(funcName, "Wrap") ||
			strings.Contains(funcName, "Error") || strings.Contains(funcName, "New") {
			// Check if err is in arguments
			for _, arg := range e.Args {
				if r.exprReferencesError(arg) {
					return true
				}
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
