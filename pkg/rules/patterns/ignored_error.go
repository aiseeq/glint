package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewIgnoredErrorRule())
}

// IgnoredErrorRule detects ignored error returns
type IgnoredErrorRule struct {
	*rules.BaseRule
}

// NewIgnoredErrorRule creates a new ignored error detector
func NewIgnoredErrorRule() *IgnoredErrorRule {
	return &IgnoredErrorRule{
		BaseRule: rules.NewBaseRule(
			"ignored-error",
			"patterns",
			"Detects error values that are explicitly ignored with blank identifier",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for ignored errors
func (r *IgnoredErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	// Skip test utility files (test.go, testing.go, test_*.go, etc.)
	pathLower := strings.ToLower(ctx.RelPath)
	if strings.Contains(pathLower, "/test") || strings.Contains(pathLower, "test_") ||
		strings.HasSuffix(pathLower, "/test.go") || strings.HasSuffix(pathLower, "/testing.go") {
		return nil
	}

	var violations []*core.Violation

	visitor := core.NewGoASTVisitor(ctx)
	visitor.OnAssignStmt(func(stmt *ast.AssignStmt) {
		violations = append(violations, r.checkBlankIdentifiers(ctx, stmt)...)
		violations = append(violations, r.checkMultiValueAssignment(ctx, stmt)...)
	})
	visitor.Visit()

	return violations
}

func (r *IgnoredErrorRule) checkBlankIdentifiers(ctx *core.FileContext, stmt *ast.AssignStmt) []*core.Violation {
	var violations []*core.Violation

	// Skip multi-value returns from single function call - check separately
	// e.g., `_, claims, err := fn()` has len(Lhs)=3 but len(Rhs)=1
	if len(stmt.Rhs) == 1 && len(stmt.Lhs) > 1 {
		return nil // Handled by checkMultiValueAssignment
	}

	// Check for nolint comment
	pos := ctx.PositionFor(stmt)
	lineContent := ctx.GetLine(pos.Line)
	if strings.Contains(lineContent, "nolint") || strings.Contains(lineContent, "errcheck") {
		return nil
	}

	for i, lhs := range stmt.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name != "_" || i >= len(stmt.Rhs) {
			continue
		}

		call, ok := stmt.Rhs[i].(*ast.CallExpr)
		if !ok {
			continue
		}

		funcName := core.ExtractFullFunctionName(call)
		if looksLikeErrorReturn(funcName) && !isKnownSafeToIgnore(funcName) {
			v := r.CreateViolation(ctx.RelPath, pos.Line, "Error from "+funcName+" is ignored")
			v.WithCode(lineContent)
			v.WithSuggestion("Handle the error or use a named blank identifier with comment")
			violations = append(violations, v)
		}
	}

	return violations
}

func (r *IgnoredErrorRule) checkMultiValueAssignment(ctx *core.FileContext, stmt *ast.AssignStmt) []*core.Violation {
	if len(stmt.Lhs) < 2 || len(stmt.Rhs) != 1 {
		return nil
	}

	// Check for nolint comment
	pos := ctx.PositionFor(stmt)
	lineContent := ctx.GetLine(pos.Line)
	if strings.Contains(lineContent, "nolint") || strings.Contains(lineContent, "errcheck") {
		return nil
	}

	// For 3+ return values, less likely the last is an error
	// Common patterns: (query, args, count), (value, ok, found), etc.
	if len(stmt.Lhs) > 2 {
		return nil
	}

	// Check if error is captured (not ignored)
	// Standard pattern: _, err := fn() or x, err := fn()
	hasErrorCapture := false
	allBlank := true
	for _, lhs := range stmt.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok {
			allBlank = false
			continue
		}
		if ident.Name != "_" {
			allBlank = false
			// Check if this looks like an error variable
			nameLower := strings.ToLower(ident.Name)
			if nameLower == "err" || strings.HasSuffix(nameLower, "err") ||
				strings.HasSuffix(nameLower, "error") {
				hasErrorCapture = true
			}
		}
	}

	// If error is captured in a variable, it's being handled
	if hasErrorCapture {
		return nil
	}

	// If not all blank, check if last value is ignored
	if !allBlank {
		lastLhs := stmt.Lhs[len(stmt.Lhs)-1]
		ident, ok := lastLhs.(*ast.Ident)
		if !ok || ident.Name != "_" {
			return nil // Last value is captured
		}
	}

	call, ok := stmt.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil
	}

	funcName := core.ExtractFullFunctionName(call)
	if isKnownSafeToIgnore(funcName) {
		return nil
	}

	// Only flag functions that look like they return errors
	if !looksLikeErrorReturn(funcName) {
		return nil
	}

	v := r.CreateViolation(ctx.RelPath, pos.Line, "Potential error ignored in multi-value assignment from "+funcName)
	v.WithCode(lineContent)
	v.WithSuggestion("Consider handling the error")
	return []*core.Violation{v}
}

func looksLikeErrorReturn(funcName string) bool {
	// Functions that commonly return errors
	errorPatterns := []string{
		"Write", "Read", "Close", "Open", "Create",
		"Parse", "Marshal", "Unmarshal",
		"Scan", "Query", "Exec",
		"Send", "Receive", "Dial", "Connect",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}

	return false
}

func isKnownSafeToIgnore(funcName string) bool {
	// Functions where ignoring return value is often acceptable
	safeSuffixes := []string{
		// Print functions
		"Printf", "Println", "Print",
		"Fprintf", "Fprintln", "Fprint",
		"Sprintf", "Sprint",
		// HTTP response writing - error usually can't be recovered
		"Write", "WriteHeader", "WriteString",
		// Close in defer - commonly ignored as cleanup
		"Close",
	}

	for _, suffix := range safeSuffixes {
		if strings.HasSuffix(funcName, suffix) {
			return true
		}
	}

	// Exact matches for common patterns
	safeExact := []string{
		"w.Write", "resp.Body.Close", "Body.Close",
		"rows.Close", "stmt.Close", "tx.Rollback",
		"file.Close", "conn.Close", "reader.Close",
	}

	for _, exact := range safeExact {
		if strings.Contains(funcName, exact) {
			return true
		}
	}

	// Functions that return (value, bool) not (value, error)
	// These are commonly ignored second return values
	boolReturnFuncs := []string{
		"CutPrefix", "CutSuffix", "Cut", // strings package
		"Float64", "Int64", "Uint64", // decimal/big number conversion (returns exact bool)
		"Load", "LoadOrStore", "Swap", // sync.Map methods
		"Lookup", // os.LookupEnv
		"ok",     // type assertions handled elsewhere
	}

	for _, fn := range boolReturnFuncs {
		if strings.HasSuffix(funcName, fn) || strings.Contains(funcName, "."+fn) {
			return true
		}
	}

	return false
}
