package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorMaskingRule())
}

// ErrorMaskingRule detects patterns that mask errors instead of handling them properly
// This implements CLAUDE.md principle: "Fail explicitly, never degrade silently"
type ErrorMaskingRule struct {
	*rules.BaseRule
	goPatterns map[string]*regexp.Regexp
	tsPatterns map[string]*regexp.Regexp
}

// NewErrorMaskingRule creates the rule
func NewErrorMaskingRule() *ErrorMaskingRule {
	r := &ErrorMaskingRule{
		BaseRule: rules.NewBaseRule(
			"error-masking",
			"patterns",
			"Detects patterns that mask errors instead of handling them properly (CLAUDE.md: Fail explicitly, never degrade silently)",
			core.SeverityCritical,
		),
	}
	r.goPatterns = r.initGoPatterns()
	r.tsPatterns = r.initTSPatterns()
	return r
}

// initGoPatterns initializes Go-specific regex patterns
func (r *ErrorMaskingRule) initGoPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		// Explicit masking comments
		"hardcoded_return": regexp.MustCompile(`return\s+(\d+|"[^"]*"|0x[0-9a-fA-F]+)\s*//.*(?i)(default|backup)`),
		"success_masked":   regexp.MustCompile(`return\s+true\s*//.*(?i)(assume)`),

		// Error handling returning success/zero
		"error_return_true":    regexp.MustCompile(`if\s+err\s*!=\s*nil\s*\{[^}]*return\s+true`),
		"error_return_success": regexp.MustCompile(`if\s+err\s*!=\s*nil\s*\{[^}]*return\s+"(?:success|ok|done)"`),
		"error_return_zero":    regexp.MustCompile(`if\s+err\s*!=\s*nil\s*\{[^}]*return\s+(?:0|""|\[\]|\{\})[,\s}]`),

		// NOTE: Switch default is handled by AST analysis only (more precise)
		// Regex would cause false positives on display/suggestion functions

		// Fake/mock data in production
		"fake_data_return": regexp.MustCompile(`return\s+"(?:fake|mock|dummy|stub|test)[^"]*"`),

		// Panic recovery returning value
		"panic_to_return": regexp.MustCompile(`recover\(\)[^;]*;[^}]*return\s+(?:true|nil|""|0)`),

		// Zero balance on error
		"zero_on_error": regexp.MustCompile(`(?:buildZero|returnZero|getZero).*(?:error|fail|unavailable)`),
	}
}

// initTSPatterns initializes TypeScript-specific regex patterns
func (r *ErrorMaskingRule) initTSPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		// Environment variable with defaults
		"env_default": regexp.MustCompile(`process\.env\.[A-Z_]+\s*\|\|\s*['"][^'"]+['"]`),

		// Config with defaults
		"config_default": regexp.MustCompile(`config\??\.[a-zA-Z_]+\s*\|\|\s*['"][^'"]+['"]`),

		// Switch default masking
		"switch_default_value": regexp.MustCompile(`default:\s*(?:return\s+(?:['"][^'"]*['"]|true|false|\d+|\[\]|\{\}|null)|break;?\s*$)`),

		// Catch block masking
		"catch_hardcoded_return": regexp.MustCompile(`catch\s*\([^)]*\)\s*\{[^}]*return\s+(?:['"][^'"]*['"]|true|false|\d+|\[\]|\{\}|null)`),

		// Fake signatures
		"fake_signature": regexp.MustCompile(`return\s+['"]0x[0-9a-fA-F]*fake[0-9a-fA-F]*['"]`),

		// Error return empty
		"error_return_empty": regexp.MustCompile(`if\s*\([^)]*error[^)]*\)[^{]*\{[^}]*return\s+(?:null|\[\]|\{\}|"")`),
	}
}

// AnalyzeFile checks for error masking patterns
func (r *ErrorMaskingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.shouldSkipFile(ctx) {
		return nil
	}

	var violations []*core.Violation

	if ctx.IsGoFile() {
		violations = append(violations, r.analyzeGoFile(ctx)...)
	} else if ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() {
		violations = append(violations, r.analyzeTSFile(ctx)...)
	}

	return violations
}

// shouldSkipFile checks if file should be excluded
func (r *ErrorMaskingRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath

	// Skip test files
	if ctx.IsTestFile() {
		return true
	}

	// Skip vendor, node_modules
	if strings.Contains(path, "vendor/") || strings.Contains(path, "node_modules/") {
		return true
	}

	// Skip generated files
	if strings.Contains(path, "generated") || strings.Contains(path, ".gen.") {
		return true
	}

	// Skip CLI tools and analyzers (handle both /cmd/ and cmd/ paths)
	if strings.Contains(path, "/cmd/") || strings.HasPrefix(path, "cmd/") ||
		strings.Contains(path, "/tools/analyzers/") || strings.HasPrefix(path, "tools/analyzers/") {
		return true
	}

	// Skip templates
	if strings.Contains(path, "/templates/") {
		return true
	}

	// Skip test helper files (not _test.go but testing utilities)
	if strings.Contains(path, "/testing/") || strings.Contains(path, "test_helper") {
		return true
	}

	// Skip config module files - they contain documented development defaults
	if strings.Contains(path, "/config/") || strings.HasPrefix(path, "config/") {
		return true
	}

	return false
}

// analyzeGoFile analyzes Go file for error masking patterns
func (r *ErrorMaskingRule) analyzeGoFile(ctx *core.FileContext) []*core.Violation {
	violations := r.analyzeGoRegex(ctx)

	// AST-based analysis for more precise detection
	if ctx.HasGoAST() {
		violations = append(violations, r.analyzeGoAST(ctx)...)
	}

	return violations
}

// analyzeGoRegex uses regex patterns for Go files
func (r *ErrorMaskingRule) analyzeGoRegex(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		if r.isCommentOrEmpty(line) {
			continue
		}

		// Skip regex pattern definitions (they contain the patterns we're looking for)
		if r.isRegexPatternDefinition(line) {
			continue
		}

		for patternName, pattern := range r.goPatterns {
			if pattern.MatchString(line) {
				if r.isGoException(ctx.RelPath, line) {
					continue
				}

				v := r.createGoViolation(ctx, lineNum+1, line, patternName)
				violations = append(violations, v)
			}
		}
	}

	return violations
}

// analyzeGoAST uses Go AST for precise detection
func (r *ErrorMaskingRule) analyzeGoAST(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	visitor := core.NewGoASTVisitor(ctx)

	// Check if statements for error masking
	visitor.OnIfStmt(func(stmt *ast.IfStmt) {
		if v := r.checkErrorIfStmt(ctx, stmt); v != nil {
			violations = append(violations, v)
		}
	})

	visitor.Visit()

	// Check switch statements in functions that return error
	// This is more conservative to avoid false positives on display/label functions
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		// Only check functions that should return error but might not
		if !r.functionShouldReturnError(funcDecl) {
			return true
		}

		// Check switch statements in this function
		ast.Inspect(funcDecl.Body, func(inner ast.Node) bool {
			if stmt, ok := inner.(*ast.SwitchStmt); ok {
				if v := r.checkSwitchDefault(ctx, stmt); v != nil {
					violations = append(violations, v)
				}
			}
			return true
		})

		return true
	})

	return violations
}

// functionShouldReturnError checks if function signature suggests it should return error
func (r *ErrorMaskingRule) functionShouldReturnError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}

	// Check if function name suggests error-returning behavior
	name := fn.Name.Name
	errorIndicators := []string{
		"Get", "Load", "Fetch", "Read", "Write", "Create", "Delete",
		"Update", "Save", "Open", "Close", "Connect", "Send", "Receive",
		"Parse", "Validate", "Process", "Execute", "Handle",
	}

	hasIndicator := false
	for _, ind := range errorIndicators {
		if strings.HasPrefix(name, ind) || strings.Contains(name, ind) {
			hasIndicator = true
			break
		}
	}

	if !hasIndicator {
		return false
	}

	// Check if last return type is error
	results := fn.Type.Results.List
	if len(results) == 0 {
		return false
	}

	lastResult := results[len(results)-1]
	if ident, ok := lastResult.Type.(*ast.Ident); ok {
		return ident.Name == "error"
	}

	return false
}

// checkErrorIfStmt checks if statement for error masking patterns
func (r *ErrorMaskingRule) checkErrorIfStmt(ctx *core.FileContext, stmt *ast.IfStmt) *core.Violation {
	// Check if condition is "err != nil"
	if !r.isErrNilCheck(stmt.Cond) {
		return nil
	}

	// Skip semantic boolean functions (Is*, Has*, Can*, Should*, etc.)
	if r.isInSemanticBooleanFunc(ctx, stmt) {
		return nil
	}

	// Check if error is logged before return (acceptable pattern)
	info := r.analyzeErrorBlock(stmt.Body.List)
	if r.isAcceptableDenialPattern(info) {
		return nil
	}

	// Find first problematic return
	return r.findProblematicReturn(ctx, stmt, info)
}

// blockAnalysis holds analysis results of an error handling block
type blockAnalysis struct {
	hasLogging bool
	returnStmt *ast.ReturnStmt
}

// analyzeErrorBlock analyzes statements in error handling block for logging and return
func (r *ErrorMaskingRule) analyzeErrorBlock(stmts []ast.Stmt) blockAnalysis {
	var info blockAnalysis
	for _, bodyStmt := range stmts {
		if exprStmt, ok := bodyStmt.(*ast.ExprStmt); ok {
			if call, ok := exprStmt.X.(*ast.CallExpr); ok {
				funcName := core.ExtractFullFunctionName(call)
				if r.isLoggingCall(funcName) {
					info.hasLogging = true
				}
			}
		}
		if ret, ok := bodyStmt.(*ast.ReturnStmt); ok {
			info.returnStmt = ret
		}
	}
	return info
}

// isLoggingCall checks if function name indicates a logging call
func (r *ErrorMaskingRule) isLoggingCall(funcName string) bool {
	return strings.Contains(funcName, "log") || strings.Contains(funcName, "Log") ||
		strings.Contains(funcName, "Error") || strings.Contains(funcName, "Warn")
}

// isAcceptableDenialPattern checks if block is an acceptable logged denial pattern
func (r *ErrorMaskingRule) isAcceptableDenialPattern(info blockAnalysis) bool {
	if !info.hasLogging || info.returnStmt == nil {
		return false
	}
	for _, result := range info.returnStmt.Results {
		if ident, ok := result.(*ast.Ident); ok && ident.Name == "false" {
			return true // Logged error + return false is acceptable
		}
		if lit, ok := result.(*ast.BasicLit); ok && lit.Value == `""` {
			return true // Logged error + return "" is acceptable
		}
	}
	return false
}

// findProblematicReturn finds problematic returns in error handling block
func (r *ErrorMaskingRule) findProblematicReturn(ctx *core.FileContext, stmt *ast.IfStmt, _ blockAnalysis) *core.Violation {
	for _, bodyStmt := range stmt.Body.List {
		retStmt, ok := bodyStmt.(*ast.ReturnStmt)
		if !ok {
			continue
		}
		if r.returnIncludesError(retStmt) || r.isCommaOkReturnWithFalse(retStmt) {
			continue
		}
		for _, result := range retStmt.Results {
			if r.isProblematicReturn(result) {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line, "Error condition returns success value, masking the error")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Return the error or handle it explicitly")
				v.WithContext("pattern", "error_return_value")
				return v
			}
		}
	}
	return nil
}

// isCommaOkReturnWithFalse checks if return is a comma-ok pattern ending with false
// Pattern: return value, false - indicates failure in Go idiom
func (r *ErrorMaskingRule) isCommaOkReturnWithFalse(stmt *ast.ReturnStmt) bool {
	if len(stmt.Results) < 2 {
		return false
	}

	// Check if last return value is false (comma-ok failure indicator)
	lastResult := stmt.Results[len(stmt.Results)-1]
	if ident, ok := lastResult.(*ast.Ident); ok {
		return ident.Name == "false"
	}

	return false
}

// returnIncludesError checks if return statement includes proper error handling
func (r *ErrorMaskingRule) returnIncludesError(stmt *ast.ReturnStmt) bool {
	for _, result := range stmt.Results {
		// Check for error variable (err)
		if ident, ok := result.(*ast.Ident); ok {
			if ident.Name == "err" {
				return true
			}
		}

		// Check for fmt.Errorf or errors.New
		if call, ok := result.(*ast.CallExpr); ok {
			funcName := core.ExtractFullFunctionName(call)
			if funcName == "fmt.Errorf" || funcName == "errors.New" ||
				strings.HasSuffix(funcName, "Errorf") || strings.HasSuffix(funcName, "Error") {
				return true
			}
		}
	}
	return false
}

// isInSemanticBooleanFunc checks if statement is inside a semantic boolean function
// Functions like IsEmpty, HasPermission, CanAccess, ShouldRetry have semantic boolean returns
// where returning true/false on error is intentional behavior, not error masking
func (r *ErrorMaskingRule) isInSemanticBooleanFunc(ctx *core.FileContext, stmt ast.Stmt) bool {
	// Find the enclosing function
	var funcName string
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		// Check if stmt is within this function's body
		if fn.Body != nil && fn.Body.Pos() <= stmt.Pos() && stmt.End() <= fn.Body.End() {
			funcName = fn.Name.Name
			return false // Found it, stop searching
		}
		return true
	})

	if funcName == "" {
		return false
	}

	// Check for semantic boolean function prefixes
	semanticPrefixes := []string{
		"Is", "Has", "Can", "Should", "Must", "Will", "Was", "Does", "Did",
		"Contains", "Exists", "Valid", "Empty", "Nil", "Zero", "Equal",
	}

	for _, prefix := range semanticPrefixes {
		if strings.HasPrefix(funcName, prefix) {
			return true
		}
	}

	return false
}

// isErrNilCheck checks if condition is "err != nil" (not "err == nil")
func (r *ErrorMaskingRule) isErrNilCheck(expr ast.Expr) bool {
	binExpr, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}

	// Must be "err != nil", not "err == nil"
	// "err == nil" with return false is valid pattern for error type checking (IsNotFound, etc.)
	if binExpr.Op != token.NEQ {
		return false
	}

	ident, ok := binExpr.X.(*ast.Ident)
	if !ok {
		return false
	}

	if ident.Name != "err" {
		return false
	}

	nilIdent, isNil := binExpr.Y.(*ast.Ident)
	return isNil && nilIdent.Name == "nil"
}

// isProblematicReturn checks if return value masks the error
func (r *ErrorMaskingRule) isProblematicReturn(expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.Ident:
		// Only "true" is problematic - it masks error as success
		// "false" is acceptable as it indicates failure (comma-ok pattern, deny-by-default)
		return v.Name == "true"
	case *ast.BasicLit:
		// Empty string, zero values
		return v.Value == `""` || v.Value == "0"
	}
	return false
}

// checkSwitchDefault checks switch for problematic default
func (r *ErrorMaskingRule) checkSwitchDefault(ctx *core.FileContext, stmt *ast.SwitchStmt) *core.Violation {
	if stmt.Body == nil {
		return nil
	}

	for _, clause := range stmt.Body.List {
		caseClause, ok := clause.(*ast.CaseClause)
		if !ok {
			continue
		}

		// Only check default clause (List is nil for default)
		if caseClause.List != nil {
			continue
		}

		// Check if default returns a value (not error)
		for _, bodyStmt := range caseClause.Body {
			retStmt, ok := bodyStmt.(*ast.ReturnStmt)
			if !ok {
				continue
			}

			// Check if return is not an error
			if r.isDefaultMaskingReturn(retStmt) {
				pos := ctx.PositionFor(stmt)
				v := r.CreateViolation(ctx.RelPath, pos.Line, "Switch default returns value instead of error")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Return an error for unknown cases: default: return fmt.Errorf(\"unknown case\")")
				v.WithContext("pattern", "switch_default_value")
				return v
			}
		}
	}

	return nil
}

// isDefaultMaskingReturn checks if return is a problematic masking
func (r *ErrorMaskingRule) isDefaultMaskingReturn(stmt *ast.ReturnStmt) bool {
	if len(stmt.Results) == 0 {
		return false
	}

	// Single value return that's not an error
	if len(stmt.Results) == 1 {
		switch v := stmt.Results[0].(type) {
		case *ast.Ident:
			return v.Name == "true" || v.Name == "false" || v.Name == "nil"
		case *ast.BasicLit:
			return true // Any literal is suspicious in default
		}
	}

	return false
}

// analyzeTSFile analyzes TypeScript/JavaScript file for masking patterns
func (r *ErrorMaskingRule) analyzeTSFile(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		if r.isCommentOrEmpty(line) {
			continue
		}

		for patternName, pattern := range r.tsPatterns {
			if pattern.MatchString(line) {
				if r.isTSException(ctx.RelPath, line) {
					continue
				}

				v := r.createTSViolation(ctx, lineNum+1, line, patternName)
				violations = append(violations, v)
			}
		}
	}

	return violations
}

// isCommentOrEmpty checks if line is a comment or empty
func (r *ErrorMaskingRule) isCommentOrEmpty(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*")
}

// isRegexPatternDefinition checks if line is defining a regex pattern
func (r *ErrorMaskingRule) isRegexPatternDefinition(line string) bool {
	return strings.Contains(line, "regexp.MustCompile") ||
		strings.Contains(line, "regexp.Compile")
}

// isGoException checks if pattern match is a valid exception
func (r *ErrorMaskingRule) isGoException(path, line string) bool {
	// Config files with documented defaults (case-insensitive)
	if strings.Contains(path, "config") {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "// default") ||
			strings.Contains(lineLower, "//default") ||
			strings.Contains(lineLower, "default value") ||
			strings.Contains(lineLower, "default if") {
			return true
		}
	}

	// Validation returning false for invalid input
	if strings.Contains(path, "valid") && strings.Contains(line, "return false") {
		return true
	}

	// Pagination defaults
	if strings.Contains(line, "defaultLimit") || strings.Contains(line, "defaultPage") {
		return true
	}

	// Config getter functions returning documented defaults
	if strings.Contains(path, "config") && strings.Contains(line, "return") {
		// Allow returns with documented fallback comments
		if strings.Contains(line, "// ") && (strings.Contains(strings.ToLower(line), "limit") ||
			strings.Contains(strings.ToLower(line), "gas") ||
			strings.Contains(strings.ToLower(line), "rate") ||
			strings.Contains(strings.ToLower(line), "timeout")) {
			return true
		}
	}

	// E2E test support - "test-" prefix returns are intentional for test mode
	if strings.Contains(line, `"test-`) && strings.Contains(line, "return") {
		return true
	}

	return false
}

// isTSException checks if pattern match is a valid exception for TS
func (r *ErrorMaskingRule) isTSException(path, line string) bool {
	// next.config.js defaults
	if strings.Contains(path, "next.config") {
		return true
	}

	// Test utilities
	if strings.Contains(path, "test") || strings.Contains(path, "spec") {
		return true
	}

	// E2E test utilities
	if strings.Contains(path, "e2e") {
		return true
	}

	// Scripts and setup files
	if strings.Contains(path, "scripts/") || strings.Contains(path, "setup") {
		return true
	}

	return false
}

// createGoViolation creates a violation for Go pattern
func (r *ErrorMaskingRule) createGoViolation(ctx *core.FileContext, lineNum int, line, patternName string) *core.Violation {
	msg, suggestion, severity := r.getGoViolationDetails(patternName)

	v := core.NewViolation(r.Name(), r.Category(), ctx.RelPath, lineNum, severity, msg)
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", patternName)
	v.WithContext("language", "go")

	return v
}

// violationInfo holds message, suggestion and severity for a pattern
type violationInfo struct {
	msg        string
	suggestion string
	severity   core.Severity
}

// goViolationDetails maps pattern names to violation details
var goViolationDetails = map[string]violationInfo{
	"hardcoded_return":     {"Function returns hardcoded value instead of handling error", "Move value to configuration or return error", core.SeverityHigh},
	"success_masked":       {"Function returns success, masking real problems", "Return error or add proper error handling", core.SeverityCritical},
	"error_return_true":    {"Returns true after error - masks the problem", "Return error or add retry mechanism", core.SeverityCritical},
	"error_return_success": {"Returns success string after error", "Return error or add proper error handling", core.SeverityCritical},
	"error_return_zero":    {"Returns zero value after error", "Return error or add explicit handling", core.SeverityHigh},
	"switch_default_value": {"Switch default returns value instead of error", "Return error for unknown cases: default: return fmt.Errorf(\"unknown case\")", core.SeverityCritical},
	"fake_data_return":     {"Returns fake/mock data in production code", "Remove fake data or move to test configuration", core.SeverityHigh},
	"panic_to_return":      {"Panic masked by returning value instead of error", "Return error from recover block", core.SeverityCritical},
	"zero_on_error":        {"Zero value returned on system error - critical UX problem", "Show user the real error instead of fake zero", core.SeverityCritical},
}

// getGoViolationDetails returns message, suggestion, and severity for Go pattern
func (r *ErrorMaskingRule) getGoViolationDetails(patternName string) (string, string, core.Severity) {
	if info, ok := goViolationDetails[patternName]; ok {
		return info.msg, info.suggestion, info.severity
	}
	return "Suspicious error masking pattern detected", "Check if this pattern is necessary", core.SeverityMedium
}

// createTSViolation creates a violation for TypeScript pattern
func (r *ErrorMaskingRule) createTSViolation(ctx *core.FileContext, lineNum int, line, patternName string) *core.Violation {
	msg, suggestion, severity := r.getTSViolationDetails(patternName)

	v := core.NewViolation(r.Name(), r.Category(), ctx.RelPath, lineNum, severity, msg)
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", patternName)
	v.WithContext("language", "typescript")

	return v
}

// tsViolationDetails maps TS pattern names to violation details
var tsViolationDetails = map[string]violationInfo{
	"env_default":            {"Environment variable with hardcoded default may mask configuration problems", "Use fail-fast validation: if (!process.env.VAR) throw new Error()", core.SeverityHigh},
	"config_default":         {"Config property with hardcoded default may become stale", "Move defaults to centralized configuration", core.SeverityHigh},
	"switch_default_value":   {"Switch default with value masks unknown cases", "Replace with explicit error: default: throw new Error('Unknown case')", core.SeverityCritical},
	"catch_hardcoded_return": {"Try-catch with hardcoded value masks real errors", "Rethrow error or return explicit error object", core.SeverityCritical},
	"fake_signature":         {"Fake signature in code", "Use real signature from test configuration", core.SeverityHigh},
	"error_return_empty":     {"Returns empty value after error check", "Add proper error handling or show user the error", core.SeverityMedium},
}

// getTSViolationDetails returns message, suggestion, and severity for TS pattern
func (r *ErrorMaskingRule) getTSViolationDetails(patternName string) (string, string, core.Severity) {
	if info, ok := tsViolationDetails[patternName]; ok {
		return info.msg, info.suggestion, info.severity
	}
	return "Suspicious error masking pattern detected", "Check if this pattern is necessary", core.SeverityMedium
}
