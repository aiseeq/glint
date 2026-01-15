package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFallbackReturnRule())
}

// FallbackReturnRule detects fallback patterns that silently degrade instead of failing explicitly
// This implements CLAUDE.md principle: "Fail explicitly, never degrade silently"
// Catches: return testProvider, return mockService on errors
// Excludes: functions with "OrDefault" in name, parse* functions, singleton getters, middleware defensive code
type FallbackReturnRule struct {
	*rules.BaseRule
	fallbackPatterns  []*regexp.Regexp
	goContextPatterns []*regexp.Regexp
	tsContextPatterns []*regexp.Regexp
}

// NewFallbackReturnRule creates the rule
func NewFallbackReturnRule() *FallbackReturnRule {
	r := &FallbackReturnRule{
		BaseRule: rules.NewBaseRule(
			"fallback-return",
			"patterns",
			"Detects fallback patterns that silently degrade instead of failing explicitly",
			core.SeverityCritical,
		),
	}
	r.fallbackPatterns = r.initFallbackPatterns()
	r.goContextPatterns = r.initGoContextPatterns()
	r.tsContextPatterns = r.initTSContextPatterns()
	return r
}

// initFallbackPatterns initializes patterns for detecting fallback returns
func (r *FallbackReturnRule) initFallbackPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// Return provider/service fallbacks (test*, mock*, fake*, stub*, dummy*, fallback*)
		regexp.MustCompile(`return\s+(?:test|mock|fake|stub|dummy|fallback)[A-Z]\w*`),

		// Return *Provider fallback after error (but not singleton getters)
		regexp.MustCompile(`return\s+\w*(?:Provider|Service|Client|Handler)\s*$`),

		// Explicit fallback naming
		regexp.MustCompile(`(?i)return\s+\w*fallback\w*`),

		// Return new*Mock/Test/Fake
		regexp.MustCompile(`return\s+[Nn]ew(?:Mock|Test|Fake|Stub|Dummy)\w*\(`),

		// Assignment then return pattern: provider = testProvider
		regexp.MustCompile(`=\s*(?:test|mock|fake|stub|dummy|fallback)[A-Z]\w*`),
	}
}

// initGoContextPatterns detects error/failure context for Go
func (r *FallbackReturnRule) initGoContextPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// Error check context
		regexp.MustCompile(`if\s+err\s*!=\s*nil`),
		regexp.MustCompile(`if\s+\w+\s*==\s*nil`),
		regexp.MustCompile(`if\s+!\w+`),

		// Error in comment
		regexp.MustCompile(`//.*(?i)(?:error|fail|unavailable|fallback)`),

		// Fallback comment
		regexp.MustCompile(`//.*(?i)(?:use|return|fall\s*back|degrad)`),
	}
}

// initTSContextPatterns detects error/failure context for TypeScript
func (r *FallbackReturnRule) initTSContextPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// Error check context - TS style
		regexp.MustCompile(`if\s*\(\s*!\w+`),                    // if (!svc)
		regexp.MustCompile(`if\s*\(\s*\w+\s*===?\s*null`),       // if (x === null)
		regexp.MustCompile(`if\s*\(\s*\w+\s*===?\s*undefined`),  // if (x === undefined)
		regexp.MustCompile(`if\s*\(\s*err`),                     // if (err...)

		// Error in comment
		regexp.MustCompile(`//.*(?i)(?:error|fail|unavailable|fallback)`),

		// Fallback comment
		regexp.MustCompile(`//.*(?i)(?:use|return|fall\s*back|degrad)`),
	}
}

// AnalyzeFile checks for fallback return patterns
func (r *FallbackReturnRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
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
func (r *FallbackReturnRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath

	// Skip test files - they legitimately use mocks
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

	// Skip testing utilities - they create mocks/fakes
	if strings.Contains(path, "/testing/") || strings.Contains(path, "test_helper") ||
		strings.Contains(path, "_test") || strings.Contains(path, "testutil") {
		return true
	}

	// Skip mock/fake implementations themselves
	if strings.Contains(path, "/mock") || strings.Contains(path, "/fake") ||
		strings.Contains(path, "/stub") || strings.Contains(path, "/testdata") {
		return true
	}

	return false
}

// analyzeGoFile analyzes Go file for fallback patterns
func (r *FallbackReturnRule) analyzeGoFile(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	// Regex-based analysis
	violations = append(violations, r.analyzeGoRegex(ctx)...)

	// AST-based analysis for more precise detection
	if ctx.HasGoAST() {
		violations = append(violations, r.analyzeGoAST(ctx)...)
	}

	return violations
}

// analyzeGoRegex uses regex patterns for Go files
func (r *FallbackReturnRule) analyzeGoRegex(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check for fallback patterns
		for _, pattern := range r.fallbackPatterns {
			if pattern.MatchString(line) {
				// Check if this is in error handling context
				if r.isInGoContext(ctx.Lines, lineNum) {
					if !r.isGoException(ctx, line, lineNum) {
						v := r.createViolation(ctx, lineNum+1, line)
						violations = append(violations, v)
						break // One violation per line
					}
				}
			}
		}
	}

	return violations
}

// isInGoContext checks if line is within error handling context for Go
func (r *FallbackReturnRule) isInGoContext(lines []string, lineNum int) bool {
	// Check previous 5 lines for error context
	start := lineNum - 5
	if start < 0 {
		start = 0
	}

	for i := start; i <= lineNum; i++ {
		for _, pattern := range r.goContextPatterns {
			if pattern.MatchString(lines[i]) {
				return true
			}
		}
	}

	return false
}

// analyzeGoAST uses Go AST for precise detection
func (r *FallbackReturnRule) analyzeGoAST(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Check if statements with error handling
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}

		// Check if condition involves error
		if !r.isErrorCondition(ifStmt.Cond) {
			return true
		}

		// Check function-level exceptions first
		if r.isFunctionException(ctx, ifStmt) {
			return true
		}

		// Check body for fallback returns
		hasReturn := false
		for _, stmt := range ifStmt.Body.List {
			retStmt, ok := stmt.(*ast.ReturnStmt)
			if !ok {
				continue
			}
			hasReturn = true

			// Skip if error is returned explicitly
			if r.returnsError(retStmt) {
				continue
			}

			for _, result := range retStmt.Results {
				if r.isFallbackReturn(result) {
					pos := ctx.PositionFor(retStmt)
					v := r.CreateViolation(ctx.RelPath, pos.Line, "Fallback return on error - silently degrades instead of failing explicitly")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Return the error instead of fallback value. Caller should decide recovery strategy.")
					violations = append(violations, v)
				}
			}
		}

		// NEW: Detect error-ignoring assignment pattern (CLAUDE.md violation)
		// Pattern: if err != nil { variable = fallbackValue } without return
		if !hasReturn && r.isErrNotNilCondition(ifStmt.Cond) {
			violations = append(violations, r.detectErrorIgnoringAssignment(ctx, ifStmt)...)
		}

		return true
	})

	return violations
}

// returnsError checks if return statement includes an error
func (r *FallbackReturnRule) returnsError(stmt *ast.ReturnStmt) bool {
	for _, result := range stmt.Results {
		// Check for error variable
		if ident, ok := result.(*ast.Ident); ok {
			if ident.Name == "err" {
				return true
			}
		}
		// Check for fmt.Errorf, errors.New, etc.
		if call, ok := result.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Errorf" || sel.Sel.Name == "New" || sel.Sel.Name == "Wrap" {
					return true
				}
			}
		}
	}
	return false
}

// isFunctionException checks if the enclosing function is an exception
func (r *FallbackReturnRule) isFunctionException(ctx *core.FileContext, stmt ast.Node) bool {
	// Find enclosing function
	var funcName string
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if fn.Body != nil && fn.Body.Pos() <= stmt.Pos() && stmt.End() <= fn.Body.End() {
			funcName = fn.Name.Name
			return false
		}
		return true
	})

	if funcName == "" {
		return false
	}

	funcLower := strings.ToLower(funcName)

	// Functions with "OrDefault", "Default" pattern - by design return defaults
	if strings.Contains(funcLower, "ordefault") || strings.HasSuffix(funcLower, "default") {
		return true
	}

	// Parse functions with default parameter - legitimate
	if strings.HasPrefix(funcLower, "parse") && strings.Contains(funcLower, "param") {
		return true
	}

	// Singleton getters (Get*Manager, Get*EventManager) - not fallbacks
	if strings.HasPrefix(funcLower, "get") && (strings.HasSuffix(funcLower, "manager") ||
		strings.HasSuffix(funcLower, "eventmanager") || strings.HasSuffix(funcLower, "instance")) {
		return true
	}

	// GetRealIP, GetClientKey - defensive programming for middleware
	if strings.HasPrefix(funcLower, "get") && (strings.Contains(funcLower, "ip") ||
		strings.Contains(funcLower, "key") || strings.Contains(funcLower, "client")) {
		return true
	}

	return false
}

// isErrorCondition checks if condition is error-related
func (r *FallbackReturnRule) isErrorCondition(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		// err != nil or err == nil
		if ident, ok := e.X.(*ast.Ident); ok {
			if ident.Name == "err" {
				return true
			}
		}
		// something == nil (nil check)
		if _, ok := e.Y.(*ast.Ident); ok {
			return true
		}
	case *ast.UnaryExpr:
		// !ok, !valid, etc.
		if e.Op.String() == "!" {
			return true
		}
	}
	return false
}

// isFallbackReturn checks if return value is a fallback
func (r *FallbackReturnRule) isFallbackReturn(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		name := e.Name
		nameLower := strings.ToLower(name)

		// Skip status constants (testStatusPassed, statusOK, etc.)
		if strings.Contains(nameLower, "status") {
			return false
		}

		// Skip "unknown" constant - it's a label, not a fallback value
		if nameLower == "unknown" || strings.HasSuffix(nameLower, "unknown") {
			return false
		}

		// Check for fallback naming patterns
		fallbackPrefixes := []string{"test", "mock", "fake", "stub", "dummy", "fallback"}
		for _, prefix := range fallbackPrefixes {
			if strings.HasPrefix(nameLower, prefix) {
				return true
			}
		}

		// Check for *Provider, *Service etc with fallback prefix
		fallbackSuffixes := []string{"provider", "service", "client", "handler"}
		for _, suffix := range fallbackSuffixes {
			if strings.HasSuffix(nameLower, suffix) {
				// Only flag if also has fallback-indicating prefix
				for _, prefix := range fallbackPrefixes {
					if strings.HasPrefix(nameLower, prefix) {
						return true
					}
				}
			}
		}

	case *ast.CallExpr:
		// Check for NewMock*, NewTest*, NewFake* calls
		if fun, ok := e.Fun.(*ast.Ident); ok {
			nameLower := strings.ToLower(fun.Name)
			if strings.HasPrefix(nameLower, "newmock") ||
				strings.HasPrefix(nameLower, "newtest") ||
				strings.HasPrefix(nameLower, "newfake") ||
				strings.HasPrefix(nameLower, "newstub") ||
				strings.HasPrefix(nameLower, "newdummy") {
				return true
			}
		}
	}

	return false
}

// isGoException checks if this is a valid exception
func (r *FallbackReturnRule) isGoException(ctx *core.FileContext, line string, lineNum int) bool {
	lineLower := strings.ToLower(line)
	path := ctx.RelPath
	lines := ctx.Lines

	// Factory functions that create test implementations
	if strings.Contains(path, "factory") || strings.Contains(path, "builder") {
		return true
	}

	// Middleware code - defensive programming is expected
	if strings.Contains(path, "middleware") || strings.Contains(path, "rate_limit") {
		return true
	}

	// Health check code - test status constants
	if strings.Contains(path, "health") {
		return true
	}

	// Helpers with explicit default parameters
	if strings.Contains(path, "helpers") || strings.Contains(path, "helper") {
		// Check if function has "default" in parameter name (by looking at func signature)
		for i := lineNum; i >= 0 && i > lineNum-15; i-- {
			if strings.Contains(lines[i], "func ") && strings.Contains(strings.ToLower(lines[i]), "default") {
				return true
			}
		}
	}

	// Explicit "for testing" comment
	if strings.Contains(lineLower, "// for test") || strings.Contains(lineLower, "//for test") {
		return true
	}

	// Check if function is explicitly a test factory
	for i := lineNum; i >= 0 && i > lineNum-15; i-- {
		funcLine := lines[i]
		funcLower := strings.ToLower(funcLine)

		// Functions with OrDefault, Default in name
		if strings.Contains(funcLine, "func ") {
			if strings.Contains(funcLower, "ordefault") || strings.Contains(funcLower, "default") {
				return true
			}
			// Parse functions with default parameter
			if strings.Contains(funcLower, "parse") {
				return true
			}
			// Singleton getters
			if strings.Contains(funcLower, "get") && strings.Contains(funcLower, "manager") {
				return true
			}
			break // Found function declaration, stop looking
		}
	}

	// Check if error is already being returned on the same line
	if strings.Contains(line, "fmt.Errorf") || strings.Contains(line, "errors.") {
		return true
	}

	// DI container test mode setup
	if strings.Contains(lineLower, "// di") || strings.Contains(lineLower, "// dependency injection") {
		return true
	}

	return false
}

// analyzeTSFile analyzes TypeScript/JavaScript file for fallback patterns
func (r *FallbackReturnRule) analyzeTSFile(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	// Patterns for TS - case insensitive for variable names
	tsPatterns := []*regexp.Regexp{
		// Return mock/test/fake (case insensitive after prefix)
		regexp.MustCompile(`(?i)return\s+(?:mock|test|fake|stub|dummy)\w+`),

		// Fallback in variable assignment
		regexp.MustCompile(`(?i)=\s+(?:mock|test|fake|fallback)\w+`),

		// || fallback pattern (but not for common defaults)
		regexp.MustCompile(`(?i)\|\|\s*(?:mock|test|fake)\w+`),

		// ?? fallback pattern
		regexp.MustCompile(`(?i)\?\?\s*(?:mock|test|fake|fallback)\w+`),
	}

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, pattern := range tsPatterns {
			if pattern.MatchString(line) {
				if r.isInTSContext(ctx.Lines, lineNum) && !r.isTSException(ctx.RelPath, line) {
					v := r.createTSViolation(ctx, lineNum+1, line)
					violations = append(violations, v)
					break
				}
			}
		}
	}

	return violations
}

// isInTSContext checks if line is within error handling context for TypeScript
func (r *FallbackReturnRule) isInTSContext(lines []string, lineNum int) bool {
	// Check previous 5 lines for error context
	start := lineNum - 5
	if start < 0 {
		start = 0
	}

	for i := start; i <= lineNum; i++ {
		for _, pattern := range r.tsContextPatterns {
			if pattern.MatchString(lines[i]) {
				return true
			}
		}
	}

	return false
}

// isTSException checks if this is a valid exception for TS
func (r *FallbackReturnRule) isTSException(path, line string) bool {
	// Test files
	if strings.Contains(path, ".test.") || strings.Contains(path, ".spec.") ||
		strings.Contains(path, "__tests__") || strings.Contains(path, "__mocks__") {
		return true
	}

	// Mock definitions
	if strings.Contains(path, "/mock") || strings.Contains(path, "/fake") {
		return true
	}

	// Storybook
	if strings.Contains(path, ".stories.") {
		return true
	}

	return false
}

// createViolation creates a violation for Go fallback
func (r *FallbackReturnRule) createViolation(ctx *core.FileContext, lineNum int, line string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, "Fallback return detected - silently degrades instead of failing explicitly")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Return error instead of fallback. Principle: 'Fail explicitly, never degrade silently'")
	v.WithContext("pattern", "fallback-return")
	v.WithContext("language", "go")
	return v
}

// createTSViolation creates a violation for TypeScript fallback
func (r *FallbackReturnRule) createTSViolation(ctx *core.FileContext, lineNum int, line string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, "Fallback return detected - silently degrades instead of failing explicitly")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Throw error instead of fallback. Principle: 'Fail explicitly, never degrade silently'")
	v.WithContext("pattern", "fallback-return")
	v.WithContext("language", "typescript")
	return v
}

// isErrNotNilCondition checks specifically for "err != nil" condition
func (r *FallbackReturnRule) isErrNotNilCondition(expr ast.Expr) bool {
	binExpr, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}

	// Check for err != nil
	if binExpr.Op.String() != "!=" {
		return false
	}

	xIdent, xOk := binExpr.X.(*ast.Ident)
	yIdent, yOk := binExpr.Y.(*ast.Ident)

	if xOk && xIdent.Name == "err" && yOk && yIdent.Name == "nil" {
		return true
	}

	return false
}

// detectErrorIgnoringAssignment detects pattern where error is caught but ignored with assignment
// Example violation: if err != nil { secretKeyBytes = []byte(h.secretKey) }
func (r *FallbackReturnRule) detectErrorIgnoringAssignment(ctx *core.FileContext, ifStmt *ast.IfStmt) []*core.Violation {
	var violations []*core.Violation

	// Skip if body is empty
	if len(ifStmt.Body.List) == 0 {
		return nil
	}

	// Check each statement in body
	for _, stmt := range ifStmt.Body.List {
		assignStmt, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}

		// Skip if this is err = ... (error reassignment)
		if r.isErrReassignment(assignStmt) {
			continue
		}

		// Check if RHS looks like a fallback value
		for _, rhs := range assignStmt.Rhs {
			if r.looksLikeFallbackAssignment(rhs, ctx) {
				pos := ctx.PositionFor(assignStmt)
				lineContent := ctx.GetLine(pos.Line)

				// Skip if there's a comment explaining legitimate reason
				if r.hasLegitimateComment(ctx.Lines, pos.Line-1) || r.hasLoggingStatement(ifStmt, ctx) {
					continue
				}

				v := r.CreateViolation(ctx.RelPath, pos.Line, "Error caught but ignored with fallback assignment - CLAUDE.md violation")
				v.WithCode(lineContent)
				v.WithSuggestion("Return the error instead of assigning fallback. Function should fail explicitly on error.")
				v.WithContext("pattern", "error-ignoring-assignment")
				violations = append(violations, v)
			}
		}
	}

	return violations
}

// isErrReassignment checks if assignment is to err variable
func (r *FallbackReturnRule) isErrReassignment(stmt *ast.AssignStmt) bool {
	for _, lhs := range stmt.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok {
			if ident.Name == "err" {
				return true
			}
		}
	}
	return false
}

// looksLikeFallbackAssignment checks if RHS is a fallback pattern
func (r *FallbackReturnRule) looksLikeFallbackAssignment(expr ast.Expr, ctx *core.FileContext) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		name := strings.ToLower(e.Name)
		// Variables with fallback-indicating names
		if strings.Contains(name, "test") || strings.Contains(name, "mock") ||
			strings.Contains(name, "fake") || strings.Contains(name, "fallback") {
			return true
		}

	case *ast.CallExpr:
		// Type conversions like []byte(h.secretKey) - converting original value
		if len(e.Args) > 0 {
			// Check if it's a type conversion (function is a type)
			if _, ok := e.Fun.(*ast.ArrayType); ok {
				return true // []byte(...) conversion as fallback
			}
			if ident, ok := e.Fun.(*ast.Ident); ok {
				// string(...), []byte(...), int(...) etc - type casts as fallbacks
				typeCasts := []string{"string", "int", "int32", "int64", "float32", "float64", "bool"}
				for _, cast := range typeCasts {
					if ident.Name == cast {
						return true
					}
				}
			}
		}

		// Function calls with fallback patterns
		if fun, ok := e.Fun.(*ast.Ident); ok {
			nameLower := strings.ToLower(fun.Name)
			if strings.HasPrefix(nameLower, "newmock") ||
				strings.HasPrefix(nameLower, "newtest") ||
				strings.HasPrefix(nameLower, "newfake") {
				return true
			}
		}

	case *ast.BasicLit:
		// Literal values like "", 0, nil as fallback
		return true

	case *ast.CompositeLit:
		// Empty struct/slice/map as fallback: Foo{}, []string{}, etc.
		return true
	}

	return false
}

// hasLegitimateComment checks if previous lines have comments explaining legitimate use
func (r *FallbackReturnRule) hasLegitimateComment(lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}

	// Check up to 3 lines before for comments
	for i := lineIdx; i >= 0 && i > lineIdx-3; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "//") {
			lineLower := strings.ToLower(line)
			// Legitimate patterns: optional, non-critical, best effort, graceful
			if strings.Contains(lineLower, "optional") ||
				strings.Contains(lineLower, "non-critical") ||
				strings.Contains(lineLower, "best effort") ||
				strings.Contains(lineLower, "graceful") ||
				strings.Contains(lineLower, "using 0") ||
				strings.Contains(lineLower, "using zero") ||
				strings.Contains(lineLower, "baseline") ||
				strings.Contains(lineLower, "explicit") ||
				strings.Contains(lineLower, "intentional") ||
				strings.Contains(lineLower, "acceptable") {
				return true
			}
		}
	}
	return false
}

// hasLoggingStatement checks if there's a logging statement in the if block before the assignment
func (r *FallbackReturnRule) hasLoggingStatement(ifStmt *ast.IfStmt, ctx *core.FileContext) bool {
	for _, stmt := range ifStmt.Body.List {
		// Check for logging calls like logger.Warn, log.Printf, s.logger.Error, etc.
		if exprStmt, ok := stmt.(*ast.ExprStmt); ok {
			if call, ok := exprStmt.X.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					methodName := strings.ToLower(sel.Sel.Name)
					// Common logging methods
					if methodName == "warn" || methodName == "error" || methodName == "info" ||
						methodName == "debug" || methodName == "printf" || methodName == "println" ||
						methodName == "warnstructured" || methodName == "errorstructured" ||
						methodName == "infostructured" {
						return true
					}
				}
			}
		}
	}
	return false
}
