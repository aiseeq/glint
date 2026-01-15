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
// Catches: return testProvider, return mockService, return defaultValue on errors
type FallbackReturnRule struct {
	*rules.BaseRule
	fallbackPatterns []*regexp.Regexp
	goContextPatterns  []*regexp.Regexp
	tsContextPatterns  []*regexp.Regexp
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

		// Return *Provider fallback after error
		regexp.MustCompile(`return\s+\w*(?:Provider|Service|Client|Handler|Manager)\s*$`),

		// Explicit fallback naming
		regexp.MustCompile(`(?i)return\s+\w*fallback\w*`),

		// Return default* variable
		regexp.MustCompile(`return\s+default[A-Z]\w+`),

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
		regexp.MustCompile(`//.*(?i)(?:error|fail|unavailable|fallback|default)`),

		// Fallback comment
		regexp.MustCompile(`//.*(?i)(?:use|return|fall\s*back|degrad)`),
	}
}

// initTSContextPatterns detects error/failure context for TypeScript
func (r *FallbackReturnRule) initTSContextPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// Error check context - TS style
		regexp.MustCompile(`if\s*\(\s*!\w+`),          // if (!svc)
		regexp.MustCompile(`if\s*\(\s*\w+\s*===?\s*null`), // if (x === null)
		regexp.MustCompile(`if\s*\(\s*\w+\s*===?\s*undefined`), // if (x === undefined)
		regexp.MustCompile(`if\s*\(\s*err`),           // if (err...)

		// Error in comment
		regexp.MustCompile(`//.*(?i)(?:error|fail|unavailable|fallback|default)`),

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
					if !r.isGoException(ctx.RelPath, line, lineNum, ctx.Lines) {
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

		// Check body for fallback returns
		for _, stmt := range ifStmt.Body.List {
			retStmt, ok := stmt.(*ast.ReturnStmt)
			if !ok {
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

		return true
	})

	return violations
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

		// Check for fallback naming patterns
		fallbackPrefixes := []string{"test", "mock", "fake", "stub", "dummy", "fallback", "default"}
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
func (r *FallbackReturnRule) isGoException(path, line string, lineNum int, lines []string) bool {
	lineLower := strings.ToLower(line)

	// Factory functions that create test implementations (test file creators, not fallbacks)
	if strings.Contains(path, "factory") || strings.Contains(path, "builder") {
		return true
	}

	// Explicit "for testing" comment
	if strings.Contains(lineLower, "// for test") || strings.Contains(lineLower, "//for test") {
		return true
	}

	// Check if function is explicitly a test factory
	for i := lineNum; i >= 0 && i > lineNum-10; i-- {
		if strings.Contains(lines[i], "func New") && strings.Contains(lines[i], "ForTest") {
			return true
		}
		if strings.Contains(lines[i], "func Create") && strings.Contains(lines[i], "Test") {
			return true
		}
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

		// Return default fallback
		regexp.MustCompile(`(?i)return\s+default\w+`),

		// Fallback in variable assignment
		regexp.MustCompile(`(?i)=\s+(?:mock|test|fake|fallback)\w+`),

		// || fallback pattern
		regexp.MustCompile(`(?i)\|\|\s*(?:mock|test|fake|default)\w+`),

		// ?? fallback pattern (nullish coalescing)
		regexp.MustCompile(`(?i)\?\?\s*(?:mock|test|fake|default)\w+`),
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
