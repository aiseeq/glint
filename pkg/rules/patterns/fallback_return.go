package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
	return r
}

// tsContextPatterns detect an error/failure context for TypeScript.
var tsContextPatterns = []*regexp.Regexp{
	// Error check context - TS style
	regexp.MustCompile(`if\s*\(\s*!\w+`),                   // if (!svc)
	regexp.MustCompile(`if\s*\(\s*\w+\s*===?\s*null`),      // if (x === null)
	regexp.MustCompile(`if\s*\(\s*\w+\s*===?\s*undefined`), // if (x === undefined)
	regexp.MustCompile(`if\s*\(\s*err`),                    // if (err...)

	// Error in comment
	regexp.MustCompile(`//.*(?i)(?:error|fail|unavailable|fallback)`),

	// Fallback comment
	regexp.MustCompile(`//.*(?i)(?:use|return|fall\s*back|degrad)`),
}

// tsFallbackPatterns detect fallback values in TypeScript. Fallback values are
// lowerCamel (testProvider) or UPPER_SNAKE (TEST_DEFAULT); PascalCase
// (TestEnvironmentSchemas) is a class/namespace of test infrastructure, not a
// fallback value.
var tsFallbackPatterns = []*regexp.Regexp{
	// Return mock/test/fake value
	regexp.MustCompile(`return\s+(?:mock|test|fake|stub|dummy|MOCK_|TEST_|FAKE_|STUB_|DUMMY_)\w+`),

	// Fallback in variable assignment
	regexp.MustCompile(`=\s+(?:mock|test|fake|fallback|MOCK_|TEST_|FAKE_|FALLBACK_)\w+`),

	// || fallback pattern (but not for common defaults)
	regexp.MustCompile(`\|\|\s*(?:mock|test|fake|MOCK_|TEST_|FAKE_)\w+`),

	// ?? fallback pattern
	regexp.MustCompile(`\?\?\s*(?:mock|test|fake|fallback|MOCK_|TEST_|FAKE_|FALLBACK_)\w+`),

	// Method/function calls named *Fallback*(...) invoked inside an
	// error-handling branch: the "primary check failed → call fallback
	// detector" pattern.
	regexp.MustCompile(`\.[A-Za-z_]\w*[Ff]allback\w*\s*\(`),
}

// tsSingletonReturn matches `return X.instance` — классический синглтон-геттер,
// не fallback.
var tsSingletonReturn = regexp.MustCompile(`return\s+\w+\.instance\b`)

// AnalyzeFile checks for fallback return patterns
func (r *FallbackReturnRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.shouldSkipFile(ctx) {
		return nil
	}

	return helpers.AnalyzeGoAndFrontend(ctx, r.analyzeGoFile, r.analyzeTSFile)
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

// analyzeGoFile analyzes Go file for fallback patterns. Only the syntax tree
// tells an error branch apart from a lazy initializer or a comment that
// happens to say "use"; line patterns cannot.
func (r *FallbackReturnRule) analyzeGoFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() {
		return nil
	}
	return r.analyzeGoAST(ctx)
}

// analyzeGoAST walks every function once, with the name that decides its
// exceptions.
func (r *FallbackReturnRule) analyzeGoAST(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	// First pass: detect implicit else fallback patterns at function level
	violations = append(violations, r.detectImplicitElseFallback(ctx)...)

	forEachFunction(ctx.GoAST, func(name string, _ *ast.FuncType, body *ast.BlockStmt) {
		if r.isFunctionException(name) {
			return
		}
		forEachOwnStatement(body, func(stmt ast.Stmt) {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok || !r.isErrorCondition(ifStmt.Cond) {
				return
			}
			violations = append(violations, r.checkErrorBranch(ctx, ifStmt)...)
		})
		// After the branch checks: where both see an assignment, their
		// finding stays.
		forEachOwnStatementList(body, func(list []ast.Stmt) {
			for i := 0; i+1 < len(list); i++ {
				results, errName := failedCallResults(list[i])
				ifStmt, ok := list[i+1].(*ast.IfStmt)
				if errName == "" || !ok || ifStmt.Init != nil || errNilCheckName(ifStmt.Cond) != errName {
					continue
				}
				violations = append(violations, r.detectReplacedResult(ctx, ifStmt, results, errName)...)
			}
		})
	})

	return uniqueViolationLines(violations)
}

// uniqueViolationLines keeps the first finding of every line: an assignment
// both detectors see is reported once.
func uniqueViolationLines(violations []*core.Violation) []*core.Violation {
	seen := make(map[int]bool, len(violations))
	unique := violations[:0]
	for _, v := range violations {
		if !seen[v.Line] {
			seen[v.Line] = true
			unique = append(unique, v)
		}
	}
	return unique
}

// failedCallResults returns the result variables and the error variable of
// `v1, v2, err := call()` (or =).
func failedCallResults(stmt ast.Stmt) (map[string]bool, string) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) < 2 {
		return nil, ""
	}
	if _, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); !ok {
		return nil, ""
	}
	errIdent, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	if !ok || !isErrorVarName(errIdent.Name) {
		return nil, ""
	}
	results := make(map[string]bool)
	for _, lhs := range assign.Lhs[:len(assign.Lhs)-1] {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
			results[ident.Name] = true
		}
	}
	if len(results) == 0 {
		return nil, ""
	}
	return results, errIdent.Name
}

// detectReplacedResult reports, in the `if err != nil` that follows a call,
// an assignment that gives the call's result a value no call produced: a
// zero, a literal, a field of another value, a zero or no-op constructor. The
// branch goes on, and so does the caller, with a plausible value. A log line
// in the branch does not change that; the result of another call (failover),
// an error recorded outside a log, or a retry does.
func (r *FallbackReturnRule) detectReplacedResult(ctx *core.FileContext, ifStmt *ast.IfStmt, results map[string]bool, errName string) []*core.Violation {
	body := ifStmt.Body
	for _, stmt := range body.List {
		if _, ok := stmt.(*ast.ReturnStmt); ok {
			return nil
		}
	}
	if readsIdentOutsideLoggers(body, errName) || r.bodyReassignsErrFromCall(body, errName) {
		return nil
	}
	produced := namesAssignedFromCalls(body)
	var violations []*core.Violation
	forEachOwnStatement(body, func(stmt ast.Stmt) {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			return
		}
		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || !results[ident.Name] || len(assign.Rhs) != len(assign.Lhs) {
				continue
			}
			if !isReplacementValue(assign.Rhs[i], produced) {
				continue
			}
			pos := ctx.PositionFor(assign)
			if r.branchExplainsFallback(ctx, ifStmt, assign) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, pos.Line, "The call failed and "+ident.Name+" gets a fallback value instead - callers go on as if it had succeeded")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Return the error. A deliberate failover takes the result of another call; a deliberate fallback is suppressed with the reason.")
			v.WithContext("pattern", "replaced-failed-result")
			violations = append(violations, v)
		}
	})
	return violations
}

// branchExplainsFallback reports a comment with a legitimate reason where
// hasLegitimateComment looks, or in the innermost block around the
// assignment, from its brace down to the assignment: the reason is usually written at the top of the branch, above a
// log call of several lines. An enclosing block explains its own step of a
// fallback chain, not this one.
func (r *FallbackReturnRule) branchExplainsFallback(ctx *core.FileContext, ifStmt *ast.IfStmt, assign ast.Node) bool {
	block := ifStmt.Body
	ast.Inspect(ifStmt.Body, func(n ast.Node) bool {
		if n == nil || n.Pos() > assign.Pos() || n.End() < assign.End() {
			return false
		}
		if inner, ok := n.(*ast.BlockStmt); ok {
			block = inner
		}
		return true
	})
	line := ctx.PositionFor(assign).Line
	if r.hasLegitimateComment(ctx.Lines, line-1) {
		return true
	}
	for l := ctx.PositionFor(block).Line; l <= line && l <= len(ctx.Lines); l++ {
		// One line at a time: the lines above the block explain another step.
		if r.hasLegitimateComment(ctx.Lines[l-1:l], 0) {
			return true
		}
	}
	return false
}

// readsIdentOutsideLoggers is nodeReadsIdent that does not look into logging
// calls: a log line reports the error to an operator, not to the caller.
func readsIdentOutsideLoggers(node ast.Node, name string) bool {
	targets := make(map[*ast.Ident]bool)
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		switch current := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if isLoggerCall(current) {
				return false
			}
		case *ast.AssignStmt:
			for _, lhs := range current.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					targets[ident] = true
				}
			}
		case *ast.Ident:
			found = current.Name == name && !targets[current]
		}
		return !found
	})
	return found
}

// namesAssignedFromCalls returns the variables the block assigns from a call:
// the results of another attempt.
func namesAssignedFromCalls(body *ast.BlockStmt) map[string]bool {
	names := make(map[string]bool)
	forEachOwnStatement(body, func(stmt ast.Stmt) {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || isFallbackConstructor(call) {
			return
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok {
				names[ident.Name] = true
			}
		}
	})
	return names
}

// isReplacementValue reports a value no new call produced: a literal, a
// composite, a constant or another variable, a field, a zero or no-op
// constructor, a conversion of one of those.
func isReplacementValue(expr ast.Expr, produced map[string]bool) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit, *ast.CompositeLit:
		return true
	case *ast.Ident:
		return !produced[e.Name]
	case *ast.SelectorExpr:
		if root, ok := e.X.(*ast.Ident); ok && produced[root.Name] {
			return false
		}
		return true
	case *ast.UnaryExpr:
		return isReplacementValue(e.X, produced)
	case *ast.CallExpr:
		if isFallbackConstructor(e) {
			return true
		}
		// A conversion of a replacement: int64(0), Amount("0").
		return len(e.Args) == 1 && isConversionCallee(e.Fun) && isReplacementValue(e.Args[0], produced)
	}
	return false
}

// fallbackConstructorWords name constructors of stand-in values.
var fallbackConstructorWords = []string{"nop", "noop", "zero", "empty", "default", "fallback", "mock", "fake", "stub", "dummy", "placeholder"}

// isFallbackConstructor reports a call whose callee names a stand-in value:
// zap.NewNop(), decimal.Zero(), NewEmptyCache().
func isFallbackConstructor(call *ast.CallExpr) bool {
	var name string
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	default:
		return false
	}
	lower := strings.ToLower(name)
	for _, word := range fallbackConstructorWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// isConversionCallee reports a callee that looks like a type: a basic type
// name, an exported type name, a slice or map type.
func isConversionCallee(fun ast.Expr) bool {
	switch f := fun.(type) {
	case *ast.ArrayType, *ast.MapType:
		return true
	case *ast.Ident:
		switch f.Name {
		case "string", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64",
			"float32", "float64", "bool", "byte", "rune":
			return true
		}
	}
	return false
}

// checkErrorBranch reports fallback values returned from an error branch and,
// for an `if err != nil` without a return, fallback values assigned instead.
func (r *FallbackReturnRule) checkErrorBranch(ctx *core.FileContext, ifStmt *ast.IfStmt) []*core.Violation {
	var violations []*core.Violation
	hasReturn := false
	for _, stmt := range ifStmt.Body.List {
		retStmt, ok := stmt.(*ast.ReturnStmt)
		if !ok {
			continue
		}
		hasReturn = true

		// Skip if error is returned explicitly
		if returnCarriesError(retStmt) {
			continue
		}

		for _, result := range retStmt.Results {
			if !r.isFallbackReturn(result) {
				continue
			}
			pos := ctx.PositionFor(retStmt)
			v := r.CreateViolation(ctx.RelPath, pos.Line, "Fallback return on error - silently degrades instead of failing explicitly")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Return the error instead of fallback value. Caller should decide recovery strategy.")
			violations = append(violations, v)
			break // one finding per return
		}
	}

	// Pattern: if err != nil { variable = fallbackValue } without return
	if errName := errNilCheckName(ifStmt.Cond); !hasReturn && errName != "" {
		violations = append(violations, r.detectErrorIgnoringAssignment(ctx, ifStmt, errName)...)
	}
	return violations
}

// isFunctionException checks whether the function's name declares fallbacks
// as its contract.
func (r *FallbackReturnRule) isFunctionException(funcName string) bool {
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

	if !hasLeadingWord(funcName, "Get") {
		return false
	}

	// Singleton getters (Get*Manager, Get*EventManager) - not fallbacks
	if strings.HasSuffix(funcLower, "manager") || strings.HasSuffix(funcLower, "instance") {
		return true
	}

	// GetRealIP, GetClientKey - defensive programming for middleware that
	// derives a request key. Whole words only: GetRecipient merely contains
	// the letters "ip", and GetClient builds a client, it derives no key.
	return hasCamelWord(funcName, "IP") || hasCamelWord(funcName, "Key")
}

// isErrorCondition checks if condition is error-related
func (r *FallbackReturnRule) isErrorCondition(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		// err != nil or err == nil
		if ident, ok := e.X.(*ast.Ident); ok && isErrorVarName(ident.Name) {
			return true
		}
		// something == nil / nil == something (nil check). Сравнение с любым
		// другим идентификатором (mode == modeFake) — выбор режима, не ошибка.
		if ident, ok := e.Y.(*ast.Ident); ok && ident.Name == "nil" {
			return true
		}
		if ident, ok := e.X.(*ast.Ident); ok && ident.Name == "nil" {
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

// analyzeTSFile analyzes TypeScript/JavaScript file for fallback patterns
func (r *FallbackReturnRule) analyzeTSFile(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if tsSingletonReturn.MatchString(line) {
			continue
		}

		for _, pattern := range tsFallbackPatterns {
			if pattern.MatchString(line) {
				if r.isInTSContext(ctx.Lines, lineNum) && !r.isTSException(ctx.RelPath) {
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
		for _, pattern := range tsContextPatterns {
			if pattern.MatchString(lines[i]) {
				return true
			}
		}
	}

	return false
}

// isTSException checks if this is a valid exception for TS
func (r *FallbackReturnRule) isTSException(path string) bool {
	// Test files and test infrastructure (Playwright e2e dir)
	if strings.Contains(path, ".test.") || strings.Contains(path, ".spec.") ||
		strings.Contains(path, "__tests__") || strings.Contains(path, "__mocks__") ||
		strings.Contains(path, "/e2e/") || strings.HasPrefix(path, "e2e/") {
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

// createTSViolation creates a violation for TypeScript fallback
func (r *FallbackReturnRule) createTSViolation(ctx *core.FileContext, lineNum int, line string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, "Fallback return detected - silently degrades instead of failing explicitly")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Throw error instead of fallback. Principle: 'Fail explicitly, never degrade silently'")
	v.WithContext("pattern", "fallback-return")
	v.WithContext("language", "typescript")
	return v
}

// detectErrorIgnoringAssignment detects pattern where error is caught but ignored with assignment
// Example violation: if err != nil { secretKeyBytes = []byte(h.secretKey) }
func (r *FallbackReturnRule) detectErrorIgnoringAssignment(ctx *core.FileContext, ifStmt *ast.IfStmt, errName string) []*core.Violation {
	var violations []*core.Violation

	// Skip if body is empty
	if len(ifStmt.Body.List) == 0 {
		return nil
	}

	// A branch that reads the error (res.Message = err.Error(), a log line,
	// a collector) records the failure; the values assigned beside it are
	// the report, not a replacement for it.
	if nodeReadsIdent(ifStmt.Body, errName) {
		return nil
	}

	// Переприсваивание err результатом нового вызова — retry: судьбу ошибки
	// решает следующая проверка err, а сопутствующие присваивания (настройка
	// повторной команды) не являются fallback-значениями
	if r.bodyReassignsErrFromCall(ifStmt.Body, errName) {
		return nil
	}

	// Check each statement in body
	for _, stmt := range ifStmt.Body.List {
		assignStmt, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}

		// Skip if this is err = ... (error reassignment)
		if assignsName(assignStmt, errName) {
			continue
		}

		// Check if RHS looks like a fallback value
		for _, rhs := range assignStmt.Rhs {
			if r.looksLikeFallbackAssignment(rhs) {
				pos := ctx.PositionFor(assignStmt)
				lineContent := ctx.GetLine(pos.Line)

				// Skip if there's a comment explaining legitimate reason
				if r.hasLegitimateComment(ctx.Lines, pos.Line-1) || r.hasLoggingStatement(ifStmt) {
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

// bodyReassignsErrFromCall reports whether the block reassigns err with the
// result of a new call (retry pattern). A literal like `err = nil` does not
// count — silencing an error is not a retry.
func (r *FallbackReturnRule) bodyReassignsErrFromCall(body *ast.BlockStmt, errName string) bool {
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || !assignsName(assign, errName) {
			continue
		}
		for _, rhs := range assign.Rhs {
			if _, ok := rhs.(*ast.CallExpr); ok {
				return true
			}
		}
	}
	return false
}

// looksLikeFallbackAssignment checks if RHS is a fallback pattern
func (r *FallbackReturnRule) looksLikeFallbackAssignment(expr ast.Expr) bool {
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

	case *ast.UnaryExpr:
		// Pointer to empty struct as fallback: &Foo{}, &Config{}
		if e.Op.String() == "&" {
			if _, ok := e.X.(*ast.CompositeLit); ok {
				return true
			}
		}
	}

	return false
}

// hasLegitimateComment checks if lines have comments explaining legitimate use
// Checks inline comments on current line and standalone comments on previous lines
func (r *FallbackReturnRule) hasLegitimateComment(lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}

	legitimatePatterns := []string{
		"optional", "non-critical", "best effort", "graceful",
		"using 0", "using zero", "baseline", "explicit",
		"intentional", "acceptable", "allow", "permit", "failover",
		"разрешаем", "устанавливаем", "базовые", "явный",
	}

	// Check current line for inline comment
	currentLine := lines[lineIdx]
	if commentIdx := strings.Index(currentLine, "//"); commentIdx >= 0 {
		commentLower := strings.ToLower(currentLine[commentIdx:])
		for _, pattern := range legitimatePatterns {
			if strings.Contains(commentLower, pattern) {
				return true
			}
		}
	}

	// Check up to 3 lines before for standalone comments
	for i := lineIdx - 1; i >= 0 && i > lineIdx-4; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "//") {
			lineLower := strings.ToLower(line)
			for _, pattern := range legitimatePatterns {
				if strings.Contains(lineLower, pattern) {
					return true
				}
			}
		}
	}
	return false
}

// hasLoggingStatement checks if the if block logs (see isLoggerCall).
func (r *FallbackReturnRule) hasLoggingStatement(ifStmt *ast.IfStmt) bool {
	for _, stmt := range ifStmt.Body.List {
		if exprStmt, ok := stmt.(*ast.ExprStmt); ok {
			if call, ok := exprStmt.X.(*ast.CallExpr); ok && isLoggerCall(call) {
				return true
			}
		}
	}
	return false
}

// detectImplicitElseFallback detects pattern: if good { return good } return fallback
// This catches CreateValidationService-like patterns where fallback is returned after positive check
func (r *FallbackReturnRule) detectImplicitElseFallback(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok || funcDecl.Body == nil {
			return true
		}

		// Skip exception functions
		if r.isFunctionNameException(funcDecl.Name.Name) {
			return true
		}

		// Check if function returns (T, error) pattern
		if !r.returnsValueAndError(funcDecl) {
			return true
		}

		// Look for pattern: if x != nil { return x, nil } return fallback, nil
		violations = append(violations, r.checkForImplicitFallback(ctx, funcDecl)...)

		return true
	})

	return violations
}

// isFunctionNameException checks if function name indicates its OK to have fallbacks
func (r *FallbackReturnRule) isFunctionNameException(name string) bool {
	nameLower := strings.ToLower(name)

	// OrX patterns are by design
	if strings.Contains(nameLower, "ordefault") || strings.Contains(nameLower, "orempty") ||
		strings.Contains(nameLower, "ornew") || strings.Contains(nameLower, "ornull") {
		return true
	}

	// Get*Manager, Get*Instance - singleton patterns
	if strings.HasPrefix(nameLower, "get") && (strings.HasSuffix(nameLower, "manager") ||
		strings.HasSuffix(nameLower, "instance") || strings.HasSuffix(nameLower, "singleton")) {
		return true
	}

	// Parse* functions often have legitimate fallbacks
	if strings.HasPrefix(nameLower, "parse") {
		return true
	}

	return false
}

// returnsValueAndError checks if function signature is (T, error)
func (r *FallbackReturnRule) returnsValueAndError(funcDecl *ast.FuncDecl) bool {
	if funcDecl.Type.Results == nil || len(funcDecl.Type.Results.List) < 2 {
		return false
	}

	// Check last return type is error
	lastResult := funcDecl.Type.Results.List[len(funcDecl.Type.Results.List)-1]
	if ident, ok := lastResult.Type.(*ast.Ident); ok {
		return ident.Name == "error"
	}
	return false
}

// checkForImplicitFallback looks for if-return-good then return-fallback patterns
func (r *FallbackReturnRule) checkForImplicitFallback(ctx *core.FileContext, funcDecl *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	stmts := funcDecl.Body.List

	for i := 0; i < len(stmts)-1; i++ {
		ifStmt, ok := stmts[i].(*ast.IfStmt)
		if !ok {
			continue
		}

		// Check if the if body returns (positive path)
		if !r.bodyReturnsWithoutError(ifStmt.Body) {
			continue
		}

		// Check next statement is a return (the fallback)
		nextReturn, ok := stmts[i+1].(*ast.ReturnStmt)
		if !ok {
			continue
		}

		// Skip if the return includes an error
		if returnCarriesError(nextReturn) {
			continue
		}

		// Check if theres a fallback comment nearby
		pos := ctx.PositionFor(nextReturn)
		if r.hasFallbackCommentNearby(ctx.Lines, pos.Line-1) {
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Implicit else fallback - returns non-error value when precondition fails")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Return an error instead of fallback. Caller should handle missing precondition.")
			v.WithContext("pattern", "implicit-else-fallback")
			violations = append(violations, v)
		}
	}

	return violations
}

// bodyReturnsWithoutError checks if block has a return without error
func (r *FallbackReturnRule) bodyReturnsWithoutError(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		if retStmt, ok := stmt.(*ast.ReturnStmt); ok {
			return !returnCarriesError(retStmt)
		}
	}
	return false
}

// hasFallbackCommentNearby checks if theres a comment with fallback nearby.
// Only the comment part of a line counts: code that names a fallbackX value is
// not a comment announcing a fallback.
func (r *FallbackReturnRule) hasFallbackCommentNearby(lines []string, lineIdx int) bool {
	// Check 3 lines before
	for i := lineIdx; i >= 0 && i > lineIdx-4; i-- {
		commentIdx := strings.Index(lines[i], "//")
		if commentIdx < 0 {
			continue
		}
		lineLower := strings.ToLower(lines[i][commentIdx:])
		if strings.Contains(lineLower, "fallback") || strings.Contains(lineLower, "fall back") ||
			strings.Contains(lineLower, "fall-back") {
			return true
		}
	}
	return false
}
