package patterns

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewFinancialConstantsRule())
}

// FinancialConstantsRule detects hardcoded financial constants that should be in config
// Examples: fees, commissions, rates, percentages in financial context
type FinancialConstantsRule struct {
	*rules.BaseRule
}

// NewFinancialConstantsRule creates the rule
func NewFinancialConstantsRule() *FinancialConstantsRule {
	return &FinancialConstantsRule{
		BaseRule: rules.NewBaseRule(
			"financial-constants",
			"patterns",
			"Detects hardcoded financial constants (fees, rates, commissions) that should be in config",
			core.SeverityMedium,
		),
	}
}

// shouldSkipFile checks if file should be skipped
func (r *FinancialConstantsRule) shouldSkipFile(path string) bool {
	pathLower := strings.ToLower(path)
	if isConfigOrConstantsPath(pathLower) {
		return true
	}
	skipPatterns := []string{
		"_test.go",    // Skip test files - they may have test constants
		"/math.go",    // Skip math utility files (percentage, days calculations)
		"math/",       // Skip math directories
		"monitoring/", // Skip monitoring files/directories (thresholds are not financial)
	}
	for _, pattern := range skipPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

// AnalyzeFile checks for hardcoded financial constants
func (r *FinancialConstantsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}

	if r.shouldSkipFile(ctx.RelPath) {
		return nil
	}

	aliases := decimalPackageAliases(ctx.GoAST)
	if len(aliases) == 0 {
		return nil
	}

	var violations []*core.Violation

	// Function context is scoped to the declaration: calls in package-level var
	// initializers must not inherit the name of a previously visited function.
	for _, decl := range ctx.GoAST.Decls {
		funcName := ""
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil {
			funcName = fn.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if v := r.checkDecimalCall(ctx, call, funcName, aliases); v != nil {
					violations = append(violations, v)
				}
			}
			return true
		})
	}

	return violations
}

// nonFinancialFunctionWords are function-name words that mark code whose
// numbers are not fees: tests, analytics, validation limits, builders.
var nonFinancialFunctionWords = wordSet(
	"test", "analytics", "dashboard", "metrics", "exchange", "balance",
	"limits", "validate", "build", "create", "result",
)

// feeContextFunctionWords are function-name words that put every number in
// the function under suspicion of being a fee, rate or charge. They name what
// a fee applies to rather than an amount, so the set is its own and not the
// money-value vocabulary: a "balance" function is explicitly not a fee context.
var feeContextFunctionWords = wordSet(
	"fee", "commission", "price", "cost", "charge", "premium", "margin", "spread",
	"withdrawal", "transfer",
)

// isExplicitlyNonFinancial checks if the function name clearly indicates a
// non-financial context. Names are read word by word: "latest" is not a test.
func (r *FinancialConstantsRule) isExplicitlyNonFinancial(funcName string) bool {
	return hasTokenIn(funcName, nonFinancialFunctionWords)
}

// isFinancialContext checks if the function name suggests a financial context.
// Names are read word by word: "feedback" is not a fee.
func (r *FinancialConstantsRule) isFinancialContext(funcName string) bool {
	if r.isExplicitlyNonFinancial(funcName) {
		return false
	}
	return hasTokenIn(funcName, feeContextFunctionWords)
}

// decimalPackageAliases returns the identifiers the file uses for an imported
// decimal package: github.com/shopspring/decimal or a project package with the
// same last path element (a wrapper keeping its constructor API).
func decimalPackageAliases(file *ast.File) map[string]bool {
	aliases := make(map[string]bool)
	for _, spec := range file.Imports {
		if spec.Path == nil {
			continue
		}
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || (path != "decimal" && !strings.HasSuffix(path, "/decimal")) {
			continue
		}
		for alias := range helpers.PackageAliases(file, spec.Path.Value, "decimal") {
			aliases[alias] = true
		}
	}
	return aliases
}

// decimalStringConstructors take the value as a decimal string literal.
var decimalStringConstructors = map[string]bool{
	"NewFromString":     true,
	"RequireFromString": true,
}

// checkDecimalCall checks decimal constructor calls (NewFromInt, NewFromFloat,
// NewFromString, RequireFromString, ...) for hardcoded financial values.
// aliases are the names the file imports the decimal package under.
func (r *FinancialConstantsRule) checkDecimalCall(ctx *core.FileContext, call *ast.CallExpr, funcName string, aliases map[string]bool) *core.Violation {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok || !aliases[ident.Name] {
		return nil
	}

	methodName := sel.Sel.Name
	if !strings.HasPrefix(methodName, "NewFrom") && !decimalStringConstructors[methodName] {
		return nil
	}

	// Must have at least one argument
	if len(call.Args) == 0 {
		return nil
	}

	// Check first argument for numeric literal
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return nil
	}

	var value float64
	switch {
	case lit.Kind == token.INT:
		v, err := strconv.ParseInt(lit.Value, 0, 64)
		if err != nil {
			return r.invalidNumericLiteral(ctx, lit, err)
		}
		value = float64(v)
	case lit.Kind == token.FLOAT:
		v, err := strconv.ParseFloat(lit.Value, 64)
		if err != nil {
			return r.invalidNumericLiteral(ctx, lit, err)
		}
		value = v
	case lit.Kind == token.STRING && decimalStringConstructors[methodName]:
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			return r.invalidNumericLiteral(ctx, lit, err)
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err != nil {
			return r.invalidNumericLiteral(ctx, lit, err)
		}
		value = v
	default:
		return nil
	}

	// Skip only 0 - often used for initialization
	// Note: 1 is NOT skipped in financial context as it could be a $1 fee
	if value == 0 {
		return nil
	}

	// Skip explicitly non-financial contexts entirely
	if r.isExplicitlyNonFinancial(funcName) {
		return nil
	}

	// Check if we're in a financial context (function name suggests fees/rates/etc)
	inFinancialContext := r.isFinancialContext(funcName)

	// Skip 1 only if NOT in financial context (1 could be a $1 fee)
	if value == 1 && !inFinancialContext {
		return nil
	}

	// Skip scaling factors ONLY if NOT in financial context
	// In financial context, even 10 or 100 could be a fee
	if !inFinancialContext && r.isLikelyScalingFactor(value) {
		return nil
	}

	if inFinancialContext {
		// In financial context - flag any numeric constant
		pos := ctx.PositionFor(call)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Hardcoded financial constant detected - move to config")
		v.WithCode(lit.Value)
		v.WithSuggestion("Define this value in the configuration and read it from there")
		return v
	}

	// Not in obvious financial context, apply stricter check
	// Only flag if value looks like money (2-999 range, typical for fees)
	if value >= 2 && value <= 999 {
		pos := ctx.PositionFor(call)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Hardcoded financial constant detected - move to config")
		v.WithCode(lit.Value)
		v.WithSuggestion("Define this value in the configuration and read it from there")
		return v
	}

	return nil
}

func (r *FinancialConstantsRule) invalidNumericLiteral(ctx *core.FileContext, lit *ast.BasicLit, err error) *core.Violation {
	line := ctx.PositionFor(lit).Line
	v := r.CreateViolation(ctx.RelPath, line, "Invalid financial numeric literal: "+err.Error())
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Fix the numeric literal before financial constant analysis")
	return v
}

// isLikelyScalingFactor checks if value is likely used for scaling/conversion, not as a fee
func (r *FinancialConstantsRule) isLikelyScalingFactor(value float64) bool {
	// Powers of 10 are often used for decimal scaling
	scalingFactors := map[float64]bool{
		10:         true,
		100:        true,
		1000:       true,
		10000:      true,
		100000:     true,
		1000000:    true,
		10000000:   true,
		100000000:  true,
		1000000000: true,
	}

	// Also skip common percentage bases
	scalingFactors[365] = true // Days in year
	scalingFactors[366] = true // Leap year
	scalingFactors[12] = true  // Months
	scalingFactors[24] = true  // Hours
	scalingFactors[60] = true  // Minutes/seconds

	return scalingFactors[value]
}
