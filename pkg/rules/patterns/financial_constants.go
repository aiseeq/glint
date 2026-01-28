package patterns

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
	skipPatterns := []string{
		"config/",
		"/config/",
		"_config.go",
		"config.go",
		"constants/",
		"/constants/",
		"_constants.go",
		"constants.go",
		"_test.go", // Skip test files - they may have test constants
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

	var violations []*core.Violation

	// Track current function name for context
	var currentFuncName string

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name != nil {
				currentFuncName = strings.ToLower(node.Name.Name)
			}
			return true

		case *ast.CallExpr:
			if v := r.checkDecimalCall(ctx, node, currentFuncName); v != nil {
				violations = append(violations, v)
			}
		}
		return true
	})

	return violations
}

// isFinancialContext checks if function name suggests financial context
func (r *FinancialConstantsRule) isFinancialContext(funcName string) bool {
	financialKeywords := []string{
		"fee", "commission", "rate", "price", "cost",
		"charge", "premium", "margin", "spread",
		"withdrawal", "deposit", "transfer",
	}

	for _, keyword := range financialKeywords {
		if strings.Contains(funcName, keyword) {
			return true
		}
	}
	return false
}

// checkDecimalCall checks decimal.NewFromInt/NewFromFloat calls for hardcoded financial values
func (r *FinancialConstantsRule) checkDecimalCall(ctx *core.FileContext, call *ast.CallExpr, funcName string) *core.Violation {
	// Check if it's a decimal.NewFromInt or decimal.NewFromFloat call
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "decimal" {
		return nil
	}

	// Check for NewFromInt, NewFromFloat, NewFromInt32, NewFromInt64
	methodName := sel.Sel.Name
	if !strings.HasPrefix(methodName, "NewFrom") {
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

	if lit.Kind != token.INT && lit.Kind != token.FLOAT {
		return nil
	}

	// Parse numeric value
	var value float64
	if lit.Kind == token.INT {
		v, err := strconv.ParseInt(lit.Value, 0, 64)
		if err != nil {
			return nil
		}
		value = float64(v)
	} else {
		v, err := strconv.ParseFloat(lit.Value, 64)
		if err != nil {
			return nil
		}
		value = v
	}

	// Skip only 0 - often used for initialization
	// Note: 1 is NOT skipped in financial context as it could be a $1 fee
	if value == 0 {
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
		v.WithSuggestion("Define this value in config (e.g., config/limits.yaml) and access via UnifiedConfig")
		return v
	}

	// Not in obvious financial context, apply stricter check
	// Only flag if value looks like money (2-999 range, typical for fees)
	if value >= 2 && value <= 999 {
		pos := ctx.PositionFor(call)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Hardcoded financial constant detected - move to config")
		v.WithCode(lit.Value)
		v.WithSuggestion("Define this value in config (e.g., config/limits.yaml) and access via UnifiedConfig")
		return v
	}

	return nil
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
