package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFinancialFPRoundingRule())
}

// FinancialFPRoundingRule detects unsafe floor/ceil/trunc rounding of money
// values multiplied by 100 (or by an explicit percentage). Pattern
// `Math.floor(value * 100) / 100` looks like "round down to cent" but
// JavaScript IEEE-754 makes `5055.19 * 100 = 505518.99999999994`, which
// floors to `505518` and yields `5055.18` — silently losing one cent.
//
// The same shimmer hits `Math.floor(money * pct) / 100` for percentage
// buttons (e.g. 100% of max → 5055.18 instead of 5055.19).
//
// Safe alternatives:
//   - `Math.round(value * 100) / 100` — half-even, no shimmer for cent grid
//   - `Math.floor(value * 100 + 1e-9) / 100` — explicit epsilon
//   - `value.toFixed(2)` when half-up rounding is acceptable
//   - In Go: use `decimal.Decimal` arithmetic, never float64
type FinancialFPRoundingRule struct {
	*rules.BaseRule
	// JS/TS: the opening of Math.floor|ceil|trunc( — the argument is taken up
	// to its matching parenthesis, so nested calls stay inside it.
	jsRoundCall *regexp.Regexp
	// Go: the opening of math.Floor|Ceil|Trunc( (we avoid float money entirely).
	goRoundCall *regexp.Regexp
	// The rounded argument: <money> * <factor>, factor an identifier or a number.
	scaledArgument *regexp.Regexp
	// What follows the rounding call: / 100.
	divideBy100 *regexp.Regexp
	// Epsilon already present? Then the line is safe.
	hasEpsilon *regexp.Regexp
}

// NewFinancialFPRoundingRule creates the rule
func NewFinancialFPRoundingRule() *FinancialFPRoundingRule {
	return &FinancialFPRoundingRule{
		BaseRule: rules.NewBaseRule(
			"financial-fp-rounding",
			"patterns",
			"Detects unsafe Math.floor/ceil/trunc(money * 100)/100 — IEEE-754 shimmer silently drops cents (e.g. 5055.19 → 5055.18)",
			core.SeverityHigh,
		),
		jsRoundCall:    regexp.MustCompile(`Math\.(?:floor|ceil|trunc)\s*\(`),
		goRoundCall:    regexp.MustCompile(`math\.(?:Floor|Ceil|Trunc)\s*\(`),
		scaledArgument: regexp.MustCompile(`^\s*(.*\S)\s*\*\s*([A-Za-z_$][\w$]*|\d+)\s*$`),
		divideBy100:    regexp.MustCompile(`^\s*/\s*100\b`),
		hasEpsilon:     regexp.MustCompile(`(?:\+\s*1e-?\d+|\+\s*0\.0{4,}\d+|EPSILON)`),
	}
}

// roundedMoney is one floor/ceil/trunc(<money> * <factor>) / 100 on a line.
type roundedMoney struct {
	factor string
}

// roundedMoneyCalls finds the rounding calls of the line whose argument scales
// a money operand and whose result is divided by 100. The argument is cut at
// its matching parenthesis, so Math.floor(Number(amount) * 100) / 100 is seen
// whole.
func (r *FinancialFPRoundingRule) roundedMoneyCalls(line string, call *regexp.Regexp) []roundedMoney {
	var found []roundedMoney
	for _, loc := range call.FindAllStringIndex(line, -1) {
		end := matchingParenEnd(line, loc[1])
		if end < 0 || !r.divideBy100.MatchString(line[end+1:]) {
			continue
		}
		scaled := r.scaledArgument.FindStringSubmatch(line[loc[1]:end])
		if scaled == nil || !looksLikeMoney(scaled[1]) {
			continue
		}
		found = append(found, roundedMoney{factor: scaled[2]})
	}
	return found
}

// AnalyzeFile checks for floating-point rounding of money
func (r *FinancialFPRoundingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.shouldSkip(ctx) {
		return nil
	}

	isTSJS := ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile()
	isGo := strings.HasSuffix(ctx.RelPath, ".go")
	if !isTSJS && !isGo {
		return nil
	}

	var violations []*core.Violation
	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		// Every rounding call names the math package: the needle comes before
		// the regexps.
		roundsJS := isTSJS && strings.Contains(line, "Math.")
		roundsGo := isGo && strings.Contains(line, "math.")
		if !roundsJS && !roundsGo {
			continue
		}
		if r.hasEpsilon.MatchString(line) {
			continue
		}

		if isTSJS {
			if calls := r.roundedMoneyCalls(line, r.jsRoundCall); len(calls) > 0 {
				message := "Math.floor(money * pct)/100 — FP shimmer can drop a cent; add epsilon or use toFixed"
				for _, call := range calls {
					if call.factor == "100" {
						message = "Math.floor(money * 100)/100 — IEEE-754 shimmer drops cents; use Math.round(v*100)/100 or v.toFixed(2)"
						break
					}
				}
				violations = append(violations, r.violation(ctx, i+1, line, message))
				continue
			}
		}

		if isGo {
			for _, call := range r.roundedMoneyCalls(line, r.goRoundCall) {
				if call.factor == "100" {
					violations = append(violations, r.violation(ctx, i+1, line,
						"math.Floor on float money — use decimal.Decimal arithmetic"))
					break
				}
			}
		}
	}
	return violations
}

func (r *FinancialFPRoundingRule) shouldSkip(ctx *core.FileContext) bool {
	if ctx.IsTestFile() {
		return true
	}
	path := ctx.RelPath
	return strings.Contains(path, "/node_modules/") ||
		strings.Contains(path, "/.next/") ||
		strings.Contains(path, "/out/") ||
		strings.Contains(path, "/dist/") ||
		strings.Contains(path, "/generated/") ||
		strings.Contains(path, "generated-") ||
		strings.Contains(path, ".generated") ||
		strings.Contains(path, "/testdata/")
}

func (r *FinancialFPRoundingRule) violation(ctx *core.FileContext, lineNum int, line, message string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, message)
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Replace floor/ceil(money*100)/100 with Math.round(v*100)/100, value.toFixed(2), or add explicit epsilon (+ 1e-9).")
	v.WithContext("pattern", "financial-fp-rounding")
	return v
}
