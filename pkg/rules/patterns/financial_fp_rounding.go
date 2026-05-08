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
	// JS/TS: Math.floor|ceil|trunc(<expr> * 100) / 100 — without epsilon.
	jsFloorBy100 *regexp.Regexp
	// JS/TS: Math.floor|ceil|trunc(<expr> * <pct>) / 100 — pct is var/literal
	jsFloorByPct *regexp.Regexp
	// Go: math.Floor(... * 100) / 100 on float (we avoid this in finance entirely).
	goFloorBy100 *regexp.Regexp
	// Money-context check on the multiplied expression.
	moneyContext *regexp.Regexp
	// Epsilon already present? Then the line is safe.
	hasEpsilon *regexp.Regexp
}

func NewFinancialFPRoundingRule() *FinancialFPRoundingRule {
	return &FinancialFPRoundingRule{
		BaseRule: rules.NewBaseRule(
			"financial-fp-rounding",
			"patterns",
			"Detects unsafe Math.floor/ceil/trunc(money * 100)/100 — IEEE-754 shimmer silently drops cents (e.g. 5055.19 → 5055.18)",
			core.SeverityHigh,
		),
		jsFloorBy100: regexp.MustCompile(`Math\.(?:floor|ceil|trunc)\s*\(\s*([^)]*?)\s*\*\s*100\s*\)\s*/\s*100`),
		jsFloorByPct: regexp.MustCompile(`Math\.(?:floor|ceil|trunc)\s*\(\s*([^)]*?)\s*\*\s*([A-Za-z_$][\w$]*|\d+)\s*\)\s*/\s*100`),
		goFloorBy100: regexp.MustCompile(`math\.(?:Floor|Ceil|Trunc)\s*\(\s*([^)]*?)\s*\*\s*100\s*\)\s*/\s*100`),
		moneyContext: regexp.MustCompile(`(?i)(amount|balance|price|fee|cost|total|maxReceive|maxWithdraw|sum|usd|usdc|usdt|payout|payment|deposit|withdraw|profit|principal)`),
		hasEpsilon:   regexp.MustCompile(`(?:\+\s*1e-?\d+|\+\s*0\.0{4,}\d+|EPSILON)`),
	}
}

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
		if r.hasEpsilon.MatchString(line) {
			continue
		}

		if isTSJS {
			if m := r.jsFloorBy100.FindStringSubmatch(line); m != nil {
				if r.moneyContext.MatchString(m[1]) {
					violations = append(violations, r.violation(ctx, i+1, line,
						"Math.floor(money * 100)/100 — IEEE-754 shimmer drops cents; use Math.round(v*100)/100 or v.toFixed(2)"))
					continue
				}
			}
			if m := r.jsFloorByPct.FindStringSubmatch(line); m != nil {
				// Skip the *100 case (already handled above).
				if m[2] == "100" {
					continue
				}
				if r.moneyContext.MatchString(m[1]) {
					violations = append(violations, r.violation(ctx, i+1, line,
						"Math.floor(money * pct)/100 — FP shimmer can drop a cent; add epsilon or use toFixed"))
				}
			}
		}

		if isGo {
			if m := r.goFloorBy100.FindStringSubmatch(line); m != nil {
				if r.moneyContext.MatchString(m[1]) {
					violations = append(violations, r.violation(ctx, i+1, line,
						"math.Floor on float money — use decimal.Decimal arithmetic"))
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
