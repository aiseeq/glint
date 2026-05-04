package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFinancialRoundedDeltaRule())
}

// FinancialRoundedDeltaRule detects financial deltas derived by subtracting
// parsed cumulative money fields. Financial deltas should be calculated in the
// canonical backend/domain layer from full-precision decimals and exposed as a
// first-class field, not reconstructed from rounded API/display values.
type FinancialRoundedDeltaRule struct {
	*rules.BaseRule
	parseAssign       *regexp.Regexp
	directParsedDelta *regexp.Regexp
	financialField    *regexp.Regexp
	deltaContext      *regexp.Regexp
}

func NewFinancialRoundedDeltaRule() *FinancialRoundedDeltaRule {
	return &FinancialRoundedDeltaRule{
		BaseRule: rules.NewBaseRule(
			"financial-rounded-delta",
			"patterns",
			"Detects financial deltas calculated from parsed cumulative money fields",
			core.SeverityHigh,
		),
		parseAssign:       regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:Number|parseFloat)\s*\(([^)]*)\)`),
		directParsedDelta: regexp.MustCompile(`(?:Number|parseFloat)\s*\([^)]*(?:amount|balance|profit|yield|total|value)[^)]*\)\s*-\s*(?:Number|parseFloat)\s*\([^)]*(?:amount|balance|profit|yield|total|value)[^)]*\)`),
		financialField:    regexp.MustCompile(`(?i)(amount|balance|profit|yield|total|value)`),
		deltaContext:      regexp.MustCompile(`(?i)(delta|change|daily|difference|diff|yesterday|today|profit|yield)`),
	}
}

func (r *FinancialRoundedDeltaRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if r.shouldSkip(ctx) {
		return nil
	}

	parsedFinancialVars := map[string]bool{}
	var violations []*core.Violation

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if r.deltaContext.MatchString(line) && r.directParsedDelta.MatchString(line) {
			violations = append(violations, r.violation(ctx, i+1, line))
			continue
		}

		if matches := r.parseAssign.FindStringSubmatch(line); len(matches) == 3 {
			name := matches[1]
			expr := matches[2]
			if r.financialField.MatchString(name) || r.financialField.MatchString(expr) {
				parsedFinancialVars[name] = true
			}
		}

		if !strings.Contains(line, "-") {
			continue
		}
		if r.deltaContext.MatchString(line) && r.subtractsParsedFinancialVars(line, parsedFinancialVars) {
			violations = append(violations, r.violation(ctx, i+1, line))
		}
	}

	return violations
}

func (r *FinancialRoundedDeltaRule) subtractsParsedFinancialVars(line string, vars map[string]bool) bool {
	parts := strings.Split(line, "-")
	if len(parts) < 2 {
		return false
	}

	for i := 0; i < len(parts)-1; i++ {
		left := parts[i]
		right := parts[i+1]
		leftParsed := containsParsedFinancialVar(left, vars)
		rightParsed := containsParsedFinancialVar(right, vars)
		if leftParsed && rightParsed {
			return true
		}
		if leftParsed && r.financialField.MatchString(right) {
			return true
		}
		if rightParsed && r.financialField.MatchString(left) {
			return true
		}
	}
	return false
}

func containsParsedFinancialVar(text string, vars map[string]bool) bool {
	for name := range vars {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(text) {
			return true
		}
	}
	return false
}

func (r *FinancialRoundedDeltaRule) shouldSkip(ctx *core.FileContext) bool {
	path := ctx.RelPath
	if ctx.IsTestFile() {
		return true
	}
	return strings.Contains(path, "/node_modules/") ||
		strings.Contains(path, "/.next/") ||
		strings.Contains(path, "/out/") ||
		strings.Contains(path, "/dist/") ||
		strings.Contains(path, "/generated/") ||
		strings.Contains(path, "generated-") ||
		strings.Contains(path, ".generated")
}

func (r *FinancialRoundedDeltaRule) violation(ctx *core.FileContext, lineNum int, line string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, "Financial delta is calculated from parsed cumulative money fields")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Expose the delta from the backend/canonical calculation layer and render that value directly.")
	v.WithContext("pattern", "financial-rounded-delta")
	v.WithContext("language", "typescript")
	return v
}
