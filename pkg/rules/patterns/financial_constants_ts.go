package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// tsMoneyLimit is an object property of a money limit or a fee set to a
// number: { minAmount: 10 }, { maxWithdrawal: 5000 }, { feePercent: 1.5 }.
var tsMoneyLimit = regexp.MustCompile(`\b((?:min|max)(?:Amount|Deposit|Withdrawal|Withdraw|Investment|Invest|Payout|Transfer|Balance)\w*|fee(?:Percent|Rate|Amount)?|commission\w*)\s*:\s*(\d[\d_]*(?:\.\d+)?)\b`)

// analyzeTS reports a money limit or a fee the frontend writes as a number:
// the backend owns the value and the copy in the UI does not follow it.
func (r *FinancialConstantsRule) analyzeTS(ctx *core.FileContext) []*core.Violation {
	if ctx.IsTestFile() || isE2EPath(ctx.RelPath) || r.shouldSkipFile(ctx.RelPath) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range newJSSource(ctx).code {
		m := tsMoneyLimit.FindStringSubmatch(line)
		if m == nil || strings.Trim(m[2], "0._") == "" {
			continue
		}
		if ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "Money limit or fee "+m[1]+" written as a number in the frontend — the backend owns the value, and this copy does not follow it")
		v.WithCode(strings.TrimSpace(ctx.Lines[i]))
		v.WithSuggestion("Read the limit from the API (the endpoint that serves the product's terms) or from the generated contract")
		violations = append(violations, v)
	}
	return violations
}
