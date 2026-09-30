package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFinancialRoundedDeltaRule(t *testing.T) {
	rule := NewFinancialRoundedDeltaRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "parsed cumulative profit subtraction is forbidden",
			code: `const currentProfit = parseFloat(entry.profit)
const prevProfit = parseFloat(previous.profit)
const dailyDelta = currentProfit - prevProfit`,
			filename:  "frontend/src/hooks/useOperations.ts",
			wantCount: 1,
		},
		{
			name:      "direct parsed amount subtraction is forbidden",
			code:      `const delta = parseFloat(today.balance) - parseFloat(yesterday.balance)`,
			filename:  "frontend/src/lib/balance.ts",
			wantCount: 1,
		},
		{
			name: "backend delta field is valid",
			code: `const dailyDelta = parseFloat(entry.dailyYield)
if (Math.abs(dailyDelta) < 0.001) return`,
			filename:  "frontend/src/hooks/useOperations.ts",
			wantCount: 0,
		},
		{
			name:      "non financial numeric subtraction is valid",
			code:      `const duration = parseFloat(endMs) - parseFloat(startMs)`,
			filename:  "frontend/src/lib/timing.ts",
			wantCount: 0,
		},
		{
			name: "parsed var name matches only as a whole word",
			code: `const profit = parseFloat(entry.profit)
const delta = profitRate - profitScore`,
			filename:  "frontend/src/lib/rates.ts",
			wantCount: 0,
		},
		{
			// "profitability" and "evaluation" only contain money fragments;
			// no word of either name is a money field.
			name: "money fragments inside other words are not money fields",
			code: `const dailyDelta = parseFloat(today.profitability) - parseFloat(yesterday.profitability)
const score = parseFloat(entry.evaluation)
const scoreChange = score - parseFloat(prev.evaluation)`,
			filename:  "frontend/src/lib/ratios.ts",
			wantCount: 0,
		},
		{
			name:      "camel-case money field words are still money",
			code:      `const dailyChange = Number(today.totalValue) - Number(yesterday.totalValue)`,
			filename:  "frontend/src/lib/portfolio.ts",
			wantCount: 1,
		},
		{
			name:      "test files are skipped",
			code:      `const dailyDelta = parseFloat(entry.profit) - parseFloat(prev.profit)`,
			filename:  "frontend/src/hooks/useOperations.test.ts",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d (%q)", v.Message, v.Line, v.Code)
				}
			}
		})
	}
}
