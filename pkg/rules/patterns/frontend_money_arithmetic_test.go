package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFrontendMoneyArithmeticRule(t *testing.T) {
	rule := NewFrontendMoneyArithmeticRule()

	tests := []struct {
		name      string
		filename  string
		code      string
		wantCount int
	}{
		{
			name:     "accumulating parsed investment amounts",
			filename: "user-service.ts",
			code: `const investedAmount = 0
investments.forEach((inv) => {
  investedAmount += parseFloat(inv.amount)
})
`,
			wantCount: 1,
		},
		{
			name:     "reduce-summing parsed withdrawal amounts",
			filename: "FinancialDashboard.tsx",
			code: `const pendingAmount = pending.reduce((sum, w) => sum + parseFloat(w.amount || '0'), 0)
`,
			wantCount: 1,
		},
		{
			name:     "subtracting parsed money values",
			filename: "dashboard.ts",
			code: `const totalReturn = parseFloat(inv.currentValue) - parseFloat(inv.amount)
`,
			wantCount: 1,
		},
		{
			name:     "reduce over raw money field",
			filename: "stats.ts",
			code: `const total = rows.reduce((acc, r) => acc + r.balance, 0)
`,
			wantCount: 1,
		},
		{
			name:     "formatting a parsed amount is display only",
			filename: "modal.tsx",
			code: `const label = formatAmount(parseFloat(withdrawal.amount))
`,
			wantCount: 0,
		},
		{
			name:     "comparison is not arithmetic",
			filename: "validation.ts",
			code: `if (parseFloat(form.amount) > maxAmount) {
  setError('too much')
}
`,
			wantCount: 0,
		},
		{
			name:     "non-money numbers are out of scope",
			filename: "chart.ts",
			code: `const width = parseFloat(style.width) + padding * 2
const days = items.reduce((acc, i) => acc + i.retryCount, 0)
`,
			wantCount: 0,
		},
		{
			name:     "test files are skipped",
			filename: "user-service.test.ts",
			code: `expect(parseFloat(inv.amount) + parseFloat(inv.fee)).toBe(150)
`,
			wantCount: 0,
		},
		{
			name:     "go files are out of scope",
			filename: "service.go",
			code: `total := parseFloat(inv.amount) + 1
`,
			wantCount: 0,
		},
		{
			name:     "Number() aggregation over money field",
			filename: "summary.ts",
			code: `let feeTotal = 0
for (const tx of txs) {
  feeTotal = feeTotal + Number(tx.serviceFee)
}
`,
			wantCount: 1,
		},
		{
			name:     "parseFloat inside trailing comment is not code",
			filename: "types.ts",
			code: `export interface ChartDataPoint {
  balance: number        // parseFloat(DailyBalanceEntry.totalBalance) - parseFloat(x)
  deposits: number       // parseFloat(DailyBalanceEntry.deposits) + 1
}
`,
			wantCount: 0,
		},
		{
			name:     "sort comparator subtracting the same money field",
			filename: "deposits.tsx",
			code: `rows.sort((a, b) => {
  return (parseFloat(String(a.amount)) - parseFloat(String(b.amount))) * dir
})
`,
			wantCount: 0,
		},
		{
			name:     "trend delta of the same money field across periods",
			filename: "analytics.tsx",
			code: `const delta = hasPrev
  ? (parseFloat(prevWindow.business?.withdrawals ?? '0') - parseFloat(business?.withdrawals ?? '0'))
  : 0
`,
			wantCount: 0,
		},
		{
			name:     "accumulating money variable derived from parseFloat",
			filename: "user-service.ts",
			code: `const invAmount = parseFloat(String(inv.amount))
investedAmount += invAmount
`,
			wantCount: 1,
		},
		{
			name:     "accumulating non-money variables is out of scope",
			filename: "layout.ts",
			code: `width += padding
retries += attempt
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}
