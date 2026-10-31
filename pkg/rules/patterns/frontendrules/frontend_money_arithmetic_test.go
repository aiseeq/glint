package frontendrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
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
  balance: number        // parseFloat(DailyLedgerEntry.totalBalance) - parseFloat(x)
  deposits: number       // parseFloat(DailyLedgerEntry.deposits) + 1
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

func TestFrontendMoneyArithmetic_DecimalFieldViaHelper(t *testing.T) {
	files := map[string]string{
		"api/types.go": "package api\ntype MoneyDecimal string\ntype Totals struct { ValueUsd MoneyDecimal " + "`json:\"valueUsd\"`" + " }\ntype Flow struct { NetUsd MoneyDecimal " + "`json:\"netUsd\"`" + " }\n",
		"frontend/types.ts": `interface Totals { valueUsd?: MoneyDecimal | null }
interface Flow { netUsd?: MoneyDecimal | null }
`,
		"frontend/report.ts": `const accountingValue = report && report.flow ? toNumberOr(report.totals.valueUsd, null) : null
const accountingInflow = report?.flow ? toNumberOr(report.flow.netUsd, null) : null
const accountingResult = accountingValue !== null && accountingInflow !== null
  ? accountingValue - accountingInflow
  : null
`,
	}
	assert.Equal(t, []string{"frontend/report.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_TSDecimalType(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal; count: number }`,
		"frontend/calc.ts":  "const x = Number(t.valueUsd) * 2\nconst y = Number(t.count) * 2\n",
	}
	assert.Equal(t, []string{"frontend/calc.ts:1"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_MathRounding(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal; count: number }`,
		"frontend/calc.ts":  "Math.round(toNumber(t.valueUsd))\nMath.floor(toNumber(t.count))\nconst v = toNumber(t.valueUsd)\nMath.ceil(v)\n",
	}
	assert.Equal(t, []string{"frontend/calc.ts:1", "frontend/calc.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_MoneyVariableNotArithmetic(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal; count: number }`,
		"frontend/calc.ts":  "const amount = toNumber(t.valueUsd)\namount !== null\nformatAmount(amount)\nf.money0(amount)\n'$' + amount\nconst n = toNumber(t.count)\nn - 1\n",
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ConflictingFieldType(t *testing.T) {
	files := map[string]string{
		"api/types.go":     "package api\ntype MoneyDecimal string\ntype Totals struct { ValueUsd MoneyDecimal " + "`json:\"valueUsd\"`" + " }\ntype Metrics struct { ValueUsd float64 " + "`json:\"valueUsd\"`" + " }\n",
		"frontend/calc.ts": `const value = Number(x.valueUsd) * 2`,
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_CustomParsers(t *testing.T) {
	rule := NewFrontendMoneyArithmeticRule()
	assert.NoError(t, rule.Configure(map[string]any{"number_parsers": "asAmount"}))
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal }`,
		"frontend/calc.ts":  "asAmount(t.valueUsd) - 1\ntoNumber(t.valueUsd) - 1\n",
	}
	assert.Equal(t, []string{"frontend/calc.ts:1"}, rulestest.ProjectFilesRulePlaces(t, rule, files))
}

func TestFrontendMoneyArithmetic_OperatorFarFromParse(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal }`,
		"frontend/calc.ts":  "const w = width - padding\nconst v = toNumber(t.valueUsd)\n",
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_JSXNotArithmetic(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal; incomeUsd: MoneyDecimal }`,
		"frontend/view.tsx": `const v = toNumber(row.incomeUsd)
const w = toNumber(other.incomeUsd)
const a = <div className="a-b">{formatAmount(v)}</div>
const b = <Field label="x"><Money value={row.incomeUsd} /></Field>
const c = <span>{v - w}</span>
`,
	}
	assert.Equal(t, []string{"frontend/view.tsx:5"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ParseInsideComparisonOperand(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal }`,
		"frontend/calc.ts":  "'Итого' + (toNumberOr(t.valueUsd, 0) > 0 ? ` + ${x}` : '')\n",
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ComparisonScalingNotArithmetic(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal }`,
		"frontend/calc.ts":  "if (Math.round(toNumber(t.valueUsd) * 100) !== Math.round(other * 100)) continue\n",
	}
	assert.Equal(t, []string{"frontend/calc.ts:1"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_PercentageRatios(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal; balanceUsd: MoneyDecimal }`,
		"frontend/calc.ts": `const value = toNumber(t.valueUsd)
const balance = toNumber(t.balanceUsd)
const target = toNumber(t.valueUsd)
const fill = (balance / target) * 100
const width = (value / target * 100).toFixed(2) + '%'
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:4", "frontend/calc.ts:5"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_RoundingMoneyName(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { totalUsd: MoneyDecimal }`,
		"frontend/calc.ts": `f.money0(Math.floor(balance))
Math.floor(count)
Math.round(width)
Math.trunc(t.totalUsd)
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:1", "frontend/calc.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_MoneyShare(t *testing.T) {
	files := map[string]string{
		"frontend/calc.ts": `export const a3 = Math.min(100, (balance / MIN) * 100)
const ratio = (done / total) * 100
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:1"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_CentRoundingShape(t *testing.T) {
	files := map[string]string{
		"frontend/calc.ts": `export function floorToCent(value: number): number {
  return Math.floor(value * 100 + 1e-9) / 100
}
const ratio = Math.round(ratioValue * 1000) / 1000
const legacy = Math.floor(balance * 100) / 100
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:2"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))

	rule := NewFrontendMoneyArithmeticRule()
	assert.NoError(t, rule.Configure(map[string]any{"money_formatter": "renderCents"}))
	formatter := map[string]string{
		"frontend/format.ts": `function renderCents(value: number): number {
  return Math.floor(value * 100) / 100
}
`,
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, rule, formatter))
}

func TestFrontendMoneyArithmetic_CompoundAssignMoneyVariable(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { netUsd: MoneyDecimal }`,
		"frontend/calc.ts":  "const v = Number(r.netUsd)\nv += 2\n",
	}
	assert.Equal(t, []string{"frontend/calc.ts:2"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_FallbackAfterDecimalField(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { netUsd: MoneyDecimal }`,
		"frontend/calc.ts": `Number(r?.netUsd ?? fallback) + 2
Number(count ?? r.netUsd) + 2
Number(r.count ?? 0) + 2
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:1", "frontend/calc.ts:2"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ArithmeticInsideComparison(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { netUsd: MoneyDecimal }`,
		"frontend/calc.ts": `const v = Number(r.netUsd)
if (v + 10 > 100) {}
if (v > 100) {}
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:2"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_FormatterArithmeticNotMoney(t *testing.T) {
	files := map[string]string{
		"frontend/calc.ts": `export function formatCompactAmount(value: string): string {
  return value.replace(/\\$(\\d+)/, (_match, amount: string) => {
    const numeric = Number(amount)
    const compact = numeric % 1000 === 0 ? String(numeric / 1000) : (numeric / 1000).toFixed(1)
    return '$' + compact + 'k'
  })
}
`,
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_E2EHelpersAreTests(t *testing.T) {
	files := map[string]string{
		"frontend/e2e/helpers/calc.ts": "const halfAmount = Math.max(1, Math.floor(availableBalance / 2))\n",
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_JSXTagSyntaxNotArithmetic(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { balance: MoneyDecimal }`,
		"frontend/view.tsx": `const v = toNumber(row.balance)
const col = <col className={period ? 'w-[13%]' : 'w-[15%]'} />{
<nav></nav>
<div data-locked={locked ? '' : undefined}></div>
<span className="gc-amtwrap"><b data-gc-amount="">{giftCardAmountText(amount)}</b></span>
`,
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_NonMoneyNameSubstrings(t *testing.T) {
	files := map[string]string{
		"frontend/calc.tsx": `const version = txn ? 2 + feed.filter((item) => item.kind === 'txn').length : 0
const requested = 3 + (canReadBalances ? 1 : 0)
const cutoff = now - PENDING_DEPOSIT_WINDOW_MS
const label = network.charAt(0).toUpperCase() + network.slice(1)
const pricesApplied = 0
pricesApplied += result.appliedRows
<nav></nav>
`,
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_UnaryNotArithmetic(t *testing.T) {
	files := map[string]string{
		"frontend/types.ts": `interface Totals { valueUsd: MoneyDecimal }`,
		"frontend/calc.ts": `const v = toNumber(t.valueUsd)
const negative = -v
const direct = -toNumber(t.valueUsd)
requestRef.current++
--v
`,
	}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_MoneyWordLastPart(t *testing.T) {
	files := map[string]string{
		"frontend/calc.ts": `const usedPct = quota.monthlyLimit > 0 ? (quota.creditsUsedMonth / quota.monthlyLimit) * 100 : 0
const sentPct = (sentAmount / limit) * 100
const yieldPct = (yieldIncome / limit) * 100
const investmentPct = (MIN_BALANCE_FOR_INVESTMENT / limit) * 100
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:2", "frontend/calc.ts:3", "frontend/calc.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_CounterParameterDefault(t *testing.T) {
	files := map[string]string{
		"frontend/calc.ts": `function increment(counter: Map<string, number>, key: string, amount = 1): void {
  counter.set(key, (counter.get(key) ?? 0) + amount)
}
function f(amount: number) {
  return amount + fee
}
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:5"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

// A decimal field of the API names a field of a response, not every local of
// that name: a chart scales its axis by its own min and max.
func TestFrontendMoneyArithmetic_ChartScaleNotMoney(t *testing.T) {
	files := map[string]string{
		"api/types.go": "package api\ntype MoneyDecimal string\ntype Limits struct { Min MoneyDecimal " + "`json:\"min\"`" + " }\ntype Quote struct { Value MoneyDecimal " + "`json:\"value\"`" + " }\n",
		"frontend/chart.tsx": `type LineDatum = { label: string; value: number }
export function LineChart({ data, top, chartHeight }: { data: LineDatum[]; top: number; chartHeight: number }) {
  const min = Math.min(...data.map((item) => item.value))
  const max = Math.max(...data.map((item) => item.value))
  const range = max - min || 1
  return data.map((item) => top + (1 - (item.value - min) / range) * chartHeight)
}
`,
		"frontend/limits.ts": `export const span = (limits: Limits) => Number(limits.min) * 2
`,
	}
	assert.Equal(t, []string{"frontend/limits.ts:1"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}
