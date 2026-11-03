package frontendrules

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestFrontendMoneyArithmeticLargeFileCompletes(t *testing.T) {
	source := "let value = 0;" + strings.Repeat("value += 1;", 1<<17)
	start := time.Now()
	rulestest.TextFileRuleLines(t, NewFrontendMoneyArithmeticRule(), "frontend/src/generated.ts", source)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("analyzing %d bytes took %s, want at most 10s", len(source), elapsed)
	}
}

func TestFormattingIndexFindsContainingRangeBehindNestedRange(t *testing.T) {
	code := "function formatOuter(){function formatInner(){}; Math.round(value)}"
	f := patternkit.JsFlat{Code: code}
	index := newFormattingIndex(f, f.Functions())
	pos := strings.Index(code, "Math.round")
	assert.True(t, index.inFunction(pos))
}

func TestFormattingIndexUsesBraceScopesWithoutPairedAllBracketClose(t *testing.T) {
	code := `function formatAmount(){const view = <div title="(">; Math.round(value)`
	f := patternkit.JsFlat{Code: code}
	index := newFormattingIndex(f, f.Functions())
	pos := strings.Index(code, "Math.round")
	assert.True(t, index.inFunction(pos))
}

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
			name:     "a parsed amount inside a function returning a tuple",
			filename: "pair.ts",
			code: `export function pair(o: O): [number, number] {
  const v = parseFloat(o.amount)
  const w = v * 2
  return [w, w]
}
`,
			wantCount: 1,
		},
		{
			name:     "a parsed amount inside a computed method",
			filename: "bag.ts",
			code: `export class Bag {
  [Symbol.iterator]() {
    const v = parseFloat(this.o.amount)
    return [v * 2].values()
  }
}
`,
			wantCount: 1,
		},
		{
			name:     "a parsed amount inside a downleveled async generator",
			filename: "load.js",
			code: `function load(o){return __awaiter(this,void 0,void 0,function*(){const v=parseFloat(o.amount);return v*2})}
`,
			wantCount: 1,
		},
		{
			name:     "a counter parameter of a function returning a tuple",
			filename: "pages.ts",
			code: `export function pages(o: O, amount = 3): [number, number] {
  const a = amount * 2
  return [a, a]
}
`,
			wantCount: 0,
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

// A money field on the right of a compound assignment adds money as surely as
// one on the left: total += it.price sums prices on the client. A counter or
// a length on the right is no money.
func TestFrontendMoneyArithmetic_CompoundAssignMoneyOnRight(t *testing.T) {
	files := map[string]string{
		"frontend/calc.ts": `export function sum(items: Item[]) {
  let total = 0
  for (const it of items) {
    total += it.price
    count -= it.fee
  }
  return total
}
export function layout(rows: Row[]) {
  let width = 0
  for (const row of rows) {
    width += row.padding
    shown += row.prices.length
    pricesApplied += row.appliedRows
  }
  return width
}
`,
	}
	assert.Equal(t, []string{"frontend/calc.ts:4", "frontend/calc.ts:5"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

// A money field appended to a string builds text, not a sum: the
// accumulator holds a string, or the right side ends in a string literal.
func TestFrontendMoneyArithmetic_CompoundAssignStringConcat(t *testing.T) {
	files := map[string]string{
		"frontend/csv.ts": `export function toCsv(rows: Row[]): string {
  let csv = "id,amount\n"
  for (const row of rows) {
    csv += row.id + ","
    csv += row.amount + "\n"
  }
  return csv
}
export function tooltip(p: Point): string {
  let text = p.label
  text += ": "
  text += p.price
  return text
}
export function binary(rows: Row[]): string {
  let csv = ""
  for (const row of rows) csv = csv + row.amount + "\n"
  return csv
}
export function lines(rows: Row[], out: Out, p: Point) {
  rows.forEach((row) => { out.text += row.amount + " USD" })
  let line = ` + "``" + `
  line += p.price
}
export function sum(items: Item[], qty: number) {
  let total = 0
  for (const it of items) {
    total += it.price
    total += it.price * qty
    total = total + it.fee
  }
  return total
}
export function other(p: Point) {
  let label = ""
  let total = 0
  total += p.price
  return label
}
`,
	}
	// The file-wide conservative string rule permits the mixed-use tooltip,
	// callback, and template accumulators after their nonliteral += assignments.
	assert.Equal(t, []string{"frontend/csv.ts:12", "frontend/csv.ts:17", "frontend/csv.ts:23", "frontend/csv.ts:28", "frontend/csv.ts:29", "frontend/csv.ts:30", "frontend/csv.ts:37"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_StringAccumulatorClearedByNumber(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function total(items: Item[]) {
  let total = ""
  total = 0
  for (const it of items) total += it.price
}
`}
	assert.Equal(t, []string{"frontend/total.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_TemplateAccumulatorClearedByNumber(t *testing.T) {
	files := map[string]string{"frontend/total.ts": "export function total(items: Item[]) {\n  let total = `start`\n  total = 0\n  for (const it of items) total += it.price\n}\n"}
	assert.Equal(t, []string{"frontend/total.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_BlockShadowDoesNotClearOuterAccumulator(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function total(items: Item[], mode: string) {
  let total = 0
  if (flag) { let total = ""; total += items.length }
  for (const it of items) total += it.price
}
`}
	assert.Equal(t, []string{"frontend/total.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_StringInParserFallbackDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function total(items: Item[], seed: Seed, url: URL) {
  let parsed = parseFloat(seed.amount || "0")
  for (const it of items) parsed += it.price
  let numbered = Number(url.searchParams.get("amount") ?? 0)
  for (const it of items) numbered += it.price
}
`}
	assert.Equal(t, []string{"frontend/total.ts:3", "frontend/total.ts:5"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_StringInObjectArgumentDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function total(items: Item[], seed: Seed) {
  let total = parseTotal({ label: "" })
  for (const it of items) total += it.price
}
`}
	assert.Equal(t, []string{"frontend/total.ts:3"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_CommaAssignmentDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function total(items: Item[], mode: boolean) {
  let total = 0, note = ""
  for (const it of items) total += it.price
}
`}
	assert.Equal(t, []string{"frontend/total.ts:3"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_AssignmentAfterComparisonDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function total(items: Item[], mode: string) {
  let total = ""
  if (mode === "x") { total = 0 }
  for (const it of items) total += it.price
}
`}
	assert.Equal(t, []string{"frontend/total.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ArrowParameterDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function total(items: Item[]) {
  let total = ""
  const add = (total: number): number => total + 1
  for (const it of items) total += it.price
}
`}
	assert.Equal(t, []string{"frontend/total.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_FunctionDefaultParameterDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function total(items: Item[]) {
  let total = 0
  function label(total = "") { return total }
  for (const it of items) total += it.price
}
`}
	assert.Equal(t, []string{"frontend/total.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ClosureStringAppendIsNotMoney(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function render(rows: Row[]) {
  let out = ""
  rows.forEach((row) => { out += row.amount })
}
`}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_EqualityDoesNotMarkAccumulatorString(t *testing.T) {
	files := map[string]string{"frontend/cmp.ts": `export function total(items: Item[]) {
  let total = 0
  if (total === "") return 0
  for (const it of items) total += it.price
}
`}
	assert.Equal(t, []string{"frontend/cmp.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ArrowDoesNotMarkOuterAccumulatorString(t *testing.T) {
	files := map[string]string{"frontend/cmp.ts": `export function arrow(items: Item[]) {
  return items.reduce((total, it) => { const label = total => total + ""; total += it.price; return total }, 0)
}
`}
	assert.Equal(t, []string{"frontend/cmp.ts:2"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_NumberThenStringAppendKeepsMoneyFinding(t *testing.T) {
	files := map[string]string{"frontend/append.ts": `export function sum(items: Item[]) {
  let total = 0
  for (const it of items) total += it.price
  return total
}
export function label(n: number) {
  let total = 0
  total += " units"
  return total
}
`}
	assert.Equal(t, []string{"frontend/append.ts:3"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_StringAccumulatorAppendWithoutReset(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function render(rows: Row[]) {
  let out = ""
  for (const row of rows) out += row.amount
}
`}
	assert.Equal(t, []string{"frontend/total.ts:3"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_JSXTextIsNotStringAssignment(t *testing.T) {
	files := map[string]string{
		"frontend/total.tsx": `export function sum(rows: Row[]) {
  let total
  for (const row of rows) total += row.amount
}
export function label() {
  const node = <div>total = ""</div>
  return node
}
`,
		"frontend/self.tsx": `export function label() { return <p>total = "loading"</p> }
export function calc(row: Row) {
  let total
  total = total + parseFloat(row.amount)
  return total
}
`,
		"frontend/fee.tsx": `export function label() { return <p>amount = "loading"</p> }
export function calcFee(row: Row) {
  const fee = amount + parseFloat(row.price)
  return fee
}
`,
	}
	assert.Equal(t, []string{"frontend/fee.tsx:3", "frontend/self.tsx:4", "frontend/total.tsx:3"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_GenericTypeBeforeMoneyAppend(t *testing.T) {
	files := map[string]string{"frontend/generic.ts": `export function label() {
  let total = ""
  return total
}
export function calc(rows: Row[]) {
  let total
  const values: Map<string, number>
  total += row.amount
  return total
}
`}
	assert.Equal(t, []string{"frontend/generic.ts:8"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_JSXClosingTagBeforeMoneyAppend(t *testing.T) {
	files := map[string]string{"frontend/tag.tsx": `export function label() {
  let total = ""
  return total
}
export function calc(rows: Row[]) {
  let total
  const node = <div>text</div>
  total += row.amount
  return node
}
`}
	assert.Equal(t, []string{"frontend/tag.tsx:8"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_GenericTypeBeforeStringAssignment(t *testing.T) {
	files := map[string]string{"frontend/generic.ts": `export function decl() {
  let values: Map<string, number>
  amount = ""
  return values
}
export function calc(row: Row) {
  const fee = amount + parseFloat(row.price)
  return fee
}
`}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_JSXSelfClosingTagBeforeStringAssignment(t *testing.T) {
	files := map[string]string{"frontend/tag.tsx": `export function View() {
  const node = <div className="x" />
  amount = ""
  return node
}
export function calc(row: Row) {
  const fee = amount + parseFloat(row.price)
  return fee
}
`}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_JSXClosingTagBeforeStringAssignment(t *testing.T) {
	files := map[string]string{"frontend/tag.tsx": `export function View() {
  const node = <div>text</div>
  amount = ""
  return node
}
export function calc(row: Row) {
  const fee = amount + parseFloat(row.price)
  return fee
}
`}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_NonStringCompoundAssignmentClearsAccumulator(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function label() {
  let total = ""
  return total
}
export function sum(rows: Row[]) {
  let total
  for (const row of rows) total += row.amount
  return total
}
`}
	assert.Equal(t, []string{"frontend/total.ts:7"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_FunctionNameIsNotParameterBinding(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function render() { return null }
export function sum(rows: Row[]) {
  let render = ""
  for (const row of rows) render = render + row.amount
}
`}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ParenthesizedSelfReferenceStaysString(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function sum(rows: Row[]) {
  let out = ""
  out = (out + "x")
  for (const row of rows) out = out + row.amount
}
`}
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_FunctionDefaultParameterIsExcluded(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function sum(rows: Row[]) {
	  let total
	  function label(total = "") { return total }
	  for (const row of rows) total += row.amount
}
`}
	assert.Equal(t, []string{"frontend/total.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_ArrowDefaultParameterIsExcluded(t *testing.T) {
	files := map[string]string{"frontend/total.ts": `export function sum(rows: Row[]) {
	  let total
	  const label = (total = "") => total
	  for (const row of rows) total += row.amount
}
`}
	assert.Equal(t, []string{"frontend/total.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

// A money field that only decides what a counter adds is not added itself;
// a money value in a branch of that decision is.
func TestFrontendMoneyArithmetic_GenericCallDoesNotHideMoneyAppend(t *testing.T) {
	files := map[string]string{"frontend/generic.ts": `export function label() {
  let total = ""
  return total
}
export function sum(rows: Row[]) {
  let total
  const parsed = parseRows<Row>(rows)
  for (const row of rows) total += row.amount
  return total
}
`}
	assert.Equal(t, []string{"frontend/generic.ts:8"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_GenericHookDoesNotHideMoneyAppend(t *testing.T) {
	files := map[string]string{"frontend/react.tsx": `export function label() {
  let total = ""
  return total
}
export function Sum({ rows }: { rows: Row[] }) {
  let total
  const [state, setState] = useState<Row[]>([])
  for (const row of rows) total += row.amount
  return <div>{state.map((r) => r.id)}</div>
}
`}
	assert.Equal(t, []string{"frontend/react.tsx:8"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_FunctionParameterStringDefaultDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/params.ts": `export function sum(total = "", rows: Row[]) {
  rows.forEach((row) => { total += row.amount })
  return total
}
`}
	assert.Equal(t, []string{"frontend/params.ts:2"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_NestedFunctionHeaderDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/params.ts": `export function sum(rows: Row[]) {
  let total
  function label(total = "") { return total }
  for (const row of rows) total += row.amount
}
`}
	assert.Equal(t, []string{"frontend/params.ts:4"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_NestedArrowHeaderDoesNotHideMoney(t *testing.T) {
	files := map[string]string{"frontend/params.ts": `export function label() {
  let amount = ""
  return amount
}
export function fee(row: Row) {
  const value = (amount) => amount + parseFloat(row.price)
  return value
}
`}
	assert.Equal(t, []string{"frontend/params.ts:6"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

func TestFrontendMoneyArithmetic_CompoundAssignMoneyInCondition(t *testing.T) {
	files := map[string]string{
		"frontend/count.ts": `export function countPriced(items: Item[], max: number): number {
  let count = 0
  let total = 0
  for (const it of items) {
    count += it.price ? 1 : 0
    count += it.amount > 0 ? 1 : 0
    count += it.fee === undefined ? 0 : 1
    count += (it.price !== 0)
    count = count + (it.price ? 1 : 0)
    total += it.price > max ? max : it.price
    total += it.fee ? it.amount : 0
    total += it.price ?? 0
    total = total + it.price > 0
  }
  return count + total
}
`,
	}
	assert.Equal(t, []string{"frontend/count.ts:10", "frontend/count.ts:11", "frontend/count.ts:12", "frontend/count.ts:13"}, rulestest.ProjectFilesRulePlaces(t, NewFrontendMoneyArithmeticRule(), files))
}

// jsxTagOperatorScan is the former per-offset check jsxTagOperators replaces:
// it reads back from each offset to the last '<'.
func jsxTagOperatorScan(code string, pos int) bool {
	start := strings.LastIndex(code[:pos], "<")
	if start < 0 || strings.Contains(code[start:pos], ">") {
		return false
	}
	i := start + 1
	if i < pos && code[i] == '/' {
		i++
	}
	if i >= pos || (code[i] < 'A' || code[i] > 'Z') && (code[i] < 'a' || code[i] > 'z') {
		return false
	}
	depth := 0
	var quote byte
	for i = start + 1; i < pos; i++ {
		c := code[i]
		if quote != 0 {
			if c == quote && (i == 0 || code[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return quote != 0 || depth == 0
}

// jsxTagOperators answers as the per-offset scan does for every offset.
func TestJsxTagOperatorsMatchScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("<>/{}'\"`\\aZ +=-")
	for range 3000 {
		code := make([]byte, rng.Intn(30))
		for i := range code {
			code[i] = alphabet[rng.Intn(len(alphabet))]
		}
		var positions []int
		for i := range code {
			if rng.Intn(3) == 0 {
				positions = append(positions, i)
			}
		}
		got := jsxTagOperators(string(code), positions)
		for k, pos := range positions {
			if want := jsxTagOperatorScan(string(code), pos); got[k] != want {
				t.Fatalf("offset %d of %q: one pass %v, scan %v", pos, code, got[k], want)
			}
		}
	}
}

// Operators far from the last '<' cost no walk back to it: the time grows
// with the file, not with its square.
func TestFrontendMoneyArithmeticCompoundAssignsGrowLinearly(t *testing.T) {
	source := func(n int) string {
		return "export function s(o){let total=0;" + strings.Repeat("total+=o.price;", n) + "return total}"
	}
	if growth := ruleGrowth(t, NewFrontendMoneyArithmeticRule(), "web/src/sum.js", source, 1<<12); growth > 8 {
		t.Errorf("four times the input took %.1f times as long, want at most 8", growth)
	}
}
