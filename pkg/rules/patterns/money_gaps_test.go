package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A display formatter whose parameter admits a missing value and that
// coerces it with Number(x) || 0 renders a missing amount as a real "$0.00"
// or "+0.00%". A formatter that answers the missing value with a dash, and
// one that treats a zero as missing, are fine.
func TestMissingAmountCoercedToZero_DisplayFormatter(t *testing.T) {
	rule := NewMissingAmountCoercedToZeroRule()
	assert.Equal(t, []string{"src/lib/format.ts:11", "src/lib/format.ts:2", "src/lib/format.ts:20"}, linesOf(t, rule, "src/lib/format.ts", `/** Format as currency. */
export function formatUsd(value: number | string | undefined | null, decimals = 2): string {
  const n = Number(value) || 0
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: decimals }).format(n)
}
export function formatFixed(value: number | string | undefined | null, digits = 2): string {
  const n = Number(value)
  if (!Number.isFinite(n)) return '-'
  return n.toFixed(digits)
}
export function formatUsdCompact(value: number | string | undefined | null): string {
  const n = Math.abs(Number(value) || 0)
  return n >= 1000 ? '$' + (n / 1000).toFixed(1) + 'K' : formatUsd(n, 0)
}
export function formatTokenAmount(value: number | string | undefined | null): string {
  const n = Number(value) || 0
  if (!n) return '-'
  return n.toLocaleString('en-US')
}
function formatPct(value: unknown): string {
  const n = Number(value) || 0
  return (n >= 0 ? '+' : '') + n.toFixed(2) + '%'
}
export function formatCount(value: number): string {
  const n = Number(value) || 0
  return String(n)
}
`))
	assert.Equal(t, []string{"src/app/perf/page.tsx:1", "src/app/perf/page.tsx:5"}, linesOf(t, rule, "src/app/perf/page.tsx", `function formatPct(value: unknown): string {
  const n = Number(value) || 0
  return (n >= 0 ? '+' : '') + n.toFixed(2) + '%'
}
const formatMultiple = (value: unknown): string => {
  const n = parseFloat(String(value)) || 0
  return n.toFixed(2) + 'x'
}
function pnlColor(value: unknown): string {
  const n = Number(value) || 0
  return n > 0 ? 'text-green' : 'text-red'
}
`))
}

// A money local initialized to zero and never assigned again, that still
// enters a calculation and the result: a placeholder for an amount nobody
// computes, stored as a real zero.
func TestSQLMetricLiteralZero_GoZeroPlaceholder(t *testing.T) {
	found := projectRuleLines(t, NewSQLMetricLiteralZeroRule(), map[string]string{
		"nav/nav.go": `package nav

type Money struct{ v int64 }

func MoneyZero() Money            { return Money{} }
func (m Money) Sub(o Money) Money { return m }
func (m Money) Add(o Money) Money { return m }

type Snapshot struct{ Gross, Liabilities, Net Money }

func Build(gross, fees Money) Snapshot {
	totalLiabilities := MoneyZero()
	net := gross.Sub(totalLiabilities).Sub(fees)
	return Snapshot{Gross: gross, Liabilities: totalLiabilities, Net: net}
}

func Sum(items []Money) Money {
	total := MoneyZero()
	for _, it := range items {
		total = total.Add(it)
	}
	return total
}

func Pass(gross Money) Snapshot {
	fee := MoneyZero()
	return Snapshot{Gross: gross, Liabilities: fee}
}

func Count(xs []int) int {
	retries := 0
	return len(xs) - retries
}

func Accrue(gross Money, apply func(*Money)) Money {
	fee := MoneyZero()
	apply(&fee)
	return gross.Sub(fee)
}

func Net(amount int64) int64 {
	fee := int64(0)
	return amount - fee
}
`,
	})
	assert.Equal(t, []string{"nav/nav.go:12", "nav/nav.go:42"}, found)
}

// A float money field of a JSON struct another module declares (a provider
// client) converted to decimal at the consumer: the module's own declaration
// check never sees the field, and the amount already went through float64.
func TestFinancialJSONFloat_DependencyFieldConvertedAtConsumer(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n\n" +
			"require (\n\tgithub.com/shopspring/decimal v0.0.0\n\texample.com/client v0.0.0\n)\n\n" +
			"replace github.com/shopspring/decimal => ./third_party/decimal\n\n" +
			"replace example.com/client => ./third_party/client\n",
		"third_party/decimal/go.mod":     "module github.com/shopspring/decimal\n\ngo 1.24\n",
		"third_party/decimal/decimal.go": decimalStub,
		"third_party/client/go.mod":      "module example.com/client\n\ngo 1.24\n",
		"third_party/client/feed/feed.go": `package feed

type Position struct {
	Attributes struct {
		Price float64 ` + "`json:\"price\"`" + `
		Value float64 ` + "`json:\"value\"`" + `
		Ratio float64 ` + "`json:\"ratio\"`" + `
	} ` + "`json:\"attributes\"`" + `
}

type Jetton struct {
	Price struct {
		Prices map[string]float64 ` + "`json:\"prices\"`" + `
	} ` + "`json:\"price\"`" + `
}
`,
		"app/app.go": `package app

import (
	"example.com/client/feed"
	"github.com/shopspring/decimal"
)

type Local struct {
	Amount float64 ` + "`json:\"amount\"`" + `
}

func Convert(pos feed.Position, j feed.Jetton, l Local, x float64) []decimal.Decimal {
	price := decimal.NewFromFloat(pos.Attributes.Price)
	value := decimal.NewFromFloat(pos.Attributes.Value)
	ratio := decimal.NewFromFloat(pos.Attributes.Ratio)
	priceF := j.Price.Prices["USD"]
	usd := decimal.NewFromFloat(priceF)
	local := decimal.NewFromFloat(l.Amount)
	plain := decimal.NewFromFloat(x)
	return []decimal.Decimal{price, value, ratio, usd, local, plain}
}
`,
	})
	violations, err := NewFinancialJSONFloatRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var app []string
	for _, line := range foundLines(violations) {
		if strings.HasPrefix(line, "app/") {
			app = append(app, line)
		}
	}
	assert.Equal(t, []string{"app/app.go:13", "app/app.go:14", "app/app.go:17", "app/app.go:9"}, app)
}
