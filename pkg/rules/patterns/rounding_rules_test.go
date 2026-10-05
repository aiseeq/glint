package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The margin summed from the unrounded spreads is rounded on its own next to
// the rounded spreads; a total summed from rounded parts is fine.
func TestRoundedTotalNotSumOfRoundedParts(t *testing.T) {
	assert.Equal(t, []string{"quote/calc.go:22", "quote/calc.go:23"}, typedFuncFindings(t, NewRoundedTotalNotSumOfRoundedPartsRule(), map[string]string{
		"quote/calc.go": `package quote

import "github.com/shopspring/decimal"

type Result struct {
	Transfer, Spread, Security, Margin, Fee, Total decimal.Decimal
}

var hundred = decimal.NewFromInt(100)

func Calculate(transfer, spreadPct, securityPct, feePct decimal.Decimal) *Result {
	spread := transfer.Mul(spreadPct).Div(hundred)
	security := transfer.Mul(securityPct).Div(hundred)
	margin := spread.Add(security)
	fee := transfer.Mul(feePct).Div(hundred)
	total := transfer.Add(fee)
	return &Result{
		Transfer: transfer.Round(2),
		Spread:   spread.Round(2),
		Security: security.Round(2),
		Fee:      fee.Round(2),
		Margin:   margin.Round(2),
		Total:    total.Round(2),
	}
}

func Reconciled(transfer, spreadPct, securityPct decimal.Decimal) *Result {
	spread := transfer.Mul(spreadPct).Div(hundred).Round(2)
	security := transfer.Mul(securityPct).Div(hundred).Round(2)
	return &Result{
		Spread:   spread,
		Security: security,
		Margin:   spread.Add(security),
	}
}

func Mixed(a, b decimal.Decimal) *Result {
	sum := a.Add(b)
	return &Result{Spread: a.Round(2), Security: b.Round(4), Margin: sum.Round(2)}
}
`,
	}))
}

// The client rate is published rounded while the payout was computed with
// the unrounded rate; a rate rounded before use, also by a helper, is fine.
func TestPublishedValueRoundedAfterUse(t *testing.T) {
	assert.Equal(t, []string{"quote/rate.go:13"}, typedFuncFindings(t, NewPublishedValueRoundedAfterUseRule(), map[string]string{
		"quote/rate.go": `package quote

import "github.com/shopspring/decimal"

type Quote struct {
	ClientRate, Payout, Fee decimal.Decimal
}

func Calculate(amount, fxRate, spread decimal.Decimal) *Quote {
	clientRate := fxRate.Mul(decimal.NewFromInt(1).Sub(spread))
	payout := amount.Mul(clientRate)
	return &Quote{
		ClientRate: clientRate.Round(8),
		Payout:     payout.Round(2),
	}
}

func Rounded(amount, fxRate, spread decimal.Decimal) *Quote {
	clientRate := fxRate.Mul(decimal.NewFromInt(1).Sub(spread)).Round(8)
	payout := amount.Mul(clientRate)
	return &Quote{
		ClientRate: clientRate.Round(8),
		Payout:     payout.Round(2),
	}
}

func RoundRate(d decimal.Decimal) decimal.Decimal { return d.Round(8) }

func Report(amount, legA, legB decimal.Decimal, direct bool) *Quote {
	rate := decimal.NewFromInt(1)
	if !direct {
		rate = RoundRate(legA.Mul(legB))
	}
	payout := amount.Mul(rate)
	return &Quote{ClientRate: rate.Round(8), Payout: payout.Round(2)}
}

func Unrelated(rate, fee decimal.Decimal) *Quote {
	return &Quote{ClientRate: rate.Round(8), Fee: fee.Add(fee).Round(2)}
}
`,
	}))
}

// p*n/100 used as a zero-based index sits one rank high; the nearest-rank
// form and a function that is not a percentile are fine.
func TestPercentileIndexOffByOne(t *testing.T) {
	assert.Equal(t, []string{"stats/p.go:9"}, typedFuncFindings(t, NewPercentileIndexOffByOneRule(), map[string]string{
		"stats/p.go": `package stats

import "slices"

func percentile(values []int64, pct int) int64 {
	sorted := make([]int64, len(values))
	copy(sorted, values)
	slices.Sort(sorted)
	idx := (pct * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func nearestRankPercentile(sorted []int64, pct int) int64 {
	idx := (pct*len(sorted)+99)/100 - 1
	return sorted[max(idx, 0)]
}

func share(items []int, pct int) int {
	return (pct * len(items)) / 100
}
`,
	}))
}
