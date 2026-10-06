package patterns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules"
)

// decimalWanted runs a typed rule on one file of a module that can import
// the decimal package and compares the findings with the // want lines.
func decimalWanted(t *testing.T, rule rules.GoProjectRule, source string) {
	t.Helper()
	var want []string
	for _, line := range wantLines(source) {
		want = append(want, fmt.Sprintf("ledger/ledger.go:%d", line))
	}
	assert.Equal(t, want, typedFuncFindings(t, rule, map[string]string{"ledger/ledger.go": source}))
}

// Repro from a real project: a partial exit took the share of the position
// through a ratio divided first; 2600 - 497.4 left 2102.60000000000002 and
// the position never closed.
func TestDecimalDividedBeforeMultiplied(t *testing.T) {
	decimalWanted(t, NewDecimalDividedBeforeMultipliedRule(), `package ledger

import "github.com/shopspring/decimal"

type Position struct {
	Amount   decimal.Decimal
	Invested decimal.Decimal
}

var hundred = decimal.NewFromInt(100)

func exit(p *Position, nominal decimal.Decimal) decimal.Decimal {
	ratio := nominal.Div(p.Invested)
	taken := p.Amount.Mul(ratio) // want
	return p.Amount.Sub(taken)
}

func exitInline(p *Position, nominal decimal.Decimal) decimal.Decimal {
	return nominal.Div(p.Invested).Mul(p.Amount) // want
}

func exitRight(p *Position, nominal decimal.Decimal) decimal.Decimal {
	return p.Amount.Mul(nominal).Div(p.Invested)
}

func percent(profit, start decimal.Decimal) decimal.Decimal {
	return profit.Div(start).Mul(hundred)
}

func fromPercent(amount, pct decimal.Decimal) decimal.Decimal {
	return amount.Mul(pct.Div(decimal.NewFromInt(100)))
}

func weight(part, whole, count decimal.Decimal) decimal.Decimal {
	return part.Div(whole).Mul(count)
}

type Lot struct {
	Open       decimal.Decimal
	AccruedUSD decimal.Decimal
}

func take(lot *Lot, taken decimal.Decimal) {
	keepShare := lot.Open.Sub(taken).Div(lot.Open)
	lot.AccruedUSD = lot.AccruedUSD.Mul(keepShare) // want
}

func weighted(amount, days, fromStart decimal.Decimal) decimal.Decimal {
	return amount.Mul(days.Sub(fromStart).Div(days))
}

func pow10(n int32) decimal.Decimal { return decimal.New(1, n) }

func value(raw, price decimal.Decimal, decimals int32) decimal.Decimal {
	divisor := decimal.New(1, decimals)
	tokens := raw.Div(divisor)
	return price.Mul(tokens)
}

func valueOf(raw, price decimal.Decimal, decimals int32) decimal.Decimal {
	return price.Mul(raw.Div(pow10(decimals)))
}
`)
}

// Repro from a real project: the digits of an amount were counted after the
// zeros were trimmed, and "10." with 900000 zeros was parsed whole into an
// exponent of -900000.
func TestDecimalParseBoundedByTrimmedDigits(t *testing.T) {
	decimalWanted(t, NewDecimalParseBoundedByTrimmedDigitsRule(), `package ledger

import (
	"errors"
	"math/big"
	"strings"

	"github.com/shopspring/decimal"
)

func parse(raw, whole, frac string) (decimal.Decimal, error) {
	if len(strings.TrimLeft(whole, "0")) > 15 {
		return decimal.Zero, errors.New("too large")
	}
	if len(strings.TrimRight(frac, "0")) > 6 {
		return decimal.Zero, errors.New("too precise")
	}
	return decimal.NewFromString(raw) // want
}

func parseFloat(raw, frac string) (*big.Float, error) {
	if len(strings.TrimRight(frac, "0")) > 6 {
		return nil, errors.New("too precise")
	}
	f, ok := new(big.Float).SetString(raw) // want
	if !ok {
		return nil, errors.New("bad")
	}
	return f, nil
}

func parseCapped(raw, frac string) (decimal.Decimal, error) {
	if len(raw) > 40 {
		return decimal.Zero, errors.New("too long")
	}
	if len(strings.TrimRight(frac, "0")) > 6 {
		return decimal.Zero, errors.New("too precise")
	}
	return decimal.NewFromString(raw)
}

func parseNormalized(whole, frac string) (decimal.Decimal, error) {
	frac = strings.TrimRight(frac, "0")
	if len(frac) > 6 {
		return decimal.Zero, errors.New("too precise")
	}
	return decimal.NewFromString(whole + "." + frac)
}

func parsePlain(raw string) (decimal.Decimal, error) {
	return decimal.NewFromString(raw)
}
`)
}

// Repro from a real project: the daily export rounded the balance half up
// and the day's yield down to the cent in one row; the screens floor both,
// and the same day showed amounts a cent apart.
func TestMoneyRoundingDirectionMixed(t *testing.T) {
	decimalWanted(t, NewMoneyRoundingDirectionMixedRule(), `package ledger

import "github.com/shopspring/decimal"

type Day struct {
	Balance decimal.Decimal
	Yield   decimal.Decimal
	Rate    decimal.Decimal
}

type Entry struct {
	ClosingAmount string
	DailyGain   string
	Rate         string
}

func yieldCents(v decimal.Decimal) string {
	return v.RoundFloor(2).StringFixed(2)
}

func cents(v decimal.Decimal) string {
	return v.StringFixed(2)
}

func mixed(d Day) Entry {
	return Entry{
		ClosingAmount: d.Balance.StringFixed(2), // want
		DailyGain:   yieldCents(d.Yield),
		Rate:         d.Rate.StringFixed(6),
	}
}

func inline(d Day) Entry {
	return Entry{
		ClosingAmount: d.Balance.Truncate(2).StringFixed(2),
		DailyGain:   cents(d.Yield), // want
	}
}

func oneGrid(d Day) Entry {
	return Entry{
		ClosingAmount: yieldCents(d.Balance),
		DailyGain:   yieldCents(d.Yield),
		Rate:         d.Rate.StringFixed(6),
	}
}

func allHalfUp(d Day) Entry {
	return Entry{
		ClosingAmount: d.Balance.StringFixed(2),
		DailyGain:   d.Yield.StringFixed(2),
	}
}
`)
}
