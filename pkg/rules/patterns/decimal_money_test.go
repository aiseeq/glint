package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMoneyScannedIntoFloat(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"ledger/repo.go": `package ledger

import (
	"context"
	"database/sql"

	"github.com/shopspring/decimal"
)

type Wallet struct {
	ID      string
	Balance float64
	Weight  float64
	Fee     decimal.Decimal
}

func balance(ctx context.Context, db *sql.DB, user string) (decimal.Decimal, error) {
	var totalDeposits, totalWithdrawals float64
	err := db.QueryRowContext(ctx, "SELECT 1, 2", user).Scan(
		&totalDeposits,
		&totalWithdrawals,
	)
	if err != nil {
		return decimal.Zero, err
	}
	return decimal.NewFromFloat(totalDeposits - totalWithdrawals), nil
}

func wallets(ctx context.Context, db *sql.DB) ([]Wallet, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, balance, weight, fee FROM wallets")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Wallet
	for rows.Next() {
		var w Wallet
		if err := rows.Scan(&w.ID, &w.Balance, &w.Weight, &w.Fee); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func nullable(ctx context.Context, db *sql.DB) (sql.NullFloat64, int64, float64, error) {
	var pendingAmount sql.NullFloat64
	var count int64
	var ratio float64
	err := db.QueryRowContext(ctx, "SELECT 1, 2, 3").Scan(&pendingAmount, &count, &ratio)
	return pendingAmount, count, ratio, err
}

type scanner struct{}

func (scanner) Scan(dest ...any) error { return nil }

func notDatabase(s scanner) float64 {
	var price float64
	_ = s.Scan(&price)
	return price
}
`,
	})
	violations, err := NewMoneyScannedIntoFloatRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []int{20, 21, 38, 50}, violationLines(violations))
}

func TestDecimalMarshalRounds(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"money/money.go": `package money

import (
	"database/sql/driver"
	"encoding/json"

	"github.com/shopspring/decimal"
)

type Amount struct {
	decimal.Decimal
}

func (a Amount) MarshalJSON() ([]byte, error) {
	precision := int32(6)
	if a.Abs().LessThan(decimal.New(1, -6)) {
		precision = 18
	}
	return json.Marshal(a.StringFixed(precision))
}

func (a Amount) Value() (driver.Value, error) {
	return a.Decimal.Truncate(6).String(), nil
}

type Quantity struct {
	decimal.Decimal
}

func (q Quantity) StringFixed(places int32) string { return q.Decimal.StringFixed(places) }

func (q Quantity) MarshalText() ([]byte, error) {
	return []byte(q.StringFixed(2)), nil
}

type Exact struct {
	decimal.Decimal
}

func (e Exact) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

type Scaled struct {
	value  decimal.Decimal
	places int32
}

func (s Scaled) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.value.StringFixed(s.places))
}

type Report struct {
	Total decimal.Decimal
}

func (r Report) Summary() string { return r.Total.StringFixed(2) }
`,
	})
	violations, err := NewDecimalMarshalRoundsRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []int{19, 23, 33}, violationLines(violations))
}

func TestDecimalDivUnguarded(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"growth/growth.go": `package growth

import (
	"errors"

	"github.com/shopspring/decimal"
)

var hoursPerDay = decimal.NewFromInt(24)

type Snapshot struct{ Value decimal.Decimal }

func rate(first, last Snapshot, hours int64) decimal.Decimal {
	if hours <= 0 {
		return decimal.Zero
	}
	days := decimal.NewFromInt(hours).Div(hoursPerDay)
	growth := last.Value.Sub(first.Value).Div(first.Value)
	return growth.Div(days)
}

func guarded(first, last Snapshot) (decimal.Decimal, error) {
	if first.Value.IsZero() {
		return decimal.Zero, errors.New("zero")
	}
	return last.Value.Div(first.Value), nil
}

func share(part, total decimal.Decimal) decimal.Decimal {
	if total.Sign() <= 0 {
		return decimal.Zero
	}
	return part.DivRound(total, 8)
}

func percent(part decimal.Decimal) decimal.Decimal {
	return part.Div(decimal.NewFromInt(100))
}

func compare(part, total decimal.Decimal) decimal.Decimal {
	if total.GreaterThan(decimal.Zero) {
		return part.Div(total)
	}
	return decimal.Zero
}

func unguarded(part, total decimal.Decimal) decimal.Decimal {
	return part.Mod(total)
}

const scale = 1000

func constant(part decimal.Decimal) decimal.Decimal {
	return part.Div(decimal.NewFromInt(scale))
}

type curve struct{ base decimal.Decimal }

func (c curve) factor(rate decimal.Decimal, years int64) decimal.Decimal { return c.base }

// A check of years says nothing of what factor makes of it: a discount
// factor of a long term at a high rate rounds to zero.
func discounted(price, rate decimal.Decimal, years int64, c curve) decimal.Decimal {
	if years <= 0 {
		return price
	}
	factor := c.factor(rate, years)
	return price.DivRound(factor, 18)
}

func drift(out, in decimal.Decimal) decimal.Decimal {
	if !out.IsPositive() || !in.IsPositive() {
		return decimal.Zero
	}
	return out.Sub(in).Abs().Div(decimal.Max(out, in))
}

type tally struct{ done, failed int }

func (t tally) total() int { return t.done + t.failed }

func (t tally) rate() decimal.Decimal {
	if t.total() == 0 {
		return decimal.Zero
	}
	return decimal.NewFromInt(int64(t.done)).Div(decimal.NewFromInt(int64(t.total())))
}
`,
	})
	violations, err := NewDecimalDivUnguardedRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []int{18, 48, 68}, violationLines(violations))
}

// Divisors that cannot be zero by construction are not reported; a sum
// built in a loop and decimal.Zero are.
func TestDecimalDivUnguardedNonZeroDivisors(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"rates/rates.go": `package rates

import "github.com/shopspring/decimal"

type Calculator struct {
	hundred decimal.Decimal
	base    decimal.Decimal
}

func NewCalculator(base decimal.Decimal) *Calculator {
	return &Calculator{hundred: decimal.NewFromInt(100), base: base}
}

func (c *Calculator) Percent(v decimal.Decimal) decimal.Decimal { return v.Div(c.hundred) }

func (c *Calculator) Relative(v decimal.Decimal) decimal.Decimal { return v.Div(c.base) }

func pow10(n int32) decimal.Decimal { return decimal.New(1, n) }

func tokens(raw decimal.Decimal, decimals int32) decimal.Decimal {
	tenThousand := decimal.NewFromInt(10000)
	return raw.Div(pow10(decimals)).Div(tenThousand)
}

func daily(total decimal.Decimal, days int) decimal.Decimal {
	return total.Div(decimal.NewFromInt(int64(max(days, 1))))
}

func floorDiv(a, b decimal.Decimal) decimal.Decimal {
	q, _ := a.QuoRem(b, 18)
	return q
}

func average(values []decimal.Decimal, part decimal.Decimal) decimal.Decimal {
	sum := decimal.Zero
	for _, v := range values {
		sum = sum.Add(v)
	}
	return part.Div(sum)
}

func zero(part decimal.Decimal) decimal.Decimal { return part.Div(decimal.Zero) }

type Snapshot struct{ Value decimal.Decimal }

func drop(baseline *Snapshot, now decimal.Decimal) decimal.Decimal {
	if baseline == nil || !baseline.Value.IsPositive() {
		return decimal.Zero
	}
	before := baseline.Value
	return before.Sub(now).Div(before)
}

func units(raw int64, native bool, decimals int32) decimal.Decimal {
	divisor := decimal.NewFromInt(1000000)
	if !native {
		divisor = pow10(decimals)
	}
	return decimal.NewFromInt(raw).Div(divisor)
}

func even(parts []string) map[string]decimal.Decimal {
	weights := make(map[string]decimal.Decimal, len(parts))
	for _, p := range parts {
		weights[p] = decimal.NewFromInt(1).Div(decimal.NewFromInt(int64(len(parts))))
	}
	return weights
}
`,
	})
	violations, err := NewDecimalDivUnguardedRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []int{16, 39, 42}, violationLines(violations))
}

// A divisor returned by a parser that rejects zero is not zero: the function
// returns the value only after checking it, every other return carries an
// error, and a wrapper hands its result on. The divisor of a parser without
// that check is reported.
func TestDecimalDivUnguardedCheckedByCallee(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"rates/parse.go": `package rates

import (
	"errors"
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
)

func parseRate(value string) (decimal.Decimal, error) {
	rate, err := decimal.NewFromString(value)
	if err != nil {
		return decimal.Decimal{}, err
	}
	if !rate.IsPositive() {
		return decimal.Decimal{}, errors.New("rate must be positive")
	}
	return rate, nil
}

func parseQuoted(value string) (decimal.Decimal, error) {
	rate, err := parseRate(strings.TrimSpace(value))
	if err != nil {
		return decimal.Decimal{}, fmt.Errorf("parse quoted: %w", err)
	}
	return rate, nil
}

func parseLoose(value string) (decimal.Decimal, error) {
	return decimal.NewFromString(value)
}

func Cross(base, target string) (decimal.Decimal, error) {
	baseRate, err := parseQuoted(base)
	if err != nil {
		return decimal.Decimal{}, err
	}
	targetRate, err := parseQuoted(target)
	if err != nil {
		return decimal.Decimal{}, err
	}
	return targetRate.Div(baseRate), nil
}

func LooseCross(base, target string) (decimal.Decimal, error) {
	baseRate, err := parseLoose(base)
	if err != nil {
		return decimal.Decimal{}, err
	}
	targetRate, err := parseLoose(target)
	if err != nil {
		return decimal.Decimal{}, err
	}
	return targetRate.Div(baseRate), nil
}
`,
	})
	violations, err := NewDecimalDivUnguardedRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []int{55}, violationLines(violations))
}

func TestMoneyIntegerDivisionTruncates(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"chain/amounts.go": `package chain

import (
	"math/big"

	"github.com/shopspring/decimal"
)

func ether(valueWei *big.Int) decimal.Decimal {
	divisor := big.NewInt(1000000000000000000)
	whole := new(big.Int).Div(valueWei, divisor)
	return decimal.NewFromBigInt(whole, 0)
}

func tokens(raw *big.Int, decimals int64) decimal.Decimal {
	unit := new(big.Int).Exp(big.NewInt(10), big.NewInt(decimals), nil)
	return decimal.NewFromInt(new(big.Int).Quo(raw, unit).Int64())
}

func exact(valueWei *big.Int) decimal.Decimal {
	return decimal.NewFromBigInt(valueWei, -18)
}

func rescale(amount *big.Int) *big.Int {
	return new(big.Int).Div(amount, big.NewInt(1000000000000))
}

func shares(total, count *big.Int) decimal.Decimal {
	return decimal.NewFromBigInt(new(big.Int).Div(total, count), 0)
}
`,
	})
	violations, err := NewMoneyIntegerDivisionTruncatesRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []int{11, 17}, violationLines(violations))
}

// A package that does not type-check is read from its syntax.
func TestMoneyIntegerDivisionTruncatesUntyped(t *testing.T) {
	file := rulestest.GoFile(t, "chain/amounts.go", `package chain

import (
	"math/big"

	"github.com/shopspring/decimal"
)

func ether(valueWei *big.Int) decimal.Decimal {
	divisor := big.NewInt(1000000000000000000)
	whole := new(big.Int).Div(valueWei, divisor)
	return decimal.NewFromBigInt(whole, undefinedExp)
}

func rescale(amount *big.Int) *big.Int {
	return new(big.Int).Div(amount, big.NewInt(1000000))
}

func shares(total, count *big.Int) decimal.Decimal {
	return decimal.NewFromBigInt(new(big.Int).Div(total, count), 0)
}
`)
	assert.Equal(t, []int{11}, violationLines(NewMoneyIntegerDivisionTruncatesRule().AnalyzeFile(file)))
}

// A divisor read from a struct the function stores only after checking the
// value it holds: every price in the map passed IsPositive before it went in,
// so the previous price a later row divides by is not zero. A field also set
// from an unchecked value elsewhere stays reported.
func TestDecimalDivUnguardedFieldStoredAfterCheck(t *testing.T) {
	project := decimalProject(t, map[string]string{
		"moves/moves.go": `package moves

import "github.com/shopspring/decimal"

type last struct{ price decimal.Decimal }

type row struct {
	key   string
	price decimal.Decimal
}

func Moves(rows []row) []decimal.Decimal {
	seen := map[string]last{}
	var moves []decimal.Decimal
	for _, r := range rows {
		price := r.price
		if !price.IsPositive() {
			continue
		}
		if prev, ok := seen[r.key]; ok {
			moves = append(moves, price.Div(prev.price))
		}
		seen[r.key] = last{price: price}
	}
	return moves
}

type mark struct{ value decimal.Decimal }

func Ratios(rows []row) []decimal.Decimal {
	seen := map[string]mark{}
	var out []decimal.Decimal
	for _, r := range rows {
		if prev, ok := seen[r.key]; ok {
			out = append(out, r.price.Div(prev.value))
		}
		seen[r.key] = mark{value: r.price}
	}
	return out
}
`,
	})
	violations, err := NewDecimalDivUnguardedRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []int{35}, violationLines(violations))
}
