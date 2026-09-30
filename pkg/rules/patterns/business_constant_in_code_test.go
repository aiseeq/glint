package patterns

import (
	"go/constant"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func runBusinessConstantRule(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	project := decimalProject(t, files)
	violations, err := NewBusinessConstantInCodeRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	return violations
}

func TestBusinessConstantInCode_CalendarArithmetic(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"credit/credit.go": `package credit

import "time"

// HoldDays is how many days a new deposit earns nothing.
const HoldDays = 4

// MaturedDays is how long a released deposit stays in the feed.
const MaturedDays = 7

func AccrualFrom(day time.Time) time.Time {
	return day.AddDate(0, 0, HoldDays)
}
`,
		"api/router.go": `package api

import (
	"time"

	"example.com/rulestest/credit"
)

func MaturedSince(now time.Time) time.Time {
	return now.AddDate(0, 0, -credit.MaturedDays)
}
`,
	})

	require.Len(t, violations, 2)
	assert.Contains(t, violations[0].Message, "HoldDays = 4")
	assert.Contains(t, violations[0].Message, "calendar arithmetic")
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[1].Message, "MaturedDays = 7", "a use in another package counts")
	assert.Contains(t, violations[1].Message, "router.go")
}

func TestBusinessConstantInCode_MoneyAmount(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"check/check.go": `package check

import "github.com/shopspring/decimal"

const minToleranceUSD = 50

const percentBase = 100

const basisPoints = 0.0001

const daysInYear = 365

const driftShare = 0.005

func Tolerance() decimal.Decimal {
	return decimal.NewFromInt(minToleranceUSD)
}

func Drift(d decimal.Decimal) decimal.Decimal {
	return d.Mul(decimal.NewFromFloat(driftShare))
}

func Percent(d decimal.Decimal) (decimal.Decimal, decimal.Decimal) {
	_ = decimal.NewFromInt(daysInYear)
	return decimal.NewFromInt(percentBase), decimal.NewFromFloat(basisPoints)
}
`,
	})

	require.Len(t, violations, 2, "powers of ten and calendar units convert units and are not reported")
	assert.Contains(t, violations[0].Message, "minToleranceUSD = 50")
	assert.Contains(t, violations[0].Message, "decimal amount")
	assert.Contains(t, violations[1].Message, "driftShare = 0.005", "a fraction reads as a decimal, not as 1/200")
}

// A technical constant never takes a business use: a TTL added to a time, a
// page size, a retry count.
func TestBusinessConstantInCode_TechnicalConstantsAreSilent(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"cache/cache.go": `package cache

import "time"

const ttl = 5 * time.Minute

const pageSize = 50

const zeroDays = 0

func Expiry(now time.Time) time.Time {
	local := 3
	_ = now.AddDate(0, 0, zeroDays)
	_ = now.AddDate(0, 0, local)
	_ = now.AddDate(0, 0, 1)
	return now.Add(ttl)
}

func Page() int { return pageSize }
`,
	})

	assert.Empty(t, violations)
}

// A constant that is the default of a setting read from the environment or a
// command-line flag is already configurable: an operator changes it without a
// release. Seeding the same default elsewhere does not make it hardcoded.
func TestBusinessConstantInCode_DefaultOfConfigurableSettingIsSilent(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"monitor/monitor.go": `package monitor

import (
	"flag"
	"os"
	"time"

	"github.com/shopspring/decimal"
)

const defaultReserveUSD = 250_000

const defaultLimitUSD = 700

const defaultWindowDays = 5

const hardcodedUSD = 500

func New() decimal.Decimal { return decimal.NewFromInt(defaultReserveUSD) }

func envDecimal(name string, def int64) (decimal.Decimal, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return decimal.NewFromInt(def), nil
	}
	return decimal.NewFromString(raw)
}

func Load() (decimal.Decimal, error) {
	return envDecimal("PROJECTA_RESERVE_USD", defaultReserveUSD)
}

var limit = flag.Int64("limit-usd", defaultLimitUSD, "limit")

var window = flag.Int("window-days", int(defaultWindowDays), "window")

func Limit() decimal.Decimal { return decimal.NewFromInt(defaultLimitUSD) }

func Since(now time.Time) time.Time { return now.AddDate(0, 0, -defaultWindowDays) }

func Hard() decimal.Decimal { return decimal.NewFromInt(hardcodedUSD) }
`,
	})

	require.Len(t, violations, 1, "only the constant no setting overrides is reported")
	assert.Contains(t, violations[0].Message, "hardcodedUSD = 500")
}

// A constant passed to a function that does not read the environment is not
// a setting's default: the value stays hardcoded.
func TestBusinessConstantInCode_OrdinaryHelperArgumentStillReported(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"fee/fee.go": `package fee

import "github.com/shopspring/decimal"

const minFeeUSD = 3

func atLeast(name string, floor int64) decimal.Decimal {
	_ = name
	return decimal.NewFromInt(floor)
}

func Fee() decimal.Decimal {
	_ = atLeast("fee", minFeeUSD)
	return decimal.NewFromInt(minFeeUSD)
}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "minFeeUSD = 3")
}

func TestIsPowerOfTen(t *testing.T) {
	tests := map[string]bool{"1": true, "100": true, "0.01": true, "1000": true, "50": false, "0.5": false, "110": false, "0.0003": false}
	for literal, expected := range tests {
		kind := token.INT
		if strings.Contains(literal, ".") {
			kind = token.FLOAT
		}
		assert.Equal(t, expected, isPowerOfTen(constant.MakeFromLiteral(literal, kind, 0)), literal)
	}
}
