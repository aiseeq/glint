package patterns

import (
	"go/constant"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// decimalStubModule makes github.com/shopspring/decimal resolvable in a test
// module without the network: a local replacement with the constructors the
// rules look at.
func decimalStubModule(files map[string]string) map[string]string {
	files["go.mod"] = "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/shopspring/decimal v0.0.0\n\nreplace github.com/shopspring/decimal => ./decimalstub\n"
	files["decimalstub/go.mod"] = "module github.com/shopspring/decimal\n\ngo 1.24\n"
	files["decimalstub/decimal.go"] = `package decimal

type Decimal struct{ v float64 }

func New(value int64, exp int32) Decimal  { return Decimal{} }
func NewFromInt(value int64) Decimal      { return Decimal{} }
func NewFromFloat(value float64) Decimal  { return Decimal{} }
func (d Decimal) IsZero() bool            { return d.v == 0 }
`
	return files
}

func runBusinessConstantRule(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	project := rulestest.Project(t, decimalStubModule(files))
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

func Tolerance() decimal.Decimal {
	return decimal.NewFromInt(minToleranceUSD)
}

func Percent(d decimal.Decimal) (decimal.Decimal, decimal.Decimal) {
	_ = decimal.NewFromInt(daysInYear)
	return decimal.NewFromInt(percentBase), decimal.NewFromFloat(basisPoints)
}
`,
	})

	require.Len(t, violations, 1, "powers of ten and calendar units convert units and are not reported")
	assert.Contains(t, violations[0].Message, "minToleranceUSD = 50")
	assert.Contains(t, violations[0].Message, "money amount")
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
