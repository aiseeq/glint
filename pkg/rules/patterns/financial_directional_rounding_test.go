package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
)

func TestFinancialDirectionalRoundingRule_MetadataAndRegistration(t *testing.T) {
	rule := NewFinancialDirectionalRoundingRule()
	assert.Equal(t, "financial-directional-rounding", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())

	registered, ok := rules.Get("financial-directional-rounding")
	assert.True(t, ok)
	assert.Equal(t, rule.Name(), registered.Name())
}

func TestFinancialDirectionalRoundingRule_Detection(t *testing.T) {
	tests := []struct {
		name string
		path string
		code string
		want int
	}{
		{
			// The repro: a presentation helper rounding money up on its own, so
			// every screen showed a cent the stored payment never had.
			name: "ceiling on a money value in a formatter",
			path: "format.go",
			code: `package ui
import "github.com/shopspring/decimal"
func formatAmount(amount decimal.Decimal) string {
	return amount.RoundCeil(2).StringFixed(2)
}`,
			want: 1,
		},
		{
			name: "rounding down a derived money expression",
			path: "split.go",
			code: `package payout
import "github.com/shopspring/decimal"
func share(total decimal.Decimal, parts int64) decimal.Decimal {
	return total.Div(decimal.NewFromInt(parts)).RoundDown(2)
}`,
			want: 1,
		},
		{
			name: "truncating a payout",
			path: "payout.go",
			code: `package payout
import "github.com/shopspring/decimal"
func trim(payoutAmount decimal.Decimal) decimal.Decimal {
	return payoutAmount.Truncate(2)
}`,
			want: 1,
		},
		{
			name: "symmetric rounding is the expected way",
			path: "quote.go",
			code: `package quote
import "github.com/shopspring/decimal"
func total(amount decimal.Decimal) decimal.Decimal {
	return amount.Round(2)
}`,
			want: 0,
		},
		{
			name: "truncating a duration is not money",
			path: "schedule.go",
			code: `package schedule
import (
	"time"

	"github.com/shopspring/decimal"
)
var _ = decimal.Zero
func day(paymentDeadline time.Time) time.Time {
	return paymentDeadline.Truncate(24 * time.Hour)
}`,
			want: 0,
		},
		{
			// The receiver reads as money by name, but the call is time's own
			// Truncate reached through a method chain, not decimal's.
			name: "truncating a timestamp to the day",
			path: "report.go",
			code: `package report
import (
	"time"

	"github.com/shopspring/decimal"
)
var _ = decimal.Zero
type balance struct{ LastUpdate time.Time }
func day(accountBalance balance) time.Time {
	return accountBalance.LastUpdate.UTC().Truncate(24 * time.Hour)
}`,
			want: 0,
		},
		{
			// Money divided by money is a ratio, not money: rounding the number
			// of parts up is how the split covers the whole amount.
			name: "ratio of two money values",
			path: "limit.go",
			code: `package limit
import "github.com/shopspring/decimal"
func parts(payoutAmount, maxPayoutAmount decimal.Decimal) int64 {
	return payoutAmount.Div(maxPayoutAmount).Ceil().IntPart()
}`,
			want: 0,
		},
		{
			name: "non-monetary value keeps its directional rounding",
			path: "observe.go",
			code: `package observe
import "github.com/shopspring/decimal"
func fits(value decimal.Decimal, scale int32) bool {
	return value.Equal(value.Truncate(scale))
}`,
			want: 0,
		},
		{
			name: "file without the decimal package",
			path: "report.go",
			code: `package report
type money struct{ amount float64 }
func (m money) rounded() float64 {
	return m.amount
}`,
			want: 0,
		},
	}

	rule := NewFinancialDirectionalRoundingRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createQueryContext(t, tt.path, tt.code)
			assert.Len(t, rule.AnalyzeFile(ctx), tt.want)
		})
	}
}

func TestFinancialDirectionalRoundingRule_SkipsTestFiles(t *testing.T) {
	rule := NewFinancialDirectionalRoundingRule()
	ctx := createQueryContext(t, "format_test.go", `package ui
import "github.com/shopspring/decimal"
func formatAmount(amount decimal.Decimal) string {
	return amount.RoundCeil(2).StringFixed(2)
}`)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}
