package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
)

func TestFinancialDecimalFloatRule_MetadataAndRegistration(t *testing.T) {
	rule := NewFinancialDecimalFloatRule()
	assert.Equal(t, "financial-decimal-float", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())

	registered, ok := rules.Get("financial-decimal-float")
	assert.True(t, ok)
	assert.Equal(t, rule.Name(), registered.Name())
}

func TestFinancialDecimalFloatRule_Detection(t *testing.T) {
	tests := []struct {
		name string
		path string
		code string
		want int
	}{
		{
			name: "ignored exact bool on financial target",
			path: "quote.go",
			code: `package quote
import "github.com/shopspring/decimal"
func convert(value decimal.Decimal) float64 {
	price, _ := value.Float64()
	return price
}`,
			want: 1,
		},
		{
			name: "alias import and financial receiver with indexed target",
			path: "quote.go",
			code: `package quote
import money "github.com/shopspring/decimal"
func convert(rate money.Decimal, result map[string]float64, currency string) {
	result[currency], _ = rate.Float64()
}`,
			want: 1,
		},
		{
			name: "captured exact bool",
			path: "quote.go",
			code: `package quote
import "github.com/shopspring/decimal"
func convert(amount decimal.Decimal) float64 {
	value, exact := amount.Float64()
	if !exact { panic("inexact") }
	return value
}`,
			want: 0,
		},
		{
			name: "json number error handling",
			path: "quote.go",
			code: `package quote
import (
	"encoding/json"
	"github.com/shopspring/decimal"
)
var _ = decimal.Zero
func convert(number json.Number) (float64, error) {
	amount, err := number.Float64()
	if err != nil { return 0, err }
	return amount, nil
}`,
			want: 0,
		},
		{
			name: "ignored json number error is not decimal exactness",
			path: "quote.go",
			code: `package quote
import (
	jsonvalue "encoding/json"
	"github.com/shopspring/decimal"
)
var _ = decimal.Zero
func convert(number jsonvalue.Number) float64 {
	amount, _ := number.Float64()
	return amount
}`,
			want: 0,
		},
		{
			name: "receiver types stay function scoped",
			path: "quote.go",
			code: `package quote
import (
	"encoding/json"
	"github.com/shopspring/decimal"
)
func parse(rate json.Number) float64 {
	amount, _ := rate.Float64()
	return amount
}
func convert(rate decimal.Decimal, result map[string]float64, currency string) {
	result[currency], _ = rate.Float64()
}`,
			want: 1,
		},
		{
			name: "nonfinancial coordinate",
			path: "geo.go",
			code: `package geo
import "github.com/shopspring/decimal"
func convert(latitude decimal.Decimal) float64 {
	coordinate, _ := latitude.Float64()
	return coordinate
}`,
			want: 0,
		},
		{
			name: "shopspring import required",
			path: "quote.go",
			code: `package quote
func convert(rate customDecimal) float64 {
	price, _ := rate.Float64()
	return price
}`,
			want: 0,
		},
		{
			name: "custom financial receiver in file importing shopspring",
			path: "quote.go",
			code: `package quote
import "github.com/shopspring/decimal"
type Rate struct{}
func (Rate) Float64() (float64, bool) { return 0, true }
var _ = decimal.Zero
func convert(rate Rate) float64 {
	price, _ := rate.Float64()
	return price
}`,
			want: 0,
		},
		{
			name: "selector json number receiver",
			path: "quote.go",
			code: `package quote
import (
	"encoding/json"
	"github.com/shopspring/decimal"
)
type Payload struct { Rate json.Number }
var _ = decimal.Zero
func convert(payload Payload) float64 {
	amount, _ := payload.Rate.Float64()
	return amount
}`,
			want: 0,
		},
		{
			name: "decimal selector field",
			path: "quote.go",
			code: `package quote
import money "github.com/shopspring/decimal"
type Payload struct { Amount money.Decimal }
func convert(payload Payload) float64 {
	amount, _ := payload.Amount.Float64()
	return amount
}`,
			want: 1,
		},
		{
			name: "conflicting selector field declarations",
			path: "quote.go",
			code: `package quote
import (
	"encoding/json"
	money "github.com/shopspring/decimal"
)
type DecimalPayload struct { Amount money.Decimal }
type JSONPayload struct { Amount json.Number }
func convert(payload DecimalPayload) float64 {
	amount, _ := payload.Amount.Float64()
	return amount
}`,
			want: 0,
		},
		{
			name: "unrelated same-file decimal field is insufficient",
			path: "quote.go",
			code: `package quote
import money "github.com/shopspring/decimal"
type Invoice struct { Amount money.Decimal }
func convert(payload ExternalPayload) float64 {
	amount, _ := payload.Amount.Float64()
	return amount
}`,
			want: 0,
		},
		{
			name: "range values from decimal slice and map",
			path: "quote.go",
			code: `package quote
import money "github.com/shopspring/decimal"
func convert(rates []money.Decimal, byCurrency map[string]money.Decimal) {
	for _, rate := range rates {
		value, _ := rate.Float64()
		_ = value
	}
	for _, amount := range byCurrency {
		value, _ := amount.Float64()
		_ = value
	}
}`,
			want: 2,
		},
		{
			name: "range value shadowing stays scoped",
			path: "quote.go",
			code: `package quote
import (
	"encoding/json"
	"github.com/shopspring/decimal"
)
func convert(rates []decimal.Decimal, numbers []json.Number) {
	for _, amount := range rates {
		value, _ := amount.Float64()
		_ = value
	}
	for _, amount := range numbers {
		value, _ := amount.Float64()
		_ = value
	}
}`,
			want: 1,
		},
		{
			name: "test files skipped",
			path: "quote_test.go",
			code: `package quote
import "github.com/shopspring/decimal"
func convert(rate decimal.Decimal) float64 {
	price, _ := rate.Float64()
	return price
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createQueryContext(t, tt.path, tt.code)
			assert.Len(t, NewFinancialDecimalFloatRule().AnalyzeFile(ctx), tt.want)
		})
	}
}
