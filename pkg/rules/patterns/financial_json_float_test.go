package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
)

func TestFinancialJSONFloatRule_Metadata(t *testing.T) {
	rule := NewFinancialJSONFloatRule()
	assert.Equal(t, "financial-json-float", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestFinancialJSONFloatRule_Detection(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "direct monetary fields and map values",
			code: `package api
type Response struct {
	TotalUSDValue float64 ` + "`json:\"total_usd_value\"`" + `
	Prices map[string]float64 ` + "`json:\"prices\"`" + `
	Revenue float64 ` + "`json:\"revenue\"`" + `
}`,
			want: 3,
		},
		{
			name: "market fields in financial type contexts",
			code: `package api
type QuoteResponse struct {
	Mid float64 ` + "`json:\"mid\"`" + `
	Rate float64 ` + "`json:\"rate\"`" + `
	Rates map[string]float64 ` + "`json:\"rates\"`" + `
	FX float64 ` + "`json:\"fx\"`" + `
	ExchangeRate float64 ` + "`json:\"exchange_rate\"`" + `
	FXRate float64 ` + "`json:\"fx_rate\"`" + `
}
type ExchangeRateResponse struct {
	Rate float64 ` + "`json:\"rate\"`" + `
}
type websiteManifestRates struct {
	Mid float64 ` + "`json:\"mid\"`" + `
}`,
			want: 8,
		},
		{
			name: "standalone market fields are not financial in metrics context",
			code: `package api
type MetricsResponse struct {
	Rate float64 ` + "`json:\"rate\"`" + `
	Mid float64 ` + "`json:\"mid\"`" + `
	FX float64 ` + "`json:\"fx\"`" + `
	SuccessRate float64 ` + "`json:\"successRate\"`" + `
	BitRate float64 ` + "`json:\"bitRate\"`" + `
	RefreshRate float64 ` + "`json:\"refreshRate\"`" + `
}`,
			want: 0,
		},
		{
			name: "nested structs and float aliases in containers",
			code: `package api
type Scalar float64
type SliceLevel struct {
	Rate Scalar ` + "`json:\"rate\"`" + `
}
type MapLevel struct {
	Mid Scalar ` + "`json:\"mid\"`" + `
}
type QuoteResponse struct {
	Levels []SliceLevel ` + "`json:\"levels\"`" + `
	Points map[string]MapLevel ` + "`json:\"points\"`" + `
	Rates []Scalar ` + "`json:\"rates\"`" + `
}`,
			want: 3,
		},
		{
			name: "financial parent catches approximate float",
			code: `package api
type Quantity struct {
	Numeric string ` + "`json:\"numeric\"`" + `
	Float float64 ` + "`json:\"float\"`" + `
}
type Response struct {
	Fee Quantity ` + "`json:\"fee\"`" + `
}`,
			want: 1,
		},
		{
			name: "named float aliases and default JSON fields",
			code: `package api
type Money float64
type TransferResponse struct {
	Value Money
}`,
			want: 1,
		},
		{
			name: "non-financial JSON floats are allowed",
			code: `package api
type Metrics struct {
	LatencySeconds float64 ` + "`json:\"latency_seconds\"`" + `
	Confidence float64 ` + "`json:\"confidence\"`" + `
	Latitude float64 ` + "`json:\"latitude\"`" + `
	Value float64 ` + "`json:\"value\"`" + `
	TotalGB float64 ` + "`json:\"totalGb\"`" + `
}
type Position struct { Latitude float64 }
type PriceData struct {
	Confidence float64 ` + "`json:\"confidence\"`" + `
}`,
			want: 0,
		},
		{
			// A decimal wrapper decoding JSON numbers through float64: a
			// long amount loses its last digits before it becomes a decimal.
			name: "decimal UnmarshalJSON through float64",
			code: `package money
import (
	"encoding/json"
	"github.com/shopspring/decimal"
)
type Amount struct{ decimal.Decimal }
func (a *Amount) UnmarshalJSON(data []byte) error {
	var f float64
	if err := json.Unmarshal(data, &f); err == nil {
		a.Decimal = decimal.NewFromFloat(f)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d, err := decimal.NewFromString(s)
	a.Decimal = d
	return err
}`,
			want: 1,
		},
		{
			name: "decimal UnmarshalJSON through json.Number or a string is allowed",
			code: `package money
import (
	"encoding/json"
	"github.com/shopspring/decimal"
)
type Amount struct{ decimal.Decimal }
func (a *Amount) UnmarshalJSON(data []byte) error {
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	d, err := decimal.NewFromString(n.String())
	a.Decimal = d
	return err
}
type Point struct{ X float64 }
func (p *Point) UnmarshalJSON(data []byte) error {
	var f float64
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	p.X = f
	return nil
}`,
			want: 0,
		},
		{
			name: "financial decimal and integer are allowed",
			code: `package api
type Response struct {
	Price decimal.Decimal ` + "`json:\"price\"`" + `
	Fee int64 ` + "`json:\"fee\"`" + `
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createQueryContext(t, "client.go", tt.code)
			assert.Len(t, NewFinancialJSONFloatRule().AnalyzeFile(ctx), tt.want)
		})
	}
}

func TestFinancialJSONFloatRule_SkipsTests(t *testing.T) {
	ctx := createQueryContext(t, "client_test.go", `package api
type fixture struct { Price float64 `+"`json:\"price\"`"+` }`)
	assert.Empty(t, NewFinancialJSONFloatRule().AnalyzeFile(ctx))
}
