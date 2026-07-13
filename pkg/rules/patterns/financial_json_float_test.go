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
