package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFinancialConstantsRule(t *testing.T) {
	rule := NewFinancialConstantsRule()

	tests := []struct {
		name     string
		code     string
		expected int // number of violations
	}{
		{
			name: "detects hardcoded fee in financial function",
			code: `package main

import "github.com/shopspring/decimal"

func getWithdrawalServiceFee(network string) decimal.Decimal {
	switch network {
	case "tron":
		return decimal.NewFromInt(10)
	default:
		return decimal.NewFromInt(5)
	}
}`,
			expected: 2,
		},
		{
			name: "detects hardcoded commission",
			code: `package main

import "github.com/shopspring/decimal"

func calculateCommission() decimal.Decimal {
	return decimal.NewFromFloat(2.5)
}`,
			expected: 1,
		},
		{
			name: "allows zero but flags one in financial context",
			code: `package main

import "github.com/shopspring/decimal"

func getWithdrawalFee() decimal.Decimal {
	return decimal.NewFromInt(0) // OK - zero is always allowed
}

func getDefaultFee() decimal.Decimal {
	return decimal.NewFromInt(1) // Should be flagged - $1 fee in financial context
}`,
			expected: 1, // 1 in financial context should be flagged
		},
		{
			name: "allows scaling factors",
			code: `package main

import "github.com/shopspring/decimal"

func scaleValue(v decimal.Decimal) decimal.Decimal {
	return v.Mul(decimal.NewFromInt(100))
}`,
			expected: 0,
		},
		{
			name: "detects fee-like values even outside financial functions",
			code: `package main

import "github.com/shopspring/decimal"

func processPayment() decimal.Decimal {
	fee := decimal.NewFromInt(5)
	return fee
}`,
			expected: 1,
		},
		{
			name: "allows large non-fee values outside financial context",
			code: `package main

import "github.com/shopspring/decimal"

func getMaxItems() decimal.Decimal {
	return decimal.NewFromInt(5000)
}`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/test.go", "/src", []byte(tt.code), core.DefaultConfig())

			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/src/test.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.expected, "Test: %s", tt.name)
		})
	}
}

func TestFinancialConstantsRule_SkipsConfigFiles(t *testing.T) {
	rule := NewFinancialConstantsRule()

	code := `package config

import "github.com/shopspring/decimal"

var TronFee = decimal.NewFromInt(10)
`

	// Test various config file paths
	configPaths := []string{
		"/src/config/fees.go",
		"/src/backend/config/unified_config.go",
		"/src/pkg/constants/financial.go",
	}

	for _, path := range configPaths {
		t.Run(path, func(t *testing.T) {
			ctx := core.NewFileContext(path, "/src", []byte(code), core.DefaultConfig())

			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile(path, []byte(code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}

			violations := rule.AnalyzeFile(ctx)

			assert.Empty(t, violations, "Config file %s should have no violations", path)
		})
	}
}

func TestFinancialConstantsRule_SkipsTestFiles(t *testing.T) {
	rule := NewFinancialConstantsRule()

	code := `package main

import "github.com/shopspring/decimal"

func TestWithdrawalFee(t *testing.T) {
	expected := decimal.NewFromInt(10)
	_ = expected
}
`
	path := "/src/services/fee_test.go"
	ctx := core.NewFileContext(path, "/src", []byte(code), core.DefaultConfig())

	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	if err == nil {
		ctx.SetGoAST(fset, astFile)
	}

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test file should have no violations")
}
