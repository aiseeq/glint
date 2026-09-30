package patterns

import (
	"go/ast"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestFinancialConstantsReportsInvalidNumericLiteral(t *testing.T) {
	rule := NewFinancialConstantsRule()
	ctx := core.NewFileContext("/src/fees.go", "/src", nil, core.DefaultConfig())
	call := &ast.CallExpr{
		Fun:  &ast.SelectorExpr{X: ast.NewIdent("decimal"), Sel: ast.NewIdent("NewFromInt")},
		Args: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "invalid"}},
	}

	assert.NotNil(t, rule.checkDecimalCall(ctx, call, "NewFromInt", map[string]bool{"decimal": true}))
}

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
			name: "package-level var after financial function is not financial context",
			code: `package main

import "github.com/shopspring/decimal"

func getWithdrawalFee() decimal.Decimal {
	return decimal.NewFromInt(0)
}

var scaleFactor = decimal.NewFromInt(100)`,
			expected: 0,
		},
		{
			// Function names are read word by word: "feedback" is not a fee,
			// and "latest" is not a test.
			name: "a fee fragment inside another word is not a fee",
			code: `package main

import "github.com/shopspring/decimal"

func feedbackWeight() decimal.Decimal {
	return decimal.NewFromInt(100)
}`,
			expected: 0,
		},
		{
			name: "a test fragment inside another word is not a test",
			code: `package main

import "github.com/shopspring/decimal"

func latestWithdrawalFee() decimal.Decimal {
	return decimal.NewFromInt(1)
}`,
			expected: 1,
		},
		{
			name: "aliased decimal import",
			code: `package main

import dec "github.com/shopspring/decimal"

func withdrawalFee() dec.Decimal {
	return dec.NewFromFloat(2.5)
}`,
			expected: 1,
		},
		{
			name: "string constructors carry the constant too",
			code: `package main

import "github.com/shopspring/decimal"

func withdrawalFee() decimal.Decimal {
	return decimal.RequireFromString("2.5")
}

func transferFee() (decimal.Decimal, error) {
	return decimal.NewFromString("1.25")
}

func depositLimitFee() decimal.Decimal {
	return decimal.RequireFromString("0")
}`,
			expected: 2,
		},
		{
			name: "a local value named like the package is not the package",
			code: `package main

import money "github.com/shopspring/decimal"

type builder struct{}

func (builder) NewFromInt(v int64) money.Decimal { return money.Zero }

func withdrawalFee(decimal builder) money.Decimal {
	return decimal.NewFromInt(7)
}`,
			expected: 0,
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

// A strategy card that writes the minimum investment itself: the backend
// raised it, the page kept offering 10.
func TestFinancialConstantsTypeScript(t *testing.T) {
	lines := func(path, source string) []int {
		return violationLines(NewFinancialConstantsRule().AnalyzeFile(rulestest.TextFile(t, path, source)))
	}
	assert.Equal(t, []int{2, 3}, lines("web/src/app/invest/page.tsx", `const strategies = useMemo(() => [
  { id: 'starter', minAmount: 10, title: 'Starter' },
  { id: 'premium', minInvestment: 100, feePercent: 1.5 },
], [])
`))
	assert.Empty(t, lines("web/src/app/invest/page.tsx", `const form = { minAmount: 0, maxAmount: limits.max }
const style = { minWidth: 10 }
`), "zero, a value read from data, a layout property")
	assert.Empty(t, lines("web/src/app/invest/page.test.tsx", `const s = { minAmount: 10 }
`), "test code")
	assert.Empty(t, lines("web/src/config/limits.ts", `export const LIMITS = { minAmount: 10 }
`), "configuration")
}
