package moneyrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestNegativeMoneyClampedToZero(t *testing.T) {
	const source = `package sample

import (
	"errors"

	"github.com/shopspring/decimal"
)

type loggerType struct{}
func (loggerType) Error(string, ...any) {}
func (loggerType) Warn(string, ...any) {}
func (loggerType) ErrorFields(string, ...any) {}
var logger loggerType

func calculate(total decimal.Decimal) (decimal.Decimal, decimal.Decimal) {
	report := logger.ErrorFields
	if total.LessThan(decimal.Zero) {
		report("negative amount clamped")
		total = decimal.Zero
	}
	return total, decimal.Zero
}

func reject(total decimal.Decimal) (decimal.Decimal, error) {
	if total.LessThan(decimal.Zero) { return decimal.Zero, errors.New("negative") }
	return total, nil
}

func preserve(total decimal.Decimal) decimal.Decimal {
	if total.LessThan(decimal.Zero) { logger.Warn("negative amount") }
	return total
}

func unrelated(count int) int {
	if count < 0 { count = 0 }
	return count
}
`
	ctx := patterntest.DecimalProject(t, map[string]string{"sample/calculate.go": source})
	violations, err := NewNegativeMoneyClampedToZeroRule().AnalyzeGoProject(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{17}, rulestest.ViolationLines(violations))
}
