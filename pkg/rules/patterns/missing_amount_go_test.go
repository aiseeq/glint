package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A decimal parser that answers an empty or unreadable string with zero,
// applied to the money fields of a decoded payload: an absent payout goes on
// as a payout of 0. A parser that refuses, and one applied to a counter, are
// left alone.
func TestMissingAmountCoercedToZero_GoParserOnMoneyFields(t *testing.T) {
	const source = `package hook

func parseDecimalOptional(s string) (decimal.Decimal, error) {
	if s == "" {
		return decimal.Zero, nil
	}
	return decimal.NewFromString(s)
}

func parseDecimalOrZero(s string) decimal.Decimal {
	d, err := decimal.NewFromString(s)
	if err != nil {
		return decimal.Zero
	}
	return d
}

func parseStrict(s string) (decimal.Decimal, error) {
	if s == "" {
		return decimal.Zero, errors.New("empty")
	}
	return decimal.NewFromString(s)
}

func apply(payload Payload) error {
	payout, err := parseDecimalOptional(payload.PayoutAmount)
	if err != nil {
		return err
	}
	fees := parseDecimalOrZero(payload.Fees)
	strict, err := parseStrict(payload.FXRate)
	if err != nil {
		return err
	}
	retries := parseDecimalOrZero(payload.Retries)
	return save(payout, fees, strict, retries)
}
`
	violations := NewMissingAmountCoercedToZeroRule().AnalyzeFile(rulestest.GoFile(t, "hook/apply.go", source))
	assert.Equal(t, []int{26, 30}, violationLines(violations))
}

// A nullable amount replaced with zero before it goes out: the partner reads
// "0.00" for an amount nobody knows.
func TestMissingAmountCoercedToZero_GoNilAmountBecomesZero(t *testing.T) {
	const source = `package hook

func observe(desired Desired) ([]byte, error) {
	payout := decimal.Zero
	if desired.payoutAmount != nil {
		payout = *desired.payoutAmount
	}
	count := 0
	if desired.count != nil {
		count = *desired.count
	}
	return json.Marshal(Payload{Payout: payout.StringFixed(2), Count: count})
}
`
	violations := NewMissingAmountCoercedToZeroRule().AnalyzeFile(rulestest.GoFile(t, "hook/observe.go", source))
	assert.Equal(t, []int{4}, violationLines(violations))
}
