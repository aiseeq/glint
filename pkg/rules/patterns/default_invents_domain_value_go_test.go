package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A switch over an external type string whose default stores the unknown
// variant with a made-up direction: the record is kept, and an unparsed
// event passes for an outgoing transfer.
func TestDefaultInventsDomainValue_GoSwitchDefault(t *testing.T) {
	const source = `package parse

func convert(action Action) Tx {
	tx := Tx{}
	switch action.Type {
	case "Transfer":
		tx.Direction = model.DirectionIn
	case "Swap":
		tx.Direction = model.DirectionSwap
	default:
		tx.TxType = strings.ToLower(action.Type)
		tx.Direction = model.DirectionOut
	}
	return tx
}

func label(action Action) Tx {
	tx := Tx{}
	switch action.Type {
	case "Transfer":
		tx.Direction = model.DirectionIn
	default:
		tx.Direction = model.DirectionUnknown
	}
	return tx
}

func skip(action Action) (Tx, bool) {
	tx := Tx{}
	switch action.Type {
	case "Transfer":
		tx.Direction = model.DirectionIn
	default:
		return tx, false
	}
	return tx, true
}
`
	violations := NewDefaultInventsDomainValueRule().AnalyzeFile(rulestest.GoFile(t, "parse/convert.go", source))
	assert.Equal(t, []int{12}, violationLines(violations))
}

// A rate lookup miss or an amount parse failure answered with a made-up
// number: the quote or the transfer goes on with a value the data never had.
// A zero (another rule's case), an error return and a non-money variable are
// left alone.
func TestDefaultInventsDomainValue_GoLookupMissLiteral(t *testing.T) {
	const source = `package quote

func rateFor(pair string) decimal.Decimal {
	rates := map[string]decimal.Decimal{"AAA/BBB": decimal.NewFromFloat(7.25)}
	rate, ok := rates[pair]
	if !ok {
		rate = decimal.NewFromFloat(1.0) // fallback for unknown pairs
	}
	return rate
}

func zeroRate(pair string) decimal.Decimal {
	rates := map[string]decimal.Decimal{"AAA/BBB": decimal.NewFromFloat(7.25)}
	mockRate := rates[pair]
	if mockRate.IsZero() {
		mockRate = decimal.NewFromInt(1)
	}
	return mockRate
}

func amountOf(row Row) (decimal.Decimal, error) {
	amount, err := decimal.NewFromString(row.Fields["amount"])
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		amount = decimal.NewFromFloat(100) // fallback
	}
	return amount, nil
}

func strictAmount(row Row) (decimal.Decimal, error) {
	amount, err := decimal.NewFromString(row.Fields["amount"])
	if err != nil {
		return decimal.Zero, fmt.Errorf("amount: %w", err)
	}
	return amount, nil
}

func timeoutOf(cfg map[string]int) int {
	timeout, ok := cfg["timeout"]
	if !ok {
		timeout = 30
	}
	return timeout
}

func span(first, last time.Time) decimal.Decimal {
	totalHours := int64(last.Sub(first).Hours())
	if totalHours <= 0 {
		totalHours = 24
	}
	return decimal.NewFromInt(totalHours)
}

func zeroed(rates map[string]decimal.Decimal, pair string) decimal.Decimal {
	rate, ok := rates[pair]
	if !ok {
		rate = decimal.Zero
	}
	return rate
}
`
	violations := NewDefaultInventsDomainValueRule().AnalyzeFile(rulestest.GoFile(t, "quote/rate.go", source))
	assert.Equal(t, []int{7, 16, 24}, violationLines(violations))
}

// A first-non-empty helper in a request builder that ends in a literal, or
// that fills a person's field from the company's: the provider receives an
// identity the sender never gave. A placeholder word and a fallback between
// fields of one meaning are left alone.
func TestDefaultInventsDomainValue_GoCoalesceInventsIdentity(t *testing.T) {
	const source = `package provider

func buildRequest(tx *Tx) Request {
	firstName := firstNonEmpty(tx.SenderFirstName, tx.SenderCorporateName)
	country := firstNonEmpty(tx.SenderCountry, tx.SenderCorporateRegistrationCountry)
	mobile := firstNonEmpty(tx.SenderMobileNumber, tx.SenderPhone)
	state := firstNonEmpty(tx.SenderState, tx.SenderCity, "N/A")
	return Request{
		FirstName:   firstName,
		Country:     country,
		Mobile:      mobile,
		State:       state,
		IDExpire:    firstNonEmpty(tx.SenderIDExpireDate, "2030-12-31"),
		IDNumber:    coalesce(tx.ReceiverIDNumber, "000000000000"),
		Remark:      firstNonEmpty(tx.Remark, ""),
	}
}

func load(cfg Config) Settings {
	return Settings{
		RPC:     firstNonEmpty(os.Getenv("RPC_URL"), "https://rpc.example.com"),
		Base:    firstNonEmpty(cfg.BaseCode, "AAA"),
		Gateway: firstNonEmpty(cfg.GatewayURL, "https://gw.example.com"),
	}
}
`
	violations := NewDefaultInventsDomainValueRule().AnalyzeFile(rulestest.GoFile(t, "provider/request.go", source))
	assert.Equal(t, []int{4, 5, 13, 14}, violationLines(violations))
}
