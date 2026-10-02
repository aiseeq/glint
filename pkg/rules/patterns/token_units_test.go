package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A loop over balances of different coins that divides every raw amount by
// the native coin's power of ten, while a stablecoin of the same chain has 6
// decimals.
func TestTokenAmountFixedDecimals(t *testing.T) {
	assert.Equal(t, []string{"chain/balances.go:24", "chain/balances.go:44"}, typedFuncFindings(t, NewTokenAmountFixedDecimalsRule(), map[string]string{
		"chain/balances.go": `package chain

import "github.com/shopspring/decimal"

const nativeDivisor = 1e9

type Balance struct {
	CoinType string
	Total    string
}

type Change struct {
	CoinType string
	Amount   string
}

type Meta struct{ Decimals int32 }

func totals(balances []Balance) []decimal.Decimal {
	var out []decimal.Decimal
	for _, b := range balances {
		amount, _ := decimal.NewFromString(b.Total)
		divisor := decimal.NewFromInt(1e9)
		amount = amount.Div(divisor)
		if b.CoinType == "native" {
			out = append(out, amount)
			continue
		}
		switch b.CoinType {
		case "usd":
			stable := decimal.NewFromInt(1e6)
			amount, _ = decimal.NewFromString(b.Total)
			amount = amount.Div(stable)
		}
		out = append(out, amount)
	}
	return out
}

func changes(list []Change) map[string]decimal.Decimal {
	out := map[string]decimal.Decimal{}
	for _, c := range list {
		amount, _ := decimal.NewFromString(c.Amount)
		amount = amount.Div(decimal.NewFromInt(nativeDivisor))
		out[c.CoinType] = amount
	}
	return out
}

func scaled(list []Change, meta map[string]Meta) []decimal.Decimal {
	var out []decimal.Decimal
	for _, c := range list {
		amount, _ := decimal.NewFromString(c.Amount)
		decimals := meta[c.CoinType].Decimals
		amount = amount.Div(decimal.New(1, decimals))
		out = append(out, amount)
	}
	return out
}

func gas(fees []string) []decimal.Decimal {
	var out []decimal.Decimal
	for _, fee := range fees {
		amount, _ := decimal.NewFromString(fee)
		out = append(out, amount.Div(decimal.NewFromInt(1e9)))
	}
	return out
}

func percents(list []Change) []decimal.Decimal {
	var out []decimal.Decimal
	for _, c := range list {
		amount, _ := decimal.NewFromString(c.Amount)
		out = append(out, amount.Div(decimal.NewFromInt(100)))
	}
	return out
}
`,
	}))
}

// A ledger keyed by the symbol of transfers that carry the token's address:
// two tokens with one symbol add up in one entry.
func TestTokenKeyedBySymbol(t *testing.T) {
	assert.Equal(t, []string{"ledger/ledger.go:26", "ledger/ledger.go:34"}, typedFuncFindings(t, NewTokenKeyedBySymbolRule(), map[string]string{
		"ledger/ledger.go": `package ledger

type Transfer struct {
	Wallet       string
	TokenSymbol  string
	TokenAddress string
	Amount       int64
}

type tokenKey struct {
	wallet string
	token  string
}

type Balance struct {
	Wallet string
	Symbol string
}

func transferSymbol(tx *Transfer) string { return tx.TokenSymbol }

func bySymbol(txs []*Transfer) map[tokenKey]int64 {
	out := map[tokenKey]int64{}
	for _, tx := range txs {
		symbol := transferSymbol(tx)
		out[tokenKey{wallet: tx.Wallet, token: "sym:" + symbol}] += tx.Amount
	}
	return out
}

func bySymbolField(txs []Transfer) map[tokenKey]int64 {
	out := map[tokenKey]int64{}
	for _, tx := range txs {
		out[tokenKey{wallet: tx.Wallet, token: tx.TokenSymbol}] += tx.Amount
	}
	return out
}

func byAddress(txs []*Transfer) map[tokenKey]int64 {
	out := map[tokenKey]int64{}
	for _, tx := range txs {
		token := tx.TokenSymbol
		if tx.TokenAddress != "" {
			token = tx.TokenAddress
		}
		out[tokenKey{wallet: tx.Wallet, token: token}] += tx.Amount
	}
	return out
}

func balances(list []Balance) map[tokenKey]bool {
	out := map[tokenKey]bool{}
	for _, b := range list {
		out[tokenKey{wallet: b.Wallet, token: b.Symbol}] = true
	}
	return out
}

func native(wallet string) tokenKey {
	return tokenKey{wallet: wallet, token: nativeSymbol()}
}

func nativeSymbol() string { return "ETH" }
`,
	}))
}
