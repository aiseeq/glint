package patterns

import "go/types"

// Rules about money cannot ask the type system whether a decimal holds cents
// or a ratio, so they read the name the code gave the value. A name is split
// into words (identifierTokens) and the words are compared whole: a substring
// match made "consumedUnits" a sum and "summaryBuf" money.
//
// The vocabulary is layered, and each rule reads the layers its scope needs.

// moneyValueTokens are the words every money rule reads as an amount.
var moneyValueTokens = wordSet(
	"amount", "balance", "cost", "fee", "price", "profit", "usd",
)

// moneyMarketTokens name financial figures of a market or a portfolio. A JSON
// contract field so named is money (strongFinancialName); code rounding or
// scaling a value does not treat them as cash amounts, since a yield or a
// valuation there is as often a ratio.
var moneyMarketTokens = wordSet("revenue", "tvl", "valuation", "yield")

// moneyFlowTokens name money being moved or aggregated. Where the value is
// already known to be money-shaped (a decimal being rounded, a float scaled
// by 100) they mean an amount; on a struct field of unknown use a "total" or
// a "payment" may be a count or a record, so strongFinancialName does not
// read them.
var moneyFlowTokens = wordSet(
	"total", "subtotal", "sum", "payout", "payment", "deposit", "withdraw", "withdrawal",
	"principal", "usdc", "usdt",
)

// wordSet builds a token set holding each word and its plural.
func wordSet(words ...string) map[string]bool {
	set := make(map[string]bool, 2*len(words))
	for _, word := range words {
		set[word] = true
		set[word+"s"] = true
	}
	return set
}

// hasTokenIn reports whether any word of the text is in one of the sets.
func hasTokenIn(text string, sets ...map[string]bool) bool {
	for _, token := range identifierTokens(text) {
		for _, set := range sets {
			if set[token] {
				return true
			}
		}
	}
	return false
}

// looksLikeMoney reports whether an expression names a monetary value: one of
// its words is a money value or money flow word, or it names the maximum a
// user can receive (maxReceive).
func looksLikeMoney(expression string) bool {
	tokens := identifierTokens(expression)
	for i, token := range tokens {
		if moneyValueTokens[token] || moneyFlowTokens[token] {
			return true
		}
		if token == "max" && i+1 < len(tokens) && tokens[i+1] == "receive" {
			return true
		}
	}
	return false
}

// shopspringDecimalPath is the import path of the decimal type the money
// rules know.
const shopspringDecimalPath = "github.com/shopspring/decimal"

// isShopspringDecimalType reports whether t is decimal.Decimal or a pointer
// to it.
func isShopspringDecimalType(t types.Type) bool {
	if t == nil {
		return false
	}
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == shopspringDecimalPath && named.Obj().Name() == "Decimal"
}
