package moneyrules

import (
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// Rules about money cannot ask the type system whether a decimal holds cents
// or a ratio, so they read the name the code gave the value. A name is split
// into words (identifierTokens) and the words are compared whole: a substring
// match made "consumedUnits" a sum and "summaryBuf" money.
//
// The vocabulary is layered, and each rule reads the layers its scope needs.

// moneyValueTokens are the words every money rule reads as an amount.
var moneyValueTokens = patternkit.WordSet(
	"amount", "balance", "cost", "fee", "price", "profit", "usd",
)

// moneyMarketTokens name financial figures of a market or a portfolio. A JSON
// contract field so named is money (strongFinancialName); code rounding or
// scaling a value does not treat them as cash amounts, since a yield or a
// valuation there is as often a ratio.
var moneyMarketTokens = patternkit.WordSet("revenue", "tvl", "valuation", "yield")

// moneyFlowTokens name money being moved or aggregated. Where the value is
// already known to be money-shaped (a decimal being rounded, a float scaled
// by 100) they mean an amount; on a struct field of unknown use a "total" or
// a "payment" may be a count or a record, so strongFinancialName does not
// read them.
var moneyFlowTokens = patternkit.WordSet(
	"total", "subtotal", "sum", "payout", "payment", "deposit", "withdraw", "withdrawal",
	"principal", "usdc", "usdt",
)

// looksLikeMoney reports whether an expression names a monetary value: one of
// its words is a money value or money flow word, or it names the maximum a
// user can receive (maxReceive).
func looksLikeMoney(expression string) bool {
	tokens := patternkit.IdentifierTokens(expression)
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
	return named.Obj().Pkg().Path() == patternkit.ShopspringDecimalPath && named.Obj().Name() == "Decimal"
}
