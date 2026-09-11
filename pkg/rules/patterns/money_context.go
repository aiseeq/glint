package patterns

import "regexp"

// moneyNamePattern matches identifiers that name a monetary value. Rules about
// money cannot ask the type system whether a decimal holds cents or a ratio, so
// they read the name the code gave it.
var moneyNamePattern = regexp.MustCompile(`(?i)(amount|balance|price|fee|cost|total|maxReceive|maxWithdraw|sum|usd|usdc|usdt|payout|payment|deposit|withdraw|profit|principal)`)

// looksLikeMoney reports whether an expression names a monetary value.
func looksLikeMoney(expression string) bool {
	return moneyNamePattern.MatchString(expression)
}
