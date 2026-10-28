package patternkit

import (
	"regexp"
)

// TsMoneyLimit is an object property of a money limit or a fee set to a
// number: { minAmount: 10 }, { maxWithdrawal: 5000 }, { feePercent: 1.5 }.
var TsMoneyLimit = regexp.MustCompile(`\b((?:min|max)(?:Amount|Deposit|Withdrawal|Withdraw|Investment|Invest|Payout|Transfer|Balance)\w*|fee(?:Percent|Rate|Amount)?|commission\w*)\s*:\s*(\d[\d_]*(?:\.\d+)?)\b`)
