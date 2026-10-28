package patternkit

import (
	"strings"
)

var ProviderCommandMethods = map[string]bool{
	"SendTransaction":   true,
	"ExecutePayment":    true,
	"SubmitPayment":     true,
	"CreatePayout":      true,
	"SendPayout":        true,
	"TransferFunds":     true,
	"CancelTransaction": true,
	"CancelPayment":     true,
	"RefundPayment":     true,
	"CreateRefund":      true,
	"SendRefund":        true,
}

func ContainsAnyFold(value string, needles []string) bool {
	lower := strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
