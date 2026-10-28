package patternkit

import (
	"go/token"
)

// IsComparisonOp checks if operator is a comparison
func IsComparisonOp(op token.Token) bool {
	return op == token.LSS || op == token.LEQ ||
		op == token.GTR || op == token.GEQ ||
		op == token.EQL || op == token.NEQ
}
