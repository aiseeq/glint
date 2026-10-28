package patternkit

// WordSet builds a token set holding each word and its plural.
func WordSet(words ...string) map[string]bool {
	set := make(map[string]bool, 2*len(words))
	for _, word := range words {
		set[word] = true
		set[word+"s"] = true
	}
	return set
}

// HasTokenIn reports whether any word of the text is in one of the sets.
func HasTokenIn(text string, sets ...map[string]bool) bool {
	for _, token := range IdentifierTokens(text) {
		for _, set := range sets {
			if set[token] {
				return true
			}
		}
	}
	return false
}

// ShopspringDecimalPath is the import path of the decimal type the money
// rules know.
const ShopspringDecimalPath = "github.com/shopspring/decimal"
