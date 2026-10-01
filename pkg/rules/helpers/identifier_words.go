package helpers

import (
	"strings"
	"unicode"
)

// IdentifierWords splits an identifier into lower-case words at underscores
// and camelCase boundaries; an acronym is one word (HTTPClient: http, client).
func IdentifierWords(name string) []string {
	var words []string
	runes := []rune(name)
	start := 0
	flush := func(end int) {
		if end > start {
			words = append(words, strings.ToLower(string(runes[start:end])))
		}
		start = end
	}
	for i := 0; i < len(runes); i++ {
		switch {
		case runes[i] == '_':
			flush(i)
			start = i + 1
		case i > start && unicode.IsUpper(runes[i]):
			prevLower := !unicode.IsUpper(runes[i-1])
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if prevLower || nextLower {
				flush(i)
			}
		}
	}
	flush(len(runes))
	return words
}
