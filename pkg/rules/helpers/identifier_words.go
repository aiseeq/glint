package helpers

import (
	"go/types"
	"strings"
	"unicode"
)

// IsIdentifierChar reports an ASCII letter, digit, or underscore.
func IsIdentifierChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// IsSourcePosition reports whether t is go/token.Pos.
func IsSourcePosition(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "go/token" && named.Obj().Name() == "Pos"
}

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
	for i := range runes {
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
