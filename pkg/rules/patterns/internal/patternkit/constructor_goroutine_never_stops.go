package patternkit

import (
	"strings"
	"unicode"
)

// IsConstructorName reports New… or new… followed by an upper-case letter.
func IsConstructorName(name string) bool {
	for _, prefix := range []string{"New", "new"} {
		rest, ok := strings.CutPrefix(name, prefix)
		if ok && (rest == "" || unicode.IsUpper([]rune(rest)[0])) {
			return true
		}
	}
	return false
}
