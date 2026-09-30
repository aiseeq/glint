package helpers

import (
	"unicode"
	"unicode/utf8"
)

// HasLeadingWord reports whether name starts with the camelCase word (its
// first letter in either case) and the word ends there: the name ends, or the
// next rune is an upper-case letter, a digit or an underscore.
func HasLeadingWord(name, word string) bool {
	if len(name) < len(word) {
		return false
	}
	head := name[:len(word)]
	if head != word && head != lowerFirst(word) {
		return false
	}
	return WordEndsAt(name, len(word))
}

// WordEndsAt reports whether a camelCase word of name ends at byte offset i.
func WordEndsAt(name string, i int) bool {
	if i >= len(name) {
		return true
	}
	next, _ := utf8.DecodeRuneInString(name[i:])
	return unicode.IsUpper(next) || unicode.IsDigit(next) || next == '_'
}

func lowerFirst(word string) string {
	first, size := utf8.DecodeRuneInString(word)
	return string(unicode.ToLower(first)) + word[size:]
}

// WriteVerbs lead the names of calls and methods that change stored state.
var WriteVerbs = []string{"Create", "Insert", "Update", "Delete", "Remove", "Save", "Upsert", "Exec", "Store",
	"Persist", "Commit", "Put", "Mark", "Record"}

// IsWriteName reports a name led by a write verb: UpdateStatus, saveSnapshot.
func IsWriteName(name string) bool {
	for _, verb := range WriteVerbs {
		if HasLeadingWord(name, verb) {
			return true
		}
	}
	return false
}
