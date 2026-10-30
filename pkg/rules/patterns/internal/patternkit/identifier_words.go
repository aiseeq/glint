package patternkit

import "strings"

// IdentifierWords splits an identifier into lowercase words at case changes,
// separators, and digit runs.
func IdentifierWords(name string) []string {
	var words []string
	start := -1
	flush := func(end int) {
		if start >= 0 && start < end {
			words = append(words, strings.ToLower(name[start:end]))
		}
		start = -1
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= '0' && c <= '9' {
			flush(i)
			j := i + 1
			for j < len(name) && name[j] >= '0' && name[j] <= '9' {
				j++
			}
			words = append(words, name[i:j])
			i = j - 1
			continue
		}
		if !isIdentifierLetter(c) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		previous := name[i-1]
		if isUpperASCII(c) && (isLowerASCII(previous) || isUpperASCII(previous) && i+1 < len(name) && isLowerASCII(name[i+1])) {
			flush(i)
			start = i
		}
	}
	flush(len(name))
	return words
}

func isIdentifierLetter(c byte) bool {
	return isLowerASCII(c) || isUpperASCII(c)
}

func isLowerASCII(c byte) bool { return c >= 'a' && c <= 'z' }

func isUpperASCII(c byte) bool { return c >= 'A' && c <= 'Z' }
