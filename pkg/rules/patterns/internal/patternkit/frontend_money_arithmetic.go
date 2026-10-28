package patternkit

// MatchingParenEnd returns the index of the ')' closing the call whose
// argument starts at start, or -1. Nested parens and quoted strings are
// handled.
func MatchingParenEnd(line string, start int) int {
	depth := 1
	quote := byte(0)
	for i := start; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
