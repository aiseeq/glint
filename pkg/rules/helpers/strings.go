// Package helpers provides shared utilities for rule implementations.
package helpers

import "strings"

// IsInsideString checks if a substring appears inside a double-quoted string literal.
// It counts quotes before the substring - odd count means inside a string.
func IsInsideString(line, substr string) bool {
	idx := strings.Index(line, substr)
	if idx < 0 {
		return false
	}

	beforeSubstr := line[:idx]
	quoteCount := strings.Count(beforeSubstr, `"`)
	return quoteCount%2 == 1
}

// IsInsideBackticks checks if a substring appears inside a backtick (raw) string literal.
func IsInsideBackticks(line, substr string) bool {
	idx := strings.Index(line, substr)
	if idx < 0 {
		return false
	}

	beforeSubstr := line[:idx]
	backtickCount := strings.Count(beforeSubstr, "`")
	return backtickCount%2 == 1
}

// IsInComment checks if a substring appears inside a comment.
func IsInComment(line, substr string) bool {
	commentIdx := strings.Index(line, "//")
	if commentIdx < 0 {
		return false
	}

	substrIdx := strings.Index(line, substr)
	if substrIdx < 0 {
		return false
	}

	return substrIdx > commentIdx
}

// IsInStringOrComment checks if a substring is inside a string literal or comment.
func IsInStringOrComment(line, substr string) bool {
	return IsInsideString(line, substr) || IsInsideBackticks(line, substr) || IsInComment(line, substr)
}
