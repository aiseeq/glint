package duplication

import (
	"strings"
)

// Single source of truth for the sliding-window machinery shared by
// duplicate-block (within one file) and cross-file-duplicate (across files).

// minWindowContent is the minimum total length of a window's normalized lines.
// Shorter windows carry too little signal to be worth reporting.
const minWindowContent = 150

// windowHash identifies a window by content. Both rules verify a hash match by
// comparing the windows line by line, so a collision can never produce a
// finding — it can only cost one extra comparison.
type windowHash uint64

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// hashLine returns the FNV-1a hash of a single normalized line.
func hashLine(line string) windowHash {
	hash := windowHash(fnvOffset64)
	for i := 0; i < len(line); i++ {
		hash ^= windowHash(line[i])
		hash *= fnvPrime64
	}
	return hash
}

// hashLines returns the per-line hashes of an already normalized file. Windows
// are then hashed from these values instead of re-reading the line bytes, so
// hashing all windows of a file costs O(lines x windowSize) machine words
// rather than O(lines x windowSize) bytes of SHA-256.
func hashLines(normalized []string) []windowHash {
	hashes := make([]windowHash, len(normalized))
	for i, line := range normalized {
		hashes[i] = hashLine(line)
	}
	return hashes
}

// hashWindow folds the per-line hashes of normalized[start:start+size] into a
// polynomial hash over the ring of uint64.
func hashWindow(lineHashes []windowHash, start, size int) windowHash {
	hash := windowHash(fnvOffset64)
	for _, lineHash := range lineHashes[start : start+size] {
		hash ^= lineHash
		hash *= fnvPrime64
	}
	return hash
}

// windowsMatch reports whether two windows are identical line by line.
func windowsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizeLine trims a line and collapses every run of whitespace to a single
// space, so that indentation and alignment differences do not hide duplicates.
func normalizeLine(line string) string {
	line = strings.TrimSpace(line)
	if !hasWhitespaceRun(line) {
		return line
	}

	var b strings.Builder
	b.Grow(len(line))
	inRun := false
	for i := 0; i < len(line); i++ {
		if isSpace(line[i]) {
			inRun = true
			continue
		}
		if inRun {
			b.WriteByte(' ')
			inRun = false
		}
		b.WriteByte(line[i])
	}
	return b.String()
}

// hasWhitespaceRun reports whether the line contains any whitespace that
// normalizeLine would have to rewrite (a run of two or more, or a tab).
func hasWhitespaceRun(line string) bool {
	for i := 0; i < len(line); i++ {
		if !isSpace(line[i]) {
			continue
		}
		if line[i] != ' ' || (i+1 < len(line) && isSpace(line[i+1])) {
			return true
		}
	}
	return false
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r'
}

// normalizeFileLines normalizes every line of the file, blanking the lines
// inside raw-string literals: their content is data, not code, and both
// duplication rules must judge it the same way.
func normalizeFileLines(lines []string) []string {
	rawStringLines := rawStringLineSet(lines)
	normalized := make([]string, len(lines))
	for i, line := range lines {
		if rawStringLines[i] {
			continue // stays "", carrying no duplication signal
		}
		normalized[i] = normalizeLine(line)
	}
	return normalized
}

// rawStringLineSet marks the lines that open, continue, or close a multi-line
// raw-string literal.
func rawStringLineSet(lines []string) map[int]bool {
	result := make(map[int]bool)
	inRawString := false
	for i, line := range lines {
		if rawStringDelimiters(line, inRawString)%2 == 1 {
			result[i] = true
			inRawString = !inRawString
			continue
		}
		if inRawString {
			result[i] = true
		}
	}
	return result
}

// rawStringDelimiters counts the backticks on the line that open or close a
// raw-string literal. A backtick inside a quoted literal ("`", '`') is content,
// not a delimiter — counting it flipped the raw-string state for the rest of
// the file.
func rawStringDelimiters(line string, inRawString bool) int {
	delimiters := 0
	var quote byte // the quote character we are inside, 0 outside literals
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inRawString {
			if c == '`' {
				delimiters++
				inRawString = false
			}
			continue
		}
		if quote != 0 {
			switch c {
			case '\\':
				i++ // the escaped character cannot close the literal
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '`':
			delimiters++
			inRawString = true
		case '"', '\'':
			quote = c
		}
	}
	return delimiters
}

// isTrivialLine reports whether a normalized line carries no duplication
// signal: punctuation, boilerplate control flow, comments or very short lines.
func isTrivialLine(line string) bool {
	if line == "" {
		return true
	}

	switch line {
	case "{", "}", "(", ")", "[", "]",
		"else {", "} else {", "} else if",
		"default:", "break", "continue",
		"return", "return nil", "return false", "return true",
		"return err", "return result", "return v",
		"if err != nil {", "if !ok {", "if ok {",
		"defer func() {", "}()":
		return true
	}

	// Struct literal fields and similar short comma-terminated lines.
	if strings.HasSuffix(line, ",") && len(line) < 50 {
		return true
	}

	// Struct field declarations carrying serialization tags.
	if strings.Contains(line, "`json:") || strings.Contains(line, "`xml:") {
		return true
	}

	if len(line) < 15 {
		return true
	}

	return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*")
}

// isWindowTrivial reports whether a window has too little substance to be worth
// reporting: fewer than minNonTrivial meaningful lines or too little content.
// The trivial predicate decides what "meaningful" means for the calling rule.
func isWindowTrivial(window []string, minNonTrivial int, trivial func(string) bool) bool {
	nonTrivial := 0
	totalLength := 0
	for _, line := range window {
		totalLength += len(line)
		if !trivial(line) {
			nonTrivial++
		}
	}
	return nonTrivial < minNonTrivial || totalLength < minWindowContent
}
