package duplication

import (
	"fmt"
	"hash/maphash"
	"math"
	"strings"
)

// Single source of truth for the sliding-window machinery shared by
// duplicate-block (within one file) and cross-file-duplicate (across files).

// minWindowContent is the minimum total length of a window's normalized lines.
// Shorter windows carry too little signal to be worth reporting.
const minWindowContent = 150

// windowHash identifies a window by content. duplicate-block verifies a hash
// match by comparing the windows line by line. cross-file-duplicate keeps no
// text of earlier files and verifies with a second, independent hash of the
// window (checkHash): a false finding needs both 64-bit hashes to collide.
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

// checkSeed seeds the verification hash. It only has to be the same for every
// window of one process run.
var checkSeed = maphash.MakeSeed()

// checkLines returns per-line verification hashes, computed by a hash function
// independent of hashLine.
func checkLines(normalized []string) []windowHash {
	hashes := make([]windowHash, len(normalized))
	for i, line := range normalized {
		hashes[i] = windowHash(maphash.String(checkSeed, line))
	}
	return hashes
}

// checkWindow folds the verification hashes of a window.
func checkWindow(lineChecks []windowHash, start, size int) windowHash {
	const checkPrime = 0x9E3779B97F4A7C15
	var hash windowHash
	for _, lineCheck := range lineChecks[start : start+size] {
		hash = hash*checkPrime + lineCheck + 1
	}
	return hash
}

// blockSizeSetting reads min_block_size: a whole number no smaller than
// minimum, the least window that can hold enough meaningful lines to be
// reported. An absent setting is the default; any other value is an error.
func blockSizeSetting(settings map[string]any, defaultSize, minimum int) (int, error) {
	raw, ok := settings["min_block_size"]
	if !ok {
		return defaultSize, nil
	}
	var size int
	switch v := raw.(type) {
	case int:
		size = v
	case float64:
		if v != math.Trunc(v) || v > math.MaxInt32 {
			return 0, fmt.Errorf("min_block_size must be a whole number of lines, got %v", v)
		}
		size = int(v)
	default:
		return 0, fmt.Errorf("min_block_size must be a whole number of lines, got %T %v", raw, raw)
	}
	if size < minimum {
		return 0, fmt.Errorf("min_block_size must be at least %d lines (a smaller window never holds enough meaningful lines to be reported), got %d", minimum, size)
	}
	return size, nil
}

// windowMatch is a window of the analyzed file (start) equal to a window of
// origFile starting at origStart. Lines are 0-based.
type windowMatch struct {
	start     int
	origFile  string
	origStart int
}

// duplicateRegion is a run of overlapping or adjacent matched windows: lines
// start..end (0-based, inclusive) of the analyzed file, the same as lines
// origStart..origEnd of origFile.
type duplicateRegion struct {
	start, end         int
	origFile           string
	origStart, origEnd int
}

// mergeWindowMatches joins matched windows into regions. Windows slide one
// line at a time, so a long copied region matches at every offset inside it:
// the reader needs the region once, not once per window. matches must be
// sorted by start. The original range grows only while the windows keep the
// same shift against the same file; a window that overlaps the region but
// matches elsewhere is absorbed without widening it.
func mergeWindowMatches(matches []windowMatch, size int) []duplicateRegion {
	var regions []duplicateRegion
	for _, m := range matches {
		if n := len(regions); n > 0 && m.start <= regions[n-1].end+1 {
			current := &regions[n-1]
			current.end = max(current.end, m.start+size-1)
			if m.origFile == current.origFile && m.origStart-current.origStart == m.start-current.start {
				current.origEnd = max(current.origEnd, m.origStart+size-1)
			}
			continue
		}
		regions = append(regions, duplicateRegion{
			start: m.start, end: m.start + size - 1,
			origFile: m.origFile, origStart: m.origStart, origEnd: m.origStart + size - 1,
		})
	}
	return regions
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
	// A file that ends with a newline splits into an empty last element that
	// is not a line of the file; a region must not run onto it.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
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
	var state rawScanState
	for i, line := range lines {
		wasInRawString := state.inRawString
		state = scanRawStringLine(line, state)
		// A line that starts or ends inside a literal opens, continues or
		// closes it. A literal opened and closed on one line is ordinary code.
		if wasInRawString || state.inRawString {
			result[i] = true
		}
	}
	return result
}

// rawScanState is what scanning carries from one line to the next: whether a
// raw-string literal or a block comment is still open.
type rawScanState struct {
	inRawString    bool
	inBlockComment bool
}

// scanRawStringLine follows the backticks on the line that open or close a
// raw-string literal. A backtick inside a quoted literal ("`", '`') or inside
// a comment (// or /* */) is content, not a delimiter: counting it flipped the
// raw-string state for the rest of the file.
func scanRawStringLine(line string, state rawScanState) rawScanState {
	var quote byte // the quote character we are inside, 0 outside literals
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case state.inRawString:
			if c == '`' {
				state.inRawString = false
			}
			continue
		case state.inBlockComment:
			if c == '*' && i+1 < len(line) && line[i+1] == '/' {
				state.inBlockComment = false
				i++
			}
			continue
		case quote != 0:
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
			state.inRawString = true
		case '"', '\'':
			quote = c
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return state // the rest of the line is a comment
			}
			if i+1 < len(line) && line[i+1] == '*' {
				state.inBlockComment = true
				i++
			}
		}
	}
	return state
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

// windowSubstance answers, in constant time per window, whether a window has
// enough substance to be worth reporting. The trivial predicate is evaluated
// once per line and summed into prefix counts: evaluating it for every line
// of every window cost windowSize times as much and dominated the analysis.
type windowSubstance struct {
	nonTrivial []int // nonTrivial[i] = meaningful lines among the first i
	length     []int // length[i] = total length of the first i lines
	trivial    []bool
}

// newWindowSubstance evaluates the trivial predicate - what "meaningful"
// means for the calling rule - on every normalized line.
func newWindowSubstance(normalized []string, trivial func(string) bool) windowSubstance {
	ws := windowSubstance{
		nonTrivial: make([]int, len(normalized)+1),
		length:     make([]int, len(normalized)+1),
		trivial:    make([]bool, len(normalized)),
	}
	for i, line := range normalized {
		ws.trivial[i] = trivial(line)
		ws.nonTrivial[i+1] = ws.nonTrivial[i]
		if !ws.trivial[i] {
			ws.nonTrivial[i+1]++
		}
		ws.length[i+1] = ws.length[i] + len(line)
	}
	return ws
}

// isTrivial reports whether the window of size lines at start has too little
// substance: fewer than minNonTrivial meaningful lines or too little content.
func (ws windowSubstance) isTrivial(start, size, minNonTrivial int) bool {
	nonTrivial := ws.nonTrivial[start+size] - ws.nonTrivial[start]
	totalLength := ws.length[start+size] - ws.length[start]
	return nonTrivial < minNonTrivial || totalLength < minWindowContent
}
