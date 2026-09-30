package patterns

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// jsSource is a TS/JS file in the two masked forms the frontend line rules
// read. Both keep every line's length, so a position found in one is valid in
// the other and in the original source.
type jsSource struct {
	// code has comments and literal contents blanked: braces, parentheses and
	// calls in it are real code.
	code []string
	// text has only comments blanked: literal text (env names, selectors,
	// URLs, asserted values) is still there.
	text []string
}

func newJSSource(ctx *core.FileContext) jsSource {
	return jsSource{
		code: helpers.FileJSCode(ctx),
		text: helpers.FileJSText(ctx),
	}
}

// jsBlockEnd returns the position (line, col) of the '}' that closes the '{'
// at (line, col) of the code view, or false when the file ends first.
func jsBlockEnd(code []string, line, col int) (int, int, bool) {
	depth := 0
	for i := line; i < len(code); i++ {
		from := 0
		if i == line {
			from = col
		}
		for j := from; j < len(code[i]); j++ {
			switch code[i][j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return i, j, true
				}
			}
		}
	}
	return 0, 0, false
}

// jsBlockAt returns the block that opens with the first '{' of the code view
// at or after (line, col): its text view from (line, col) through the closing
// '}', and the line of that '}'. Braces in comments and literals do not count.
func jsBlockAt(src jsSource, line, col int) (string, int, bool) {
	for i := line; i < len(src.code); i++ {
		from := 0
		if i == line {
			from = col
		}
		open := strings.IndexByte(src.code[i][from:], '{')
		if open < 0 {
			continue
		}
		endLine, endCol, ok := jsBlockEnd(src.code, i, from+open)
		if !ok {
			return "", 0, false
		}
		return jsSpan(src.text, line, col, endLine, endCol), endLine, true
	}
	return "", 0, false
}

// jsSpan joins lines from (fromLine, fromCol) through (toLine, toCol), both
// ends included.
func jsSpan(lines []string, fromLine, fromCol, toLine, toCol int) string {
	var b strings.Builder
	for i := fromLine; i <= toLine && i < len(lines); i++ {
		from, to := 0, len(lines[i])
		if i == fromLine {
			from = fromCol
		}
		if i == toLine && toCol+1 < to {
			to = toCol + 1
		}
		b.WriteString(lines[i][from:to])
		b.WriteByte('\n')
	}
	return b.String()
}

// jsFirstArgument returns the first argument of the call whose '(' is at
// (line, col) of the code view — up to the top-level ',' or the closing ')' —
// read from the text view and collapsed to one line. An argument spread over
// lines is followed for at most maxLines lines.
func jsFirstArgument(src jsSource, line, col, maxLines int) (string, bool) {
	var arg strings.Builder
	depth := 0
	for i := line; i < len(src.code) && i <= line+maxLines; i++ {
		from := 0
		if i == line {
			from = col + 1
		}
		for j := from; j < len(src.code[i]); j++ {
			switch src.code[i][j] {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				if depth == 0 {
					return strings.Join(strings.Fields(arg.String()), " "), true
				}
				depth--
			case ',':
				if depth == 0 {
					return strings.Join(strings.Fields(arg.String()), " "), true
				}
			}
			arg.WriteByte(src.text[i][j])
		}
		arg.WriteByte(' ')
	}
	return "", false
}

// jsCompact drops all whitespace, so guards can be compared token by token
// however the author spaced them.
func jsCompact(s string) string {
	return strings.Join(strings.Fields(s), "")
}
