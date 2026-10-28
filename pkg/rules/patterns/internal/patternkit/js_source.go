package patternkit

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// JsSource is a TS/JS file in the two masked forms the frontend line rules
// read. Both keep every line's length, so a position found in one is valid in
// the other and in the original source.
type JsSource struct {
	// Code has comments and literal contents blanked: braces, parentheses and
	// calls in it are real code.
	Code []string
	// Text has only comments blanked: literal text (env names, selectors,
	// URLs, asserted values) is still there.
	Text []string
}

func NewJSSource(ctx *core.FileContext) JsSource {
	return JsSource{
		Code: helpers.FileJSCode(ctx),
		Text: helpers.FileJSText(ctx),
	}
}

// JsBlockEnd returns the position (line, col) of the '}' that closes the '{'
// at (line, col) of the code view, or false when the file ends first.
func JsBlockEnd(code []string, line, col int) (int, int, bool) {
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

// JsBlockAt returns the block that opens with the first '{' of the code view
// at or after (line, col): its text view from (line, col) through the closing
// '}', and the line of that '}'. Braces in comments and literals do not count.
func JsBlockAt(src JsSource, line, col int) (string, int, bool) {
	for i := line; i < len(src.Code); i++ {
		from := 0
		if i == line {
			from = col
		}
		open := strings.IndexByte(src.Code[i][from:], '{')
		if open < 0 {
			continue
		}
		endLine, endCol, ok := JsBlockEnd(src.Code, i, from+open)
		if !ok {
			return "", 0, false
		}
		return JsSpan(src.Text, line, col, endLine, endCol), endLine, true
	}
	return "", 0, false
}

// JsSpan joins lines from (fromLine, fromCol) through (toLine, toCol), both
// ends included.
func JsSpan(lines []string, fromLine, fromCol, toLine, toCol int) string {
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

// JsFirstArgument returns the first argument of the call whose '(' is at
// (line, col) of the code view — up to the top-level ',' or the closing ')' —
// read from the text view and collapsed to one line. An argument spread over
// lines is followed for at most maxLines lines.
func JsFirstArgument(src JsSource, line, col, maxLines int) (string, bool) {
	var arg strings.Builder
	depth := 0
	for i := line; i < len(src.Code) && i <= line+maxLines; i++ {
		from := 0
		if i == line {
			from = col + 1
		}
		for j := from; j < len(src.Code[i]); j++ {
			switch src.Code[i][j] {
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
			arg.WriteByte(src.Text[i][j])
		}
		arg.WriteByte(' ')
	}
	return "", false
}

// JsCompact drops all whitespace, so guards can be compared token by token
// however the author spaced them.
func JsCompact(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// JsReceiverStart returns the column where the receiver of the member access
// whose '.' is at dot of the code line begins: a chain of names, calls and
// indexes (Math.abs(op.amount), rows[i].fee) read backwards on that line.
func JsReceiverStart(code string, dot int) int {
	j := dot - 1
	for j >= 0 {
		c := code[j]
		switch {
		case c == ')' || c == ']':
			open := jsOpeningBefore(code, j)
			if open < 0 {
				return j + 1
			}
			j = open - 1
		case c == '.' || c == '?' || c == '!' || c == '_' || c == '$' ||
			'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9':
			j--
		default:
			return j + 1
		}
	}
	return 0
}

// jsOpeningBefore returns the column of the '(' or '[' that the bracket at
// closing of the line closes, or -1.
func jsOpeningBefore(code string, closing int) int {
	depth := 0
	for j := closing; j >= 0; j-- {
		switch code[j] {
		case ')', ']':
			depth++
		case '(', '[':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}
