// Package helpers provides shared utilities for rule implementations.
package helpers

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

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

// MaskJSCommentsAndStrings returns a copy of TypeScript/JavaScript source lines
// in which every comment (//, /* */ spanning lines, JSDoc) and the contents of
// every literal — '…', "…", template text between ${…} holes, /regex/ — are
// replaced with spaces. String, template and regex delimiters stay in place,
// and so does the code inside ${…}. Every line keeps its byte length, so line
// numbers and byte columns of the masked text point at the original source.
//
// Line rules use it for structure — braces, parentheses, calls — that must
// not be read out of prose or literal text.
//
// There is no parser behind it: an apostrophe in JSX text ("Don't") opens a
// string that ends with the line, and a '/' is taken for a regex literal only
// where an operand is expected. Both keep the damage within one line.
func MaskJSCommentsAndStrings(lines []string) []string {
	return maskJS(lines, true)
}

// ContainsAny reports whether s contains one of the needles: the cheap check
// rules run before a regexp every match of which holds a needle.
func ContainsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// jsMaskKey keys the masked views of a file in core.FileShared.
type jsMaskKey struct{ maskLiterals bool }

// FileJSCode is MaskJSCommentsAndStrings of the file's lines, masked once per
// file for all rules. The result must not be modified.
func FileJSCode(ctx *core.FileContext) []string {
	return core.FileShared(ctx, jsMaskKey{maskLiterals: true}, func() []string { return maskJS(ctx.Lines, true) })
}

// FileJSText is MaskJSComments of the file's lines, masked once per file for
// all rules. The result must not be modified.
func FileJSText(ctx *core.FileContext) []string {
	return core.FileShared(ctx, jsMaskKey{maskLiterals: false}, func() []string { return maskJS(ctx.Lines, false) })
}

// MaskJSComments is MaskJSCommentsAndStrings for rules that read literal text
// (env names, selectors, URLs): only comments are blanked, literals stay.
func MaskJSComments(lines []string) []string {
	return maskJS(lines, false)
}

type jsScanMode int

const (
	jsModeCode jsScanMode = iota
	jsModeBlockComment
	jsModeSingleQuote
	jsModeDoubleQuote
	jsModeTemplate
)

// jsRegexKeywords are the words after which a '/' starts a regex literal.
var jsRegexKeywords = map[string]bool{
	"return": true, "typeof": true, "case": true, "do": true, "else": true,
	"in": true, "of": true, "new": true, "delete": true, "void": true,
	"throw": true, "yield": true, "await": true,
}

// jsMasker carries the scanner state across lines: block comments and
// template literals span lines, and the previous token decides whether a
// '/' divides or opens a regex.
type jsMasker struct {
	maskLiterals bool
	mode         jsScanMode
	// holes holds the brace depth of every open ${…} hole, innermost last.
	holes    []int
	prev     byte
	prevWord string
}

func maskJS(lines []string, maskLiterals bool) []string {
	m := &jsMasker{maskLiterals: maskLiterals}
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = m.maskLine(line)
	}
	return out
}

func (m *jsMasker) maskLine(line string) string {
	buf := []byte(line)
	for i := 0; i < len(buf); {
		switch m.mode {
		case jsModeBlockComment:
			i = m.scanBlockComment(buf, i)
		case jsModeSingleQuote, jsModeDoubleQuote:
			i = m.scanQuoted(buf, i)
		case jsModeTemplate:
			i = m.scanTemplate(buf, i)
		default:
			i = m.scanCode(buf, i)
		}
	}
	// A quoted string ends with its line unless the line ends in a backslash
	// continuation; an unterminated one must not swallow the rest of the file.
	if (m.mode == jsModeSingleQuote || m.mode == jsModeDoubleQuote) &&
		(len(line) == 0 || line[len(line)-1] != '\\') {
		m.mode = jsModeCode
	}
	return string(buf)
}

// literal blanks buf[i] when literal contents are masked.
func (m *jsMasker) literal(buf []byte, i int) {
	if m.maskLiterals && i < len(buf) {
		buf[i] = ' '
	}
}

func (m *jsMasker) scanBlockComment(buf []byte, i int) int {
	if buf[i] == '*' && i+1 < len(buf) && buf[i+1] == '/' {
		buf[i], buf[i+1] = ' ', ' '
		m.mode = jsModeCode
		return i + 2
	}
	buf[i] = ' '
	return i + 1
}

func (m *jsMasker) scanQuoted(buf []byte, i int) int {
	quote := byte('\'')
	if m.mode == jsModeDoubleQuote {
		quote = '"'
	}
	switch buf[i] {
	case '\\':
		m.literal(buf, i)
		m.literal(buf, i+1)
		return i + 2
	case quote:
		m.mode = jsModeCode
		m.prev, m.prevWord = quote, ""
		return i + 1
	}
	m.literal(buf, i)
	return i + 1
}

func (m *jsMasker) scanTemplate(buf []byte, i int) int {
	switch {
	case buf[i] == '\\':
		m.literal(buf, i)
		m.literal(buf, i+1)
		return i + 2
	case buf[i] == '`':
		m.mode = jsModeCode
		m.prev, m.prevWord = '`', ""
		return i + 1
	case buf[i] == '$' && i+1 < len(buf) && buf[i+1] == '{':
		m.holes = append(m.holes, 0)
		m.mode = jsModeCode
		m.prev, m.prevWord = '{', ""
		return i + 2
	}
	m.literal(buf, i)
	return i + 1
}

func (m *jsMasker) scanCode(buf []byte, i int) int {
	c := buf[i]
	next := byte(0)
	if i+1 < len(buf) {
		next = buf[i+1]
	}
	switch {
	case c == '/' && next == '/':
		for j := i; j < len(buf); j++ {
			buf[j] = ' '
		}
		return len(buf)
	case c == '/' && next == '*':
		buf[i], buf[i+1] = ' ', ' '
		m.mode = jsModeBlockComment
		return i + 2
	case c == '/' && m.regexAllowed():
		if end := regexLiteralEnd(buf, i); end > 0 {
			for j := i + 1; j < end; j++ {
				m.literal(buf, j)
			}
			// A regex is an operand: a '/' right after it divides.
			m.prev, m.prevWord = 'r', ""
			return end + 1
		}
	case c == '\'':
		m.mode = jsModeSingleQuote
		return i + 1
	case c == '"':
		m.mode = jsModeDoubleQuote
		return i + 1
	case c == '`':
		m.mode = jsModeTemplate
		return i + 1
	case c == '{' && len(m.holes) > 0:
		m.holes[len(m.holes)-1]++
	case c == '}' && len(m.holes) > 0:
		top := len(m.holes) - 1
		if m.holes[top] == 0 {
			m.holes = m.holes[:top]
			m.mode = jsModeTemplate
			return i + 1
		}
		m.holes[top]--
	case c == ' ' || c == '\t' || c == '\r':
		return i + 1
	case isJSWordChar(c):
		j := i
		for j < len(buf) && isJSWordChar(buf[j]) {
			j++
		}
		m.prev, m.prevWord = buf[j-1], string(buf[i:j])
		return j
	}
	m.prev, m.prevWord = c, ""
	return i + 1
}

// regexAllowed reports whether a '/' at this point opens a regex literal:
// an operand is expected after an operator, an opening bracket, a separator
// or a keyword such as return. '<' and '>' are left out on purpose: in JSX
// they precede the '/' of "</tag" and "/>".
func (m *jsMasker) regexAllowed() bool {
	if m.prev == 0 {
		return true
	}
	if isJSWordChar(m.prev) {
		return jsRegexKeywords[m.prevWord]
	}
	return strings.IndexByte("(,=:[!&|?{};+-*%~^", m.prev) >= 0
}

// regexLiteralEnd returns the index of the '/' closing the regex literal
// opened at start, or -1 when the line ends first.
func regexLiteralEnd(buf []byte, start int) int {
	inClass := false
	for j := start + 1; j < len(buf); j++ {
		switch buf[j] {
		case '\\':
			j++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				return j
			}
		}
	}
	return -1
}

func isJSWordChar(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
