package core

import "strings"

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

	// collect asks for the comments, gathered into comments: each line a
	// comment spans, cont set on the lines after the one it opens on.
	collect    bool
	comments   []lineComment
	line       int
	src        string
	blockStart int
	blockCont  bool
}

// MaskJS returns a copy of TypeScript/JavaScript source lines with every
// comment replaced with spaces and, when maskLiterals is set, the contents
// of every literal too. Every line keeps its byte length.
func MaskJS(lines []string, maskLiterals bool) []string {
	m := &jsMasker{maskLiterals: maskLiterals}
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = m.maskLine(line)
	}
	return out
}

// jsComments returns the comments of TypeScript/JavaScript source lines, as
// the masker reads them: a "//" inside a string, template or regex literal
// starts none.
func jsComments(lines []string) []lineComment {
	m := &jsMasker{collect: true}
	for i, line := range lines {
		m.line, m.src = i+1, line
		m.maskLine(line)
	}
	return m.comments
}

// record collects the comment text src[start:end] of the current line.
func (m *jsMasker) record(start, end int, cont bool) {
	if m.collect && start < end {
		m.comments = append(m.comments, lineComment{Line: m.line, Text: m.src[start:end], Cont: cont})
	}
}

func (m *jsMasker) maskLine(line string) string {
	buf := []byte(line)
	if m.mode == jsModeBlockComment {
		m.blockStart, m.blockCont = 0, true
	}
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
	if m.mode == jsModeBlockComment {
		m.record(m.blockStart, len(line), m.blockCont)
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
		m.record(m.blockStart, i+2, m.blockCont)
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
		m.record(i, len(buf), false)
		for j := i; j < len(buf); j++ {
			buf[j] = ' '
		}
		return len(buf)
	case c == '/' && next == '*':
		buf[i], buf[i+1] = ' ', ' '
		m.mode = jsModeBlockComment
		m.blockStart, m.blockCont = i, false
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
