package duplication

import (
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

type tsTokenKind int

const (
	tsIdent tsTokenKind = iota
	tsNumber
	tsString
	tsTemplate
	tsRegex
	tsPunct
)

type tsToken struct {
	text string
	kind tsTokenKind
	line int
}

// tsPunctuators are the operators of TypeScript, longest first, so that the
// scanner takes === before ==.
var tsPunctuators = []string{
	">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
	"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=",
	"*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
}

// tsOperators are the operators a copy keeps: one that compares or computes
// the other way is another function.
var tsOperators = map[string]bool{
	"===": true, "!==": true, "==": true, "!=": true, "<=": true, ">=": true, "<": true, ">": true,
	"&&": true, "||": true, "??": true, "!": true, "+": true, "-": true, "*": true, "/": true, "%": true,
	"**": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true, "&": true, "|": true, "^": true,
	"<<": true, ">>": true, ">>>": true, "&&=": true, "||=": true, "??=": true, "instanceof": true, "in": true,
}

// tsKeywords are the words that are never a variable of the function.
var tsKeywords = map[string]bool{
	"break": true, "case": true, "catch": true, "class": true, "const": true, "continue": true,
	"debugger": true, "default": true, "delete": true, "do": true, "else": true, "export": true,
	"extends": true, "finally": true, "for": true, "function": true, "if": true, "import": true,
	"in": true, "instanceof": true, "new": true, "return": true, "super": true, "switch": true,
	"this": true, "throw": true, "try": true, "typeof": true, "var": true, "void": true,
	"while": true, "with": true, "yield": true, "let": true, "static": true, "await": true,
	"async": true, "of": true, "as": true, "true": true, "false": true, "null": true, "undefined": true,
	"public": true, "private": true, "protected": true, "readonly": true,
}

// tsTokens splits TypeScript into tokens, comments left out (core.MaskJS
// reads them), a string, template or regular expression one token each.
func tsTokens(lines []string) []tsToken {
	masked := core.MaskJS(lines, false)
	var out []tsToken
	for lineIndex := 0; lineIndex < len(masked); lineIndex++ {
		line := masked[lineIndex]
		for i := 0; i < len(line); {
			c := line[i]
			switch {
			case c == ' ' || c == '\t' || c == '\r':
				i++
			case jsIdentByte(c, true):
				j := i + 1
				for j < len(line) && jsIdentByte(line[j], false) {
					j++
				}
				out = append(out, tsToken{text: line[i:j], kind: tsIdent, line: lineIndex + 1})
				i = j
			case c >= '0' && c <= '9' || c == '.' && i+1 < len(line) && line[i+1] >= '0' && line[i+1] <= '9':
				j := i + 1
				for j < len(line) && (jsIdentByte(line[j], false) || line[j] == '.') {
					j++
				}
				out = append(out, tsToken{text: line[i:j], kind: tsNumber, line: lineIndex + 1})
				i = j
			case c == '\'' || c == '"':
				j := quotedEnd(line, i)
				out = append(out, tsToken{text: line[i:j], kind: tsString, line: lineIndex + 1})
				i = j
			case c == '`':
				text, endLine, endIndex := templateLiteral(masked, lineIndex, i)
				out = append(out, tsToken{text: text, kind: tsTemplate, line: lineIndex + 1})
				lineIndex, i = endLine, endIndex
				line = masked[lineIndex]
			case c == '/' && regexAllowed(out):
				j := regexEnd(line, i)
				out = append(out, tsToken{text: line[i:j], kind: tsRegex, line: lineIndex + 1})
				i = j
			default:
				text := line[i : i+1]
				for _, p := range tsPunctuators {
					if strings.HasPrefix(line[i:], p) {
						text = p
						break
					}
				}
				out = append(out, tsToken{text: text, kind: tsPunct, line: lineIndex + 1})
				i += len(text)
			}
		}
	}
	return out
}

func jsIdentByte(c byte, first bool) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80 || !first && c >= '0' && c <= '9'
}

func quotedEnd(line string, start int) int {
	quote := line[start]
	for j := start + 1; j < len(line); j++ {
		switch line[j] {
		case '\\':
			j++
		case quote:
			return j + 1
		}
	}
	return len(line)
}

// templateLiteral reads a template literal that may span lines; the holes
// count their braces, so a } inside ${…} does not end it.
func templateLiteral(lines []string, lineIndex, start int) (string, int, int) {
	var b strings.Builder
	depth := 0
	i := start + 1
	b.WriteByte('`')
	for lineIndex < len(lines) {
		line := lines[lineIndex]
		for i < len(line) {
			c := line[i]
			b.WriteByte(c)
			switch {
			case c == '\\' && i+1 < len(line):
				b.WriteByte(line[i+1])
				i += 2
				continue
			case depth == 0 && c == '`':
				return b.String(), lineIndex, i + 1
			case depth == 0 && c == '$' && i+1 < len(line) && line[i+1] == '{':
				b.WriteByte('{')
				depth = 1
				i += 2
				continue
			case depth > 0 && c == '{':
				depth++
			case depth > 0 && c == '}':
				depth--
			}
			i++
		}
		if lineIndex == len(lines)-1 {
			return b.String(), lineIndex, len(line)
		}
		b.WriteByte('\n')
		lineIndex++
		i = 0
	}
	return b.String(), len(lines) - 1, len(lines[len(lines)-1])
}

func regexAllowed(prev []tsToken) bool {
	if len(prev) == 0 {
		return true
	}
	last := prev[len(prev)-1]
	switch last.kind {
	case tsIdent:
		return core.JSRegexKeywords[last.text]
	case tsPunct:
		return last.text != ")" && last.text != "]" && last.text != "}"
	}
	return false
}

func regexEnd(line string, start int) int {
	class := false
	for j := start + 1; j < len(line); j++ {
		switch c := line[j]; {
		case c == '\\':
			j++
		case c == '[':
			class = true
		case c == ']':
			class = false
		case c == '/' && !class:
			j++
			for j < len(line) && jsIdentByte(line[j], false) {
				j++
			}
			return j
		}
	}
	return len(line)
}

// tsFunc is a TypeScript function with a block body: its name (none for a
// callback), whether the module exports it, the token that opens its
// parameters and the token span of its body.
type tsFunc struct {
	name                string
	exported            bool
	line                int
	paramsOpen          int
	bodyOpen, bodyClose int
}

// tsSource is the tokens of a file, the matching bracket of every bracket,
// its functions and the identifiers it declares, in order.
type tsSource struct {
	toks  []tsToken
	match []int
	funcs []tsFunc
	decls []int
}

func parseTSSource(lines []string) *tsSource {
	s := &tsSource{toks: tsTokens(lines)}
	s.match = tsBrackets(s.toks)
	for i := range s.toks {
		s.scan(i)
	}
	slices.Sort(s.decls)
	s.decls = slices.Compact(s.decls)
	return s
}

func tsBrackets(toks []tsToken) []int {
	match := make([]int, len(toks))
	var stack []int
	for i, tok := range toks {
		match[i] = -1
		if tok.kind != tsPunct {
			continue
		}
		switch tok.text {
		case "(", "[", "{":
			stack = append(stack, i)
		case ")", "]", "}":
			if len(stack) > 0 {
				open := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				match[open], match[i] = i, open
			}
		}
	}
	return match
}

func (s *tsSource) text(i int) string {
	if i < 0 || i >= len(s.toks) {
		return ""
	}
	return s.toks[i].text
}

func (s *tsSource) isIdent(i int) bool {
	return i >= 0 && i < len(s.toks) && s.toks[i].kind == tsIdent && !tsKeywords[s.toks[i].text]
}

func (s *tsSource) scan(i int) {
	tok := s.toks[i]
	switch {
	case tok.kind == tsPunct && tok.text == "(":
		s.scanParen(i)
	case s.isIdent(i) && s.text(i+1) == "=>" && s.arrowParamPosition(i-1):
		s.decls = append(s.decls, i)
		if s.text(i+2) == "{" && s.match[i+2] > 0 {
			name, exported := s.bindingName(i - 1)
			s.funcs = append(s.funcs, tsFunc{name: name, exported: exported, line: tok.line, paramsOpen: i, bodyOpen: i + 2, bodyClose: s.match[i+2]})
		}
	case tok.kind == tsIdent && (tok.text == "let" || tok.text == "const" || tok.text == "var"):
		s.scanDeclaration(i + 1)
	}
}

// arrowParamPosition reports that the token at prev can come before the one
// parameter of an arrow function: not a dot, and not the colon of a return
// type, as in (raw: string): string => {.
func (s *tsSource) arrowParamPosition(prev int) bool {
	switch s.text(prev) {
	case ".", ")", "?.":
		return false
	case ":":
		return s.text(prev-1) != ")"
	}
	return true
}

// scanParen reads a parenthesized list: the parameters of a function when a
// block body or an arrow follows it, possibly after a return type.
func (s *tsSource) scanParen(open int) {
	closeParen := s.match[open]
	if closeParen < 0 {
		return
	}
	after := closeParen + 1
	if s.text(after) == ":" {
		after = s.skipReturnType(after + 1)
		if after < 0 {
			return
		}
	}
	before := open - 1
	if s.text(before) == ">" {
		before = s.genericsStart(before) - 1
	}
	switch s.text(after) {
	case "=>":
		if s.text(before) == "async" {
			before--
		}
		s.params(open, closeParen)
		if s.text(after+1) != "{" || s.match[after+1] < 0 {
			return
		}
		name, exported := s.bindingName(before)
		s.funcs = append(s.funcs, tsFunc{name: name, exported: exported, line: s.toks[open].line, paramsOpen: open, bodyOpen: after + 1, bodyClose: s.match[after+1]})
	case "{":
		if s.match[after] < 0 {
			return
		}
		word := s.text(before)
		if slices.Contains(core.JSParenControlKeywords, word) {
			if word == "catch" {
				s.params(open, closeParen)
			}
			return
		}
		var name string
		exported := false
		switch {
		case word == "function":
			name, exported = s.bindingName(before - 1)
		case s.isIdent(before) && s.text(before-1) != ".":
			name = word
			if s.text(before-1) == "function" {
				exported = s.exportedBefore(before - 2)
			}
		default:
			return
		}
		s.params(open, closeParen)
		s.funcs = append(s.funcs, tsFunc{name: name, exported: exported, line: s.toks[open].line, paramsOpen: open, bodyOpen: after, bodyClose: s.match[after]})
	}
}

func (s *tsSource) exportedBefore(i int) bool {
	for i >= 0 && (s.text(i) == "async" || s.text(i) == "default") {
		i--
	}
	return s.text(i) == "export"
}

// bindingName names the function a value is bound to: the variable of
// const name = …, the key of name: …, the property of x.name = ….
func (s *tsSource) bindingName(i int) (string, bool) {
	if s.text(i) == "async" {
		i--
	}
	switch s.text(i) {
	case ":":
		if s.isIdent(i - 1) {
			return s.text(i - 1), false
		}
	case "=":
		for q := i - 1; q >= 0 && s.toks[q].line == s.toks[i].line; q-- {
			switch s.text(q) {
			case "const", "let", "var":
				if s.isIdent(q + 1) {
					return s.text(q + 1), s.text(q-1) == "export"
				}
				return "", false
			case ";", "{", "}", "(", ",":
				q = -1
			}
		}
		if s.isIdent(i - 1) {
			return s.text(i - 1), false
		}
	}
	return "", false
}

// genericsStart finds the < that opens the type parameters closed at end.
func (s *tsSource) genericsStart(end int) int {
	depth := 0
	for i := end; i >= 0 && end-i < 64; i-- {
		switch s.text(i) {
		case ">":
			depth++
		case ">>":
			depth += 2
		case "<":
			depth--
			if depth == 0 {
				return i
			}
		case ";", "{", "}":
			return end + 1
		}
	}
	return end + 1
}

// skipReturnType returns the token after a return type that starts at i:
// the body brace or the arrow, or -1 when no function follows.
func (s *tsSource) skipReturnType(i int) int {
	angle := 0
	for start := i; i < len(s.toks) && i-start < 256; i++ {
		text := s.text(i)
		switch text {
		case "(", "[":
			if s.match[i] < 0 {
				return -1
			}
			i = s.match[i]
			continue
		case "{":
			if angle == 0 && i > start && s.endsType(i-1) {
				return i
			}
			if s.match[i] < 0 {
				return -1
			}
			i = s.match[i]
			continue
		case "<":
			angle++
		case ">":
			angle--
		case ">>":
			angle -= 2
		case "=>":
			if angle == 0 && i > start && s.endsType(i-1) {
				return i
			}
		case ";", ")", "]", "}", ",", "=":
			if angle == 0 {
				return -1
			}
		}
	}
	return -1
}

func (s *tsSource) endsType(i int) bool {
	switch s.toks[i].kind {
	case tsIdent, tsString, tsNumber:
		return true
	}
	switch s.text(i) {
	case ")", "]", "}", ">", ">>":
		return true
	}
	return false
}

// params records the names a parameter list declares: the bindings outside
// type annotations and default values.
func (s *tsSource) params(open, closeParen int) {
	depth, angle := 0, 0
	region := "binding"
	for i := open + 1; i < closeParen; i++ {
		text := s.text(i)
		switch text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case "<":
			angle++
		case ">":
			angle--
		case ",":
			if depth == 0 && angle <= 0 {
				region, angle = "binding", 0
			}
		case ":":
			if depth == 0 && region == "binding" {
				region = "type"
			}
		case "=":
			if depth == 0 {
				region = "default"
			}
		}
		if region == "binding" && s.isIdent(i) && (depth == 0 || s.text(i+1) != ":") {
			s.decls = append(s.decls, i)
		}
	}
}

// scanDeclaration records the names after let, const or var: one name or the
// names of a destructuring pattern.
func (s *tsSource) scanDeclaration(i int) {
	if s.isIdent(i) {
		s.decls = append(s.decls, i)
		return
	}
	if (s.text(i) == "{" || s.text(i) == "[") && s.match[i] > i {
		for j := i + 1; j < s.match[i]; j++ {
			if s.isIdent(j) && s.text(j+1) != ":" && s.text(j-1) != "." {
				s.decls = append(s.decls, j)
			}
		}
	}
}

// tsNearBody normalizes the body of f: the variables the function declares
// as one placeholder, a property and every other name as written, strings by
// their content; a statement ends at ; and braces, or at a line end outside
// brackets, since TypeScript lets the line end a statement.
func (s *tsSource) tsNearBody(f tsFunc) nearBody {
	locals := make(map[string]bool)
	lo := lowerBound(s.decls, f.paramsOpen)
	for _, d := range s.decls[lo:] {
		if d > f.bodyClose {
			break
		}
		locals[s.toks[d].text] = true
	}
	b := newNearBodyBuilder()
	b.openStmt()
	depth := 0
	for i := f.bodyOpen + 1; i < f.bodyClose; i++ {
		tok := s.toks[i]
		if depth == 0 && i > f.bodyOpen+1 && tok.line > s.toks[i-1].line {
			b.closeStmt()
			b.openStmt()
		}
		// A property after a dot, or the key of an object literal, is a name
		// of the data and no variable, though a variable may be called so.
		property := s.text(i-1) == "." || s.text(i-1) == "?." ||
			s.text(i+1) == ":" && (s.text(i-1) == "{" || s.text(i-1) == ",")
		switch tok.kind {
		case tsIdent:
			out := tok.text
			call := s.text(i+1) == "(" || s.text(i+1) == "?." && s.text(i+2) == "("
			switch {
			case property:
				// A property may be named like a keyword: set.delete(key).
				if call {
					b.calls["."+tok.text] = true
				}
			case tsKeywords[tok.text]:
			case locals[tok.text]:
				out = "$L"
			case call:
				b.calls[tok.text] = true
			}
			if !property && tsOperators[tok.text] {
				b.ops[tok.text] = true
			}
			b.emit(out)
		case tsString:
			value := tok.text[1:max(1, len(tok.text)-1)]
			b.emit(`"` + value + `"`)
			b.lits["s:"+value] = true
		case tsNumber, tsTemplate, tsRegex:
			b.emit(tok.text)
			b.lits[tok.text] = true
		default:
			b.emit(tok.text)
			if tsOperators[tok.text] {
				b.ops[tok.text] = true
			}
			switch tok.text {
			case "(", "[":
				depth++
			case ")", "]":
				depth = max(0, depth-1)
			case ";", "{", "}":
				b.closeStmt()
				b.openStmt()
			}
		}
	}
	return b.finish()
}

func lowerBound(sorted []int, value int) int {
	lo, hi := 0, len(sorted)
	for lo < hi {
		mid := (lo + hi) / 2
		if sorted[mid] < value {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// displayName names f in a finding: by its name, or a callback by the named
// function it is written in.
func (s *tsSource) displayName(f tsFunc) string {
	if f.name != "" {
		return "Function " + f.name
	}
	outer := -1
	for i, g := range s.funcs {
		if g.name != "" && g.bodyOpen < f.bodyOpen && f.bodyClose < g.bodyClose && (outer < 0 || g.bodyOpen > s.funcs[outer].bodyOpen) {
			outer = i
		}
	}
	if outer < 0 {
		return "Anonymous function"
	}
	return "Anonymous function in " + s.funcs[outer].name
}
