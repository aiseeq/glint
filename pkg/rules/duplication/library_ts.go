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
// its functions and the identifiers it declares, in order, and the names of
// an object pattern or literal that name a property too (markShorthand).
type tsSource struct {
	toks      []tsToken
	match     []int
	funcs     []tsFunc
	decls     []int
	shorthand map[int]bool
}

func parseTSSource(lines []string) *tsSource {
	s := &tsSource{toks: tsTokens(lines), shorthand: make(map[int]bool)}
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
	case tok.kind == tsPunct && tok.text == "{" && (tsObjectBefore[s.text(i-1)] || s.text(i-1) == ":" && s.conditionalElse(i-1)):
		s.markShorthand(i)
	}
}

// tsObjectBefore are the tokens after which a brace opens an object, not a
// block: the assignments that may assign an object, q ??= { bid, ask },
// though not those of arithmetic, which make a number or a text of it.
// After a colon a brace opens an object only in the second branch of a
// conditional (conditionalElse), not after a case or a label.
var tsObjectBefore = map[string]bool{
	"(": true, "[": true, ",": true, "=": true, "??=": true, "||=": true, "&&=": true,
	"return": true, "throw": true, "?": true, "??": true, "||": true, "&&": true, "...": true,
}

// conditionalElse reports whether the colon at colon parts the branches of
// a conditional, c ? x : { ask, bid }: a question mark no other colon
// answers comes before it in its expression. Before the colon of a case or
// a label every question mark has its colon, up to the brace that opens
// the block; before a colon in brackets, up to the bracket.
func (s *tsSource) conditionalElse(colon int) bool {
	colons := 0
	for j := colon - 1; j >= 0; j-- {
		switch s.text(j) {
		case ")", "]", "}":
			if s.match[j] < 0 {
				return false
			}
			j = s.match[j]
		case "?":
			if colons == 0 {
				return true
			}
			colons--
		case ":":
			colons++
		case "(", "[", "{":
			return false
		}
	}
	return false
}

// markShorthand marks the names of the object pattern or literal that opens
// at open, and of the objects in it, written without a key: { bid, ask }
// reads, or builds, the properties bid and ask, as { bid: bid, ask: ask }
// does; { ask, bid } with the names in the other roles is another object.
func (s *tsSource) markShorthand(open int) {
	end := s.match[open]
	object := s.text(open) == "{"
	for j := open + 1; j < end; j++ {
		switch s.text(j) {
		case "{", "[":
			s.markShorthand(j)
		case "(":
		default:
			prev, next := s.text(j-1), s.text(j+1)
			if object && s.isIdent(j) && (prev == "{" || prev == ",") && (next == "," || next == "}" || next == "=") {
				s.shorthand[j] = true
			}
			continue
		}
		if s.match[j] > j {
			j = s.match[j]
		}
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
		s.markShorthand(i)
	}
}

// tsNearBody normalizes the body of f: the variables the function declares
// as one placeholder, numbered by their first appearance in the roles, a
// property and every other name as written, strings by their content; a
// statement ends at ; and braces, or at a line end outside brackets, since
// TypeScript lets the line end a statement. The shape of a statement inside
// braces starts from the shape of the statement that opened them; so does
// the statement a check, a loop or an else holds without braces, which is
// held as it is in braces (tsNearWalker).
func (s *tsSource) tsNearBody(f tsFunc, detailed bool) nearBody {
	locals := &tsLocals{numbers: make(map[string]int)}
	lo := lowerBound(s.decls, f.paramsOpen)
	for _, d := range s.decls[lo:] {
		if d > f.bodyClose {
			break
		}
		locals.numbers[s.toks[d].text] = -1
	}
	w := &tsNearWalker{s: s, b: newNearBodyBuilder(detailed), blocks: []tsBlock{{seed: fnvOffset64, parent: -1}}, scopes: make(map[int]bool)}
	w.reopen()
	w.params(f, locals)
	for i := f.bodyOpen + 1; i < f.bodyClose; i++ {
		tok := s.toks[i]
		if w.depth == 0 && i > f.bodyOpen+1 && tok.line > s.toks[i-1].line && !w.b.fresh() {
			w.endStmt()
		}
		w.markHead(i)
		w.markJump(i)
		if s.effect(i) {
			w.b.fix()
		}
		switch tok.kind {
		case tsIdent:
			i += s.emitName(w.b, i, locals)
		case tsString:
			value := tok.text[1:max(1, len(tok.text)-1)]
			w.b.emitAnchor(`"`+value+`"`, "s:"+value, nearLiteralMask)
			w.b.lits["s:"+value] = true
		case tsNumber, tsTemplate, tsRegex:
			w.b.emitAnchor(tok.text, tok.text, nearLiteralMask)
			w.b.lits[tok.text] = true
		default:
			if tsOperators[tok.text] {
				w.b.emitAnchor(tok.text, tok.text, tok.text)
				w.b.ops[tok.text] = true
			} else {
				w.b.emit(tok.text)
			}
			w.punct(i)
		}
		if tok.text == "else" && s.text(i+1) != "{" {
			w.hold(true)
		}
	}
	return w.b.finish()
}

// params emits the patterns among the parameters of f as a statement before
// the body: ({ bid, ask }: Quote) binds the properties bid and ask to the
// names the body reads, as const { bid, ask } = q does in the body, so a
// function that destructures them in the other roles is another function.
func (w *tsNearWalker) params(f tsFunc, locals *tsLocals) {
	s := w.s
	if s.text(f.paramsOpen) != "(" || s.match[f.paramsOpen] < f.paramsOpen {
		return
	}
	emitted := false
	for j := f.paramsOpen + 1; j < s.match[f.paramsOpen]; j++ {
		pattern := (s.text(j) == "{" || s.text(j) == "[") && (s.text(j-1) == "(" || s.text(j-1) == ",")
		if pattern && s.match[j] > j {
			for k := j; k <= s.match[j]; k++ {
				if s.toks[k].kind == tsIdent {
					k += s.emitName(w.b, k, locals)
				} else {
					w.b.emit(s.text(k))
				}
			}
			emitted = true
		}
		if s.match[j] > j {
			j = s.match[j]
		}
	}
	if emitted {
		w.endStmt()
	}
}

// tsNearWalker splits the body of a TypeScript function into statements.
type tsNearWalker struct {
	s *tsSource
	b *nearBodyBuilder
	// blocks holds, for every brace open and every statement a check or a
	// loop holds without braces, what a statement inside starts from and the
	// statement that opened it.
	blocks []tsBlock
	depth  int
	// head is set while the condition of a check or a loop that opens the
	// statement is read.
	head bool
	// scopes holds the statements a break leaves, by their order of
	// opening: true for a loop, which a continue leaves too, false for a
	// switch.
	scopes map[int]bool
}

type tsBlock struct {
	seed   uint64
	parent int
	inline bool
}

func (w *tsNearWalker) reopen() {
	top := w.blocks[len(w.blocks)-1]
	w.b.openSeeded(top.seed, top.parent)
}

// hold closes the open statement as one that holds the next ones: in braces,
// or inline, the one statement it holds without them.
func (w *tsNearWalker) hold(inline bool) {
	seed, id := w.b.closeStmt()
	w.blocks = append(w.blocks, tsBlock{seed: seed, parent: id, inline: inline})
	w.reopen()
}

// endStmt closes the open statement, and with it the statements without
// braces that hold it.
func (w *tsNearWalker) endStmt() {
	w.b.closeStmt()
	w.popInline()
	w.reopen()
}

func (w *tsNearWalker) popInline() {
	for len(w.blocks) > 1 && w.blocks[len(w.blocks)-1].inline {
		w.blocks = w.blocks[:len(w.blocks)-1]
	}
}

// markHead notes a check or a loop that opens a statement, and not the while
// that ends a do loop.
func (w *tsNearWalker) markHead(i int) {
	switch w.s.text(i) {
	case "if":
		w.head = w.head || w.b.fresh()
	case "for", "while":
		if w.b.fresh() && w.s.text(i-1) != "}" {
			w.head = true
			w.scopes[w.b.openID()] = true
		}
	case "do":
		if w.b.fresh() {
			w.scopes[w.b.openID()] = true
		}
	case "switch":
		if w.b.fresh() {
			w.scopes[w.b.openID()] = false
		}
	}
}

// markJump marks the statement a return, a throw, a break or a continue at
// i opens as a jump out of the function, or of the innermost loop or switch
// it leaves (tsNearWalker.scopes); a jump to a label leaves the function.
// A property of the name, gen.return(), reads a property, which keeps the
// statement in its place (Fixed) anyway.
func (w *tsNearWalker) markJump(i int) {
	if w.s.toks[i].kind != tsIdent {
		return
	}
	text := w.s.text(i)
	switch text {
	case "return", "throw":
		w.b.jump(-1)
		return
	case "break", "continue":
	default:
		return
	}
	if w.s.isIdent(i+1) && w.s.toks[i+1].line == w.s.toks[i].line {
		w.b.jump(-1)
		return
	}
	for k := len(w.blocks) - 1; k >= 0; k-- {
		if loop, scope := w.scopes[w.blocks[k].parent]; scope && (loop || text == "break") {
			w.b.jump(w.blocks[k].parent)
			return
		}
	}
	w.b.jump(-1)
}

func (w *tsNearWalker) punct(i int) {
	switch w.s.text(i) {
	case "(", "[":
		w.depth++
	case ")", "]":
		w.depth = max(0, w.depth-1)
		if w.head && w.depth == 0 {
			w.head = false
			if w.s.text(i+1) != "{" {
				w.hold(true)
			}
		}
	case ";":
		if w.depth == 0 {
			w.endStmt()
		}
	case "{":
		w.hold(false)
	case "}":
		w.b.closeStmt()
		w.popInline()
		if len(w.blocks) > 1 {
			w.blocks = w.blocks[:len(w.blocks)-1]
		}
		w.popInline()
		w.reopen()
	}
}

// tsLocals numbers the variables of a function by their first appearance in
// its body; a name it holds with -1 is a variable not seen yet.
type tsLocals struct {
	numbers map[string]int
	next    int
}

// number is the number of a variable, or of a field of a variable read as
// v.name, which stands in the roles as a variable of its own.
func (l *tsLocals) number(name string) int {
	num, known := l.numbers[name]
	if !known || num < 0 {
		num = l.next
		l.next++
		l.numbers[name] = num
	}
	return num
}

// emitName emits the name at i: a property after a dot as written, the key
// of an object pattern or literal, written or not (markShorthand), as a key
// (nearKey), though a variable may be called so, the name
// of a called function as an anchor, a variable by its number, a field read
// of a variable, v.name, as a variable of its own; it returns the number of
// the tokens after i it emitted too.
func (s *tsSource) emitName(b *nearBodyBuilder, i int, locals *tsLocals) int {
	name := s.text(i)
	key := s.text(i+1) == ":" && (s.text(i-1) == "{" || s.text(i-1) == ",")
	property := s.text(i-1) == "." || s.text(i-1) == "?." || key
	call := s.text(i+1) == "(" || s.text(i+1) == "?." && s.text(i+2) == "("
	_, local := locals.numbers[name]
	if s.shorthand[i] {
		// The key of { bid } is a property, as in { bid: bid }.
		b.emitKey(name)
		b.emit(":")
	}
	if !property && tsOperators[name] {
		b.ops[name] = true
	}
	switch {
	case property && call:
		// A property may be named like a keyword: set.delete(key).
		b.calls["."+name] = true
		b.emitAnchor(name, "."+name, nearCallMask)
	case key:
		b.emitKey(name)
	case property:
		b.emit(name)
	case name == "break" || name == "continue" || name == "return":
		b.emitAnchor(name, name, name)
	case (local || name == "this") && s.fieldRead(i):
		if name == "this" || s.reaches(i) {
			b.fix()
		}
		root := locals.number(name)
		field := locals.number(name + "." + s.text(i+2))
		b.field(field, root)
		b.emitVar(field, s.writes(i, i+3))
		return 2
	case tsKeywords[name]:
		b.emit(name)
	case tsConstantHolders[name] && s.fieldRead(i):
		value := name + "." + s.text(i+2)
		b.emitAnchor(value, value, nearLiteralMask)
		b.lits[value] = true
		return 2
	case local:
		if s.reaches(i) {
			b.fix()
		}
		b.emitVar(locals.number(name), s.writes(i, i+1))
	case call:
		b.calls[name] = true
		b.emitAnchor(name, name, nearCallMask)
	default:
		// A name from outside the function: a variable of the module, an
		// import, a global; but not a type a value is asserted to be.
		if s.text(i-1) != "as" {
			b.fix()
		}
		b.emit(name)
	}
	return 0
}

// tsConstantHolders are the objects whose properties a function reads as
// constants: Number.MAX_SAFE_INTEGER is a literal, as 9007199254740991 is.
var tsConstantHolders = map[string]bool{"Number": true, "Math": true}

// tsAssignments are the operators that write the name before them, but for
// ++ and --, which write it on its line only.
var tsAssignments = map[string]bool{
	"=": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true, "**=": true,
	"&&=": true, "||=": true, "??=": true, "<<=": true, ">>=": true, ">>>=": true,
	"&=": true, "|=": true, "^=": true,
}

// fieldRead reports whether the name at i reads a field, name.field, and
// calls no method.
func (s *tsSource) fieldRead(i int) bool {
	return s.text(i+1) == "." && s.isIdent(i+2) && s.text(i+3) != "(" && s.text(i+3) != "?."
}

// writes reports whether the name at i, whose tokens end before next, is
// written: declared, incremented in front, deleted from, or assigned,
// itself or at an index.
func (s *tsSource) writes(i, next int) bool {
	switch s.text(i - 1) {
	case "let", "const", "var", "delete":
		return true
	case "++", "--":
		if s.toks[i-1].line == s.toks[i].line {
			return true
		}
	}
	for s.text(next) == "[" && s.match[next] > next {
		next = s.match[next] + 1
	}
	if op := s.text(next); op == "++" || op == "--" {
		return s.toks[next].line == s.toks[next-1].line
	}
	return tsAssignments[s.text(next)]
}

// reaches reports whether the name at i reaches what is not the function's
// own: a property, which may be a getter, or an element of what it names,
// which another name may reach too, or what a loop or in reads of it. Only
// its length, read and nothing more, is its own.
func (s *tsSource) reaches(i int) bool {
	switch s.text(i + 1) {
	case ".", "?.":
		after := s.text(i + 3)
		return s.text(i+2) != "length" || s.writes(i, i+3) || after == "." || after == "?." || after == "["
	case "[":
		return true
	}
	return s.text(i-1) == "of" || s.text(i-1) == "in"
}

// effect reports whether the token at i may do what nothing proves
// independent of the statements around it: a call, a function made, an
// await or a yield, a tagged template or a template with an expression,
// whose names and calls the body does not see.
func (s *tsSource) effect(i int) bool {
	switch s.text(i) {
	case "=>", "function", "await", "yield", "new":
		return true
	case "(":
		prev := s.text(i - 1)
		return s.isIdent(i-1) || prev == "super" || prev == ")" || prev == "]" || prev == "?."
	}
	return s.toks[i].kind == tsTemplate && (s.isIdent(i-1) || strings.Contains(s.toks[i].text, "${"))
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
