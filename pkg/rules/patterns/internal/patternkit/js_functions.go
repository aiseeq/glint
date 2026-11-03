package patternkit

import (
	"sort"
	"strings"
	"unicode"
)

// JsFunctions answers FunctionAtBrace for every '{' of a file without walking
// back over the same code again for each brace. One pass from left to right
// finds where each brace's Header starts, and the regexes FunctionAtBrace runs
// on the header are answered from positions collected in that pass, so a long
// header (one that runs back over nested brackets) costs no more than a short
// one.
type JsFunctions struct {
	code   string
	braces []jsBraceHeader
	// parens are the '(' and ')' offsets in order, each with the offset of the
	// last byte before it that \s does not match (-1 at the start).
	parens []jsParen
	equals []int
	colons []int
	// closeColons are the ')' that \s* and a ':' follow: "): T".
	closeColons []jsCloseColon
	words       []jsFunctionWord
	wordsDone   bool
	routes      *jsColonRoutes
	names       map[int]string
}

type jsBraceHeader struct {
	pos      int // offset of the '{'
	start    int // where Header starts
	from, to int // the header without surrounding spaces, as Header returns it
	function bool
}

type jsParen struct{ pos, before int }

type jsCloseColon struct{ close, colon int }

// jsFunctionWord is a "function" keyword that jsNamedFunction matches at,
// with the name it captures.
type jsFunctionWord struct{ pos, name, end int }

// jsColonRoutes holds, for the ':' that start a binding's value in
// jsArrowBinding, what can follow them; see arrowValue.
type jsColonRoutes struct {
	parens []jsColonRoute // ':' that an "(" value follows, at offset value
	colons []jsColonRoute // ':' whose identifier value a ':' follows, at offset value
}

type jsColonRoute struct{ pos, value int }

// Functions indexes the function bodies of the file.
func (f JsFlat) Functions() *JsFunctions {
	code := f.Code
	x := &JsFunctions{code: code}
	// openers hold, for each open bracket, where Header stops before it.
	var openers []int
	// stop is where Header, walking back from the current offset, stops: the
	// offset of the boundary before its start, -1 at the start of the file.
	stop := -1
	lastNonSpace, lastEqual := -1, -1
	lastCloseColon := jsCloseColon{-1, -1}
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch c {
		case '{':
			x.braces = append(x.braces, x.header(i, stop+1, lastEqual, lastCloseColon))
			openers = append(openers, stop)
			stop = i
		case '(', '[':
			if c == '(' {
				x.parens = append(x.parens, jsParen{i, lastNonSpace})
			}
			openers = append(openers, stop)
			stop = i
		case ')', ']', '}':
			if c == ')' {
				x.parens = append(x.parens, jsParen{i, lastNonSpace})
			}
			matched := len(openers) > 0
			before := -1
			if matched {
				before = openers[len(openers)-1]
				openers = openers[:len(openers)-1]
			}
			switch {
			case c == '}':
				stop = i
			case matched:
				// Header passes a bracketed group whole and goes on before it.
				stop = before
			default:
				// An unmatched closer keeps Header in brackets to the start.
				stop = -1
			}
		case ';', '\n':
			stop = i
		case '=':
			x.equals = append(x.equals, i)
			lastEqual = i
		case ':':
			x.colons = append(x.colons, i)
			if lastNonSpace >= 0 && code[lastNonSpace] == ')' {
				lastCloseColon = jsCloseColon{lastNonSpace, i}
				x.closeColons = append(x.closeColons, lastCloseColon)
			}
		}
		if !IsRegexpSpace(c) {
			lastNonSpace = i
		}
	}
	return x
}

// header reads the header of the brace at pos the way FunctionAtBrace does:
// trimmed by strings.TrimSpace, not a control statement, and ending the way
// jsFuncHeader requires.
func (x *JsFunctions) header(pos, start, lastEqual int, lastCloseColon jsCloseColon) jsBraceHeader {
	raw := x.code[start:pos]
	left := strings.TrimLeftFunc(raw, unicode.IsSpace)
	from := start + len(raw) - len(left)
	to := from + len(strings.TrimRightFunc(left, unicode.IsSpace))
	h := jsBraceHeader{pos: pos, start: start, from: from, to: to}
	if from == to || x.controlHeader(from, to) {
		return h
	}
	head := x.code[from:to]
	switch {
	case strings.HasSuffix(head, "=>"), strings.HasSuffix(head, ")"):
		h.function = true
	default:
		// `\)\s*:[^=]*$`: a ')' then a ':' with no '=' after it.
		cc := lastCloseColon
		h.function = cc.close >= from && cc.colon > lastEqual
	}
	return h
}

// controlHeader is JsControlHeader on code[from:to].
func (x *JsFunctions) controlHeader(from, to int) bool {
	head := x.code[from:to]
	switch head {
	case "try", "finally", "do":
		return true
	}
	if strings.HasPrefix(head, "else") && (len(head) == 4 || !IsWordChar(head[4])) {
		return true
	}
	for _, keyword := range []string{"if", "for", "while", "switch", "catch", "with"} {
		if strings.HasPrefix(head, keyword) {
			open := x.skipSpace(from+len(keyword), to)
			return open < to && x.code[open] == '('
		}
	}
	return false
}

// AtBrace is FunctionAtBrace for the '{' at brace.
func (x *JsFunctions) AtBrace(brace int) (JsFunc, bool) {
	i := sort.Search(len(x.braces), func(i int) bool { return x.braces[i].pos >= brace })
	if i == len(x.braces) || x.braces[i].pos != brace || !x.braces[i].function {
		return JsFunc{}, false
	}
	h := x.braces[i]
	if x.names == nil {
		x.names = make(map[int]string)
	}
	name, ok := x.names[brace]
	if !ok {
		name = x.name(h.from, h.to)
		x.names[brace] = name
	}
	return JsFunc{Brace: brace, Start: h.start, Name: name}, true
}

// name is the first of jsNamedFunction, jsMethodHeader and jsArrowBinding
// that matches code[from:to], as FunctionAtBrace takes it.
func (x *JsFunctions) name(from, to int) string {
	if name, ok := x.namedFunction(from, to); ok {
		return name
	}
	if name, ok := x.methodName(from, to); ok {
		return name
	}
	if name, ok := x.arrowBinding(from, to); ok {
		return name
	}
	return ""
}

// namedFunction is jsNamedFunction: the leftmost "function" in the header
// that a name follows.
func (x *JsFunctions) namedFunction(from, to int) (string, bool) {
	if !x.wordsDone {
		x.wordsDone = true
		for i := 0; ; {
			at := strings.Index(x.code[i:], "function")
			if at < 0 {
				break
			}
			pos := i + at
			i = pos + len("function")
			if pos > 0 && IsWordChar(x.code[pos-1]) {
				continue
			}
			name := x.skipSpace(i, len(x.code))
			if name < len(x.code) && x.code[name] == '*' {
				name = x.skipSpace(name+1, len(x.code))
			}
			if name < len(x.code) && jsIdentStart(x.code[name]) {
				x.words = append(x.words, jsFunctionWord{pos, name, x.identEnd(name)})
			}
		}
	}
	// The name after one keyword ends before the next keyword's name, so the
	// first keyword in the header is the leftmost match if any is.
	i := sort.Search(len(x.words), func(i int) bool { return x.words[i].pos >= from })
	if i < len(x.words) && x.words[i].name < to {
		return x.code[x.words[i].name:x.words[i].end], true
	}
	return "", false
}

var (
	jsMethodModifiers  = []string{"export", "default", "public", "private", "protected", "static", "async", "override", "get", "set"}
	jsBindingModifiers = []string{"export", "const", "let", "var", "public", "private", "protected", "static", "readonly"}
)

// modifiers returns the offsets where the header's identifier may start after
// zero, one, ... of the leading `(?:modifier\s+)` repeats, most repeats last.
func (x *JsFunctions) modifiers(from, to int, words []string) []int {
	starts := []int{from}
	for pos := from; ; {
		next := -1
		for _, word := range words {
			end := pos + len(word)
			if strings.HasPrefix(x.code[pos:to], word) && end < to && IsRegexpSpace(x.code[end]) {
				next = x.skipSpace(end, to)
				break
			}
		}
		if next < 0 {
			return starts
		}
		starts = append(starts, next)
		pos = next
	}
}

// methodName is jsMethodHeader: name \s* <generic>? \s* ( at the start.
func (x *JsFunctions) methodName(from, to int) (string, bool) {
	starts := x.modifiers(from, to, jsMethodModifiers)
	for k := len(starts) - 1; k >= 0; k-- {
		start := starts[k]
		if start >= to || !jsIdentStart(x.code[start]) {
			continue
		}
		end := x.identEnd(start)
		next := x.skipSpace(end, to)
		if next >= to {
			continue
		}
		if x.code[next] == '(' {
			return x.code[start:end], true
		}
		if x.code[next] != '<' {
			continue
		}
		// `<[^()]*>\s*\(`: the first paren after '<' opens, and the last
		// non-space before it is a '>' after the '<'.
		i := sort.Search(len(x.parens), func(i int) bool { return x.parens[i].pos > next })
		if i < len(x.parens) && x.parens[i].pos < to && x.code[x.parens[i].pos] == '(' {
			before := x.parens[i].before
			if before > next && x.code[before] == '>' {
				return x.code[start:end], true
			}
		}
	}
	return "", false
}

// arrowBinding is jsArrowBinding:
//
//	modifiers name \s* (:[^=]*)? [=:] \s* (async\b\s*)? ( \(.*\) | ident ) \s* (:.*)? =>
//
// The value after [=:] is checked by arrowValue for each place [=:] may take.
func (x *JsFunctions) arrowBinding(from, to int) (string, bool) {
	if to-from < 2 || x.code[to-2:to] != "=>" {
		return "", false
	}
	arrow := to - 2
	starts := x.modifiers(from, to, jsBindingModifiers)
	for k := len(starts) - 1; k >= 0; k-- {
		start := starts[k]
		if start >= to || !jsIdentStart(x.code[start]) {
			continue
		}
		end := x.identEnd(start)
		sep := x.skipSpace(end, to)
		if sep >= to {
			continue
		}
		var ok bool
		switch x.code[sep] {
		case '=':
			ok = x.arrowValueFits(x.arrowValue(sep), arrow)
		case ':':
			ok = x.typedArrowBinding(sep, arrow, to)
		}
		if ok {
			return x.code[start:end], true
		}
	}
	return "", false
}

// typedArrowBinding checks `(:[^=]*)?[=:]` from the ':' at sep: [=:] is sep
// itself, a later ':' before the first '=', or that '='.
func (x *JsFunctions) typedArrowBinding(sep, arrow, to int) bool {
	equal := -1
	if i := sort.SearchInts(x.equals, sep+1); i < len(x.equals) && x.equals[i] < to {
		equal = x.equals[i]
	}
	colonsEnd := to
	if equal >= 0 {
		colonsEnd = equal
	}
	routes := x.colonRoutes()
	// A '(' value fits for any ')' after it, so the earliest '(' decides.
	parenValue := -1
	if i := sort.Search(len(routes.parens), func(i int) bool { return routes.parens[i].pos >= sep }); i < len(routes.parens) && routes.parens[i].pos < colonsEnd {
		parenValue = routes.parens[i].value
	} else if equal >= 0 {
		parenValue = x.arrowValue(equal).paren
	}
	if parenValue >= 0 && x.parenValueFits(parenValue, arrow) {
		return true
	}
	// An identifier value then ':' — the earliest such ':' decides.
	if i := sort.Search(len(routes.colons), func(i int) bool { return routes.colons[i].pos >= sep }); i < len(routes.colons) && routes.colons[i].pos < colonsEnd {
		if routes.colons[i].value < arrow {
			return true
		}
	} else if equal >= 0 {
		if v := x.arrowValue(equal); v.typed >= 0 && v.typed < arrow {
			return true
		}
	}
	// An identifier value right before "=>": only the last place before the
	// arrow can have it, since each value ends before the next place.
	last := -1
	if equal >= 0 && equal < arrow {
		last = equal
	} else if i := sort.SearchInts(x.colons, min(colonsEnd, arrow)) - 1; i >= 0 && x.colons[i] >= sep {
		last = x.colons[i]
	}
	if last >= 0 {
		v := x.arrowValue(last)
		return v.ident[0] == arrow || v.ident[1] == arrow
	}
	return false
}

// jsArrowValue is what `\s*(async\b\s*)?(\(|ident)` finds after a [=:]: the
// offset of a '(' value, and for each identifier value the first non-space
// after it, -1 where there is none.
type jsArrowValue struct {
	paren int
	ident [2]int
	typed int // the smallest of ident that is a ':'
}

func (x *JsFunctions) arrowValue(sep int) jsArrowValue {
	v := jsArrowValue{paren: -1, ident: [2]int{-1, -1}, typed: -1}
	n := len(x.code)
	value := func(at, slot int) {
		if at >= n {
			return
		}
		switch {
		case x.code[at] == '(':
			v.paren = at
		case jsIdentStart(x.code[at]):
			after := x.skipSpace(x.identEnd(at), n)
			v.ident[slot] = after
			if after < n && x.code[after] == ':' && (v.typed < 0 || after < v.typed) {
				v.typed = after
			}
		}
	}
	first := x.skipSpace(sep+1, n)
	if strings.HasPrefix(x.code[first:], "async") && (first+5 == n || !IsWordChar(x.code[first+5])) {
		value(x.skipSpace(first+5, n), 1)
	}
	value(first, 0)
	return v
}

// arrowValueFits checks the value after one [=:] against the arrow at the
// header's end.
func (x *JsFunctions) arrowValueFits(v jsArrowValue, arrow int) bool {
	if v.paren >= 0 && x.parenValueFits(v.paren, arrow) {
		return true
	}
	return v.ident[0] == arrow || v.ident[1] == arrow || v.typed >= 0 && v.typed < arrow
}

// parenValueFits is `\(.*\)\s*(:.*)?=>$` from the '(' at open: some ')'
// after it is followed by the arrow or by a ':' before the arrow.
func (x *JsFunctions) parenValueFits(open, arrow int) bool {
	before := arrow - 1
	for before > open && IsRegexpSpace(x.code[before]) {
		before--
	}
	if before > open && x.code[before] == ')' {
		return true
	}
	i := sort.Search(len(x.closeColons), func(i int) bool { return x.closeColons[i].close > open })
	return i < len(x.closeColons) && x.closeColons[i].colon < arrow
}

func (x *JsFunctions) colonRoutes() *jsColonRoutes {
	if x.routes != nil {
		return x.routes
	}
	x.routes = &jsColonRoutes{}
	for _, colon := range x.colons {
		v := x.arrowValue(colon)
		if v.paren >= 0 {
			x.routes.parens = append(x.routes.parens, jsColonRoute{colon, v.paren})
		}
		if v.typed >= 0 {
			x.routes.colons = append(x.routes.colons, jsColonRoute{colon, v.typed})
		}
	}
	return x.routes
}

func (x *JsFunctions) skipSpace(pos, to int) int {
	for pos < to && IsRegexpSpace(x.code[pos]) {
		pos++
	}
	return pos
}

func (x *JsFunctions) identEnd(pos int) int {
	pos++
	for pos < len(x.code) && (IsWordChar(x.code[pos]) || x.code[pos] == '$') {
		pos++
	}
	return pos
}

func jsIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
