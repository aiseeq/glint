package frontendrules

import (
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewFrontendErrorMessageMatchRule())
}

// FrontendErrorMessageMatchRule detects frontend code that decides what an
// error is by the wording of its message:
//
//	} catch (err) {
//	    const text = err instanceof Error ? err.message : String(err)
//	    if (text.includes('token expired')) logout()
//	}
//
// The wording belongs to whoever threw the error — a backend, a library, a
// browser — and changes with a translation, a rephrased message or a prefix
// added on the way. The branch then silently stops matching. An error code or
// a status the thrower sets on purpose is the contract to test.
//
// A message is followed from the error (err.message, a catch parameter, a
// name ending in err or error) through variables assigned from it and through
// a helper of the file it is handed to as the first argument. The parameter
// holds it inside the helper only: elsewhere the same name is another
// variable. It is matched when a branch tests it: includes, startsWith,
// endsWith, indexOf, match, search, a comparison with a string, a regular
// expression's test.
type FrontendErrorMessageMatchRule struct {
	*rules.BaseRule
	catchParam  *regexp.Regexp
	declaration *regexp.Regexp
	// functions are the helper declarations: a named function, an arrow
	// function bound to a name. Each is searched on its own, so a function
	// declared inside the value of a binding is found too.
	functions []*regexp.Regexp
}

// NewFrontendErrorMessageMatchRule creates the rule
func NewFrontendErrorMessageMatchRule() *FrontendErrorMessageMatchRule {
	return &FrontendErrorMessageMatchRule{
		BaseRule: rules.NewBaseRule(
			"frontend-error-message-match",
			"patterns",
			"Detects frontend code branching on the wording of an error message instead of a code or status",
			core.SeverityMedium,
		),
		catchParam:  regexp.MustCompile(`\bcatch\s*\(\s*([A-Za-z_$][\w$]*)|\.catch\s*\(\s*\(?\s*([A-Za-z_$][\w$]*)|\bon[A-Z]\w*Error\w*\s*[:=]\s*\(?\s*([A-Za-z_$][\w$]*)|\bon[Ee]rror\s*[:=]\s*\(?\s*([A-Za-z_$][\w$]*)`),
		declaration: regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)$`),
		functions: []*regexp.Regexp{
			regexp.MustCompile(`\bfunction\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)`),
			regexp.MustCompile(`\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(\s*([A-Za-z_$][\w$]*)`),
		},
	}
}

// AnalyzeFile reports the lines that test the wording of an error message.
func (r *FrontendErrorMessageMatchRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || patternkit.SkipFrontendPath(ctx) {
		return nil
	}
	code := separateDollars(helpers.FileJSCode(ctx))
	errorNames := r.errorNames(code)
	if len(errorNames) == 0 {
		return nil
	}
	names := wordAlternation(errorNames)
	// A cast names a type, generic ones with their arguments: Foo<A, B<C>>.
	messageOf := regexp.MustCompile(`(?:` + names + `|\(\s*` + names + `\s+as\s+(?:[\w$.<>]*<[\w$.<>]*(?:,\s*[\w$.<>]+)+|[\w$.<>]+)\s*\))\s*\??\.\s*message\b`)
	lineStarts := lineOffsets(code)
	marks := r.messageTexts(code, lineStarts, messageOf)

	// A name that holds a message where it stands is written between two
	// NULs by marks.rewrite; any other name is not a subject.
	subject := `(?:` + names + `\s*\??\.\s*message|\x00[^\x00]*\x00)`
	match := regexp.MustCompile(subject + `(?:\s*\??\.\s*(?:includes|startsWith|endsWith|indexOf|match|search)\s*\(` +
		`|\s*[!=]==?\s*['"` + "`" + `])` +
		`|['"` + "`" + `]\s*[!=]==?\s*` + subject +
		`|/[gimsuy]*\s*\.\s*test\s*\(\s*` + subject + `\s*\)`)

	scopes := newHelperScopes(marks.bodies)
	var violations []*core.Violation
	for i, line := range code {
		if !mayTestText(line) {
			continue
		}
		// typeof x === 'string' tests the kind of value, not its wording.
		// Blanking it keeps the offsets the scopes of the helpers go by.
		line = typeofOperand.ReplaceAllStringFunc(line, blank)
		line = marks.rewrite(line, lineStarts[i], scopes)
		if !match.MatchString(line) || ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "The branch is chosen by the wording of an error message — a rephrased or translated message silently stops matching")
		v.WithCode(strings.TrimSpace(ctx.Lines[i]))
		v.WithSuggestion("Branch on an error code or status the thrower sets on purpose")
		violations = append(violations, v)
	}
	return violations
}

func blank(s string) string { return strings.Repeat(" ", len(s)) }

// lineOffsets returns the offset of every line's first byte in the lines
// joined by newlines.
func lineOffsets(code []string) []int {
	starts := make([]int, len(code))
	offset := 0
	for i, line := range code {
		starts[i] = offset
		offset += len(line) + 1
	}
	return starts
}

var typeofOperand = regexp.MustCompile(`\btypeof\s+[A-Za-z_$][\w$.]*`)

// textTests are the words every form the rule matches contains: a string
// method, a comparison, a regular expression's test.
var textTests = []string{"includes", "startsWith", "endsWith", "indexOf", "match", "search", "==", "!=", "test"}

// mayTestText is the cheap filter in front of the per-file expression: a line
// without any of textTests cannot match it.
func mayTestText(line string) bool {
	for _, word := range textTests {
		if strings.Contains(line, word) {
			return true
		}
	}
	return false
}

// jsWord is one JS identifier inside a line.
var jsWord = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

// isErrorName reports a name errors go by: e, err, error, or a name ending in
// Err or Error. A name with $ is not one: $ is no word character.
func isErrorName(name string) bool {
	switch name {
	case "e", "err", "error":
		return true
	}
	return !strings.Contains(name, "$") && (strings.HasSuffix(name, "Err") || strings.HasSuffix(name, "Error"))
}

// errorNames returns the names errors go by in the file: catch parameters,
// onError callback parameters, and every name ending in err or error.
func (r *FrontendErrorMessageMatchRule) errorNames(code []string) []string {
	seen := make(map[string]bool)
	var names []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, line := range code {
		for _, m := range r.catchParam.FindAllStringSubmatch(line, -1) {
			for _, name := range m[1:] {
				add(name)
			}
		}
		for _, name := range jsWord.FindAllString(line, -1) {
			if isErrorName(name) {
				add(name)
			}
		}
	}
	return names
}

// textSymbol is what a name stands for: the first parameter of helper inside
// a body of the helper, else the variable name of the file.
type textSymbol struct{ helper, name string }

// textMarks are the symbols that hold the message of an error.
type textMarks struct {
	texts  map[textSymbol]bool
	bodies *helperBodies
	// names are the names that hold a message somewhere in the file.
	names nameIndex
}

// rewrite returns line, which starts at offset start of the file, with every
// name that holds a message there put between two NULs. Of names that
// overlap, as m and m$x do, the longest of those starting first is taken.
func (t *textMarks) rewrite(line string, start int, scopes *helperScopes) string {
	var spans [][2]int
	t.names.each(line, func(name string, at int) {
		if !t.texts[scopes.symbol(name, start+at)] {
			return
		}
		end := at + len(name)
		if n := len(spans); n > 0 && at < spans[n-1][1] {
			if at == spans[n-1][0] {
				spans[n-1][1] = end
			}
			return
		}
		spans = append(spans, [2]int{at, end})
	})
	var b strings.Builder
	last := 0
	for _, span := range spans {
		b.WriteString(line[last:span[0]])
		b.WriteByte(0)
		b.WriteString(line[span[0]:span[1]])
		b.WriteByte(0)
		last = span[1]
	}
	b.WriteString(line[last:])
	return b.String()
}

// messageTexts returns the symbols that hold the message of an error:
// variables assigned from a message or from another such symbol, and the
// first parameter of a helper the file calls with one. A name read inside a
// body of a helper whose first parameter it names is that parameter, so a
// message handed to the helper stays inside it.
//
// The names each declaration and each helper argument read are found once;
// marking a symbol then marks what reads it, so a chain of n names costs no n
// passes over the file.
func (r *FrontendErrorMessageMatchRule) messageTexts(code []string, lineStarts []int, messageOf *regexp.Regexp) *textMarks {
	bodies := r.helperDecls(code, lineStarts)
	type declarationMatch struct {
		name  string
		value string
		at    int // offset of the value in the file
	}
	var declarations []declarationMatch
	names := nameIndex{names: make(map[string]bool)}
	paramsOf := make(map[string][]string)
	for _, decl := range bodies.decls {
		paramsOf[decl.helper] = append(paramsOf[decl.helper], decl.param)
		names.add(decl.param)
	}
	for i, line := range code {
		if m := r.declaration.FindStringSubmatchIndex(line); m != nil {
			declarations = append(declarations, declarationMatch{name: line[m[2]:m[3]], value: line[m[4]:m[5]], at: lineStarts[i] + m[4]})
			names.add(line[m[2]:m[3]])
		}
	}
	calls := make(map[string]*regexp.Regexp, len(paramsOf))
	for helper := range paramsOf {
		calls[helper] = regexp.MustCompile(`\b` + regexp.QuoteMeta(helper) + `\s*\(`)
	}
	callLines := indexHelperCalls(code, calls)

	texts := make(map[textSymbol]bool)
	var queue []textSymbol
	mark := func(symbol textSymbol) {
		if !texts[symbol] {
			texts[symbol] = true
			queue = append(queue, symbol)
		}
	}
	// readers maps a symbol to the declarations whose value reads it.
	readers := make(map[textSymbol][]string)
	scopes := newHelperScopes(bodies)
	for _, declaration := range declarations {
		if messageOf.MatchString(declaration.value) {
			mark(textSymbol{name: declaration.name})
			continue
		}
		names.each(declaration.value, func(name string, at int) {
			symbol := scopes.symbol(name, declaration.at+at)
			readers[symbol] = append(readers[symbol], declaration.name)
		})
	}
	// all holds every helper call of the file and parents the call whose first
	// argument holds each one: a name inside an inner argument is inside the
	// outer ones too. argumentsOf maps a symbol to the innermost calls whose
	// first argument reads it.
	var all []helperCall
	var parents []int
	argumentsOf := make(map[textSymbol][]int)
	scopes = newHelperScopes(bodies)
	for i, line := range callLines {
		if line == nil {
			continue
		}
		line.messages = messageOf.FindAllStringIndex(code[i], -1)
		nest := newCallNest(line.calls, len(all))
		all = append(all, line.calls...)
		parents = append(parents, nest.parents...)
		names.each(code[i], func(name string, at int) {
			if call := nest.innermost(at); call >= 0 {
				symbol := scopes.symbol(name, lineStarts[i]+at)
				argumentsOf[symbol] = append(argumentsOf[symbol], call)
			}
		})
		for _, call := range line.calls {
			if spanHolds(line.messages, call.start, call.end) {
				mark(textSymbol{helper: call.helper})
			}
		}
	}
	// live returns the first call from call outwards whose helper parameter is
	// not marked yet, -1 when there is none. A call passed over stays passed
	// over, since marks are never taken back, so it jumps there next time.
	jump := make([]int, len(all))
	for i := range jump {
		jump[i] = i
	}
	dead := func(call int) bool { return texts[textSymbol{helper: all[call].helper}] }
	up := func(call int) int {
		if jump[call] != call {
			return jump[call]
		}
		return parents[call]
	}
	live := func(call int) int {
		found := call
		for found >= 0 && dead(found) {
			found = up(found)
		}
		for call >= 0 && call != found {
			next := up(call)
			jump[call] = found
			call = next
		}
		return found
	}
	for len(queue) > 0 {
		symbol := queue[0]
		queue = queue[1:]
		for _, reader := range readers[symbol] {
			mark(textSymbol{name: reader})
		}
		for _, call := range argumentsOf[symbol] {
			for call = live(call); call >= 0; call = live(parents[call]) {
				mark(textSymbol{helper: all[call].helper})
			}
		}
	}
	// A helper's symbol has no name of its own: its parameters are added.
	marks := &textMarks{texts: texts, bodies: bodies, names: nameIndex{names: make(map[string]bool)}}
	for symbol := range texts {
		marks.names.add(symbol.name)
		for _, param := range paramsOf[symbol.helper] {
			marks.names.add(param)
		}
	}
	return marks
}

// helperScopes tells, for offsets taken in increasing order, the helper
// whose first parameter a name is: the innermost body around the offset of a
// helper whose first parameter has that name.
type helperScopes struct {
	bodies *helperBodies
	next   int
	// byParam holds, for each parameter name, the bodies entered so far,
	// innermost last; those ended are dropped when the name is asked for.
	byParam map[string][]int
}

func newHelperScopes(bodies *helperBodies) *helperScopes {
	return &helperScopes{bodies: bodies, byParam: make(map[string][]int)}
}

// symbol returns what name at offset pos stands for.
func (s *helperScopes) symbol(name string, pos int) textSymbol {
	decls := s.bodies.scoped()
	for s.next < len(decls) && decls[s.next].start <= pos {
		param := decls[s.next].param
		s.byParam[param] = append(s.byParam[param], s.next)
		s.next++
	}
	open := s.byParam[name]
	for len(open) > 0 && decls[open[len(open)-1]].end <= pos {
		open = open[:len(open)-1]
	}
	s.byParam[name] = open
	if len(open) > 0 {
		return textSymbol{helper: decls[open[len(open)-1]].helper}
	}
	return textSymbol{name: name}
}

// nameIndex finds the names of a set in a text as the expressions of
// wordAlternation match them: a name with no '$' at an end is bounded by \b,
// for which '$' is no word character, so x$err reads err; an end at '$' is
// bounded by \B, so $m is read in ($m) and not in a$m.
type nameIndex struct {
	names   map[string]bool
	longest int
}

func (x *nameIndex) add(name string) {
	x.names[name] = true
	x.longest = max(x.longest, len(name))
}

// each calls found with every name of the set in text and its offset, in
// the order of the offsets. Inside a run of word characters and '$' a name
// starts at the run's start or right after a '$' and ends at the run's end or
// right before a '$', as \b and \B allow; a name that starts or ends with '$'
// only at the run's own start or end.
func (x *nameIndex) each(text string, found func(name string, at int)) {
	if len(x.names) == 0 {
		return
	}
	var dollars []int
	for i := 0; i < len(text); {
		if !identifierByte(text[i]) {
			i++
			continue
		}
		start := i
		for i < len(text) && identifierByte(text[i]) {
			i++
		}
		end := i
		dollars = dollars[:0]
		for k := start; k < end; k++ {
			if text[k] == '$' {
				dollars = append(dollars, k)
			}
		}
		x.run(text, start, end, dollars, found)
	}
}

// run finds the names of the run text[start:end] whose '$' are at dollars.
func (x *nameIndex) run(text string, start, end int, dollars []int, found func(name string, at int)) {
	check := func(from, to int) {
		if name := text[from:to]; x.names[name] {
			found(name, from)
		}
	}
	for k := -1; k < len(dollars); k++ {
		from := start
		if k >= 0 {
			from = dollars[k] + 1
			if from == end || text[from] == '$' {
				continue
			}
		}
		for _, to := range dollars[k+1:] {
			if to-from > x.longest {
				break
			}
			if to > from && text[to-1] != '$' {
				check(from, to)
			}
		}
		if end-from <= x.longest {
			check(from, end)
		}
	}
}

func identifierByte(c byte) bool {
	return c == '$' || patternkit.IsWordChar(c)
}

// callNest pairs the helper calls of a line, in the order of their first
// arguments, with the calls whose first argument holds them.
type callNest struct {
	calls   []helperCall
	offset  int
	parents []int
	stack   []int
	next    int
}

// newCallNest indexes calls numbered from offset on. The first arguments of
// a line come from one pairing of its brackets, so two of them either nest or
// do not meet.
func newCallNest(calls []helperCall, offset int) *callNest {
	slices.SortStableFunc(calls, func(a, b helperCall) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return b.end - a.end
	})
	nest := &callNest{calls: calls, offset: offset, parents: make([]int, len(calls))}
	var stack []int
	for k, call := range calls {
		for len(stack) > 0 && calls[stack[len(stack)-1]].end <= call.start {
			stack = stack[:len(stack)-1]
		}
		nest.parents[k] = -1
		if len(stack) > 0 {
			nest.parents[k] = offset + stack[len(stack)-1]
		}
		stack = append(stack, k)
	}
	return nest
}

// innermost returns the innermost call whose first argument holds offset at,
// -1 for none. Offsets come in increasing order.
func (n *callNest) innermost(at int) int {
	for n.next < len(n.calls) && n.calls[n.next].start <= at {
		n.pop(n.calls[n.next].start + 1)
		n.stack = append(n.stack, n.next)
		n.next++
	}
	n.pop(at + 1)
	if len(n.stack) == 0 {
		return -1
	}
	return n.offset + n.stack[len(n.stack)-1]
}

func (n *callNest) pop(at int) {
	for len(n.stack) > 0 && n.calls[n.stack[len(n.stack)-1]].end < at {
		n.stack = n.stack[:len(n.stack)-1]
	}
}

// helperDecl is a declaration of a helper with its first parameter. Its body
// is the code from the '(' of the parameters at start to end, exclusive; end
// is -1 when no body is found, as for an overload's signature.
type helperDecl struct {
	helper, param string
	start, end    int
	arrow         bool
}

// helperDecls returns the helper declarations of the file in the order of
// their offsets.
func (r *FrontendErrorMessageMatchRule) helperDecls(code []string, lineStarts []int) *helperBodies {
	bodies := &helperBodies{lines: code}
	bodies.scoped = sync.OnceValue(bodies.withBodies)
	for i, line := range code {
		type found struct {
			m     []int
			arrow bool
		}
		var all []found
		for k, re := range r.functions {
			for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
				all = append(all, found{m: m, arrow: k > 0})
			}
		}
		slices.SortStableFunc(all, func(a, b found) int { return a.m[0] - b.m[0] })
		for _, f := range all {
			start := lineStarts[i] + strings.LastIndexByte(line[:f.m[4]], '(')
			bodies.decls = append(bodies.decls, helperDecl{helper: line[f.m[2]:f.m[3]], param: line[f.m[4]:f.m[5]], start: start, arrow: f.arrow})
		}
	}
	return bodies
}

// helperBodies finds where the bodies of the helpers end in the file's code
// joined by newlines, its brackets paired once, when a name is first looked
// up in them.
type helperBodies struct {
	lines []string
	decls []helperDecl
	// scoped returns the declarations that have a body, by start: a
	// declaration found later on a line starts later, as no name or '(' of
	// one comes between "const name = (" and its parameter.
	scoped   func() []helperDecl
	code     string
	brackets *patternkit.JsBrackets
}

func (h *helperBodies) withBodies() []helperDecl {
	var bodies []helperDecl
	h.code = strings.Join(h.lines, "\n")
	h.brackets = patternkit.NewJsBrackets(h.code)
	for _, decl := range h.decls {
		if decl.end = h.end(decl.start, decl.arrow); decl.end >= 0 {
			bodies = append(bodies, decl)
		}
	}
	return bodies
}

// end returns the end of the body of the function whose parameters open at
// paren, -1 when there is none. A body in braces ends after its closing
// brace, an arrow's expression at the end of its line, at a ';' or ',' or at
// a bracket it does not open; brackets it opens it passes whole.
func (h *helperBodies) end(paren int, arrow bool) int {
	closing, ok := h.brackets.Closing(paren)
	if !ok {
		return -1
	}
	pos := h.skipSpace(closing + 1)
	switch {
	case h.at(pos, ":"):
		if pos = h.afterReturnType(pos, arrow); pos < 0 {
			return -1
		}
	case arrow:
		if !h.at(pos, "=>") {
			return -1
		}
		pos += 2
	}
	pos = h.skipSpace(pos)
	if h.at(pos, "{") {
		return h.after(pos)
	}
	if !arrow {
		return -1
	}
	for pos < len(h.code) {
		switch h.code[pos] {
		case '(', '[', '{':
			pos = h.after(pos)
		case ')', ']', '}', ';', ',', '\n':
			return pos
		default:
			pos++
		}
	}
	return pos
}

// afterReturnType returns, for a return type whose ':' is at pos, where the body
// begins: the '{' of a function's body, past the "=>" of an arrow's; -1 when
// the code shows it is no function. A '{' after ':', '<', '|', '&' or ',' is
// a type of an object.
func (h *helperBodies) afterReturnType(pos int, arrow bool) int {
	var last byte
	for pos < len(h.code) {
		c := h.code[pos]
		switch {
		case c == '{' && strings.IndexByte(":<|&,", last) < 0:
			if arrow {
				return -1
			}
			return pos
		case c == '(' || c == '[' || c == '{':
			pos = h.after(pos)
			last = h.code[pos-1]
			continue
		case c == '=' && h.at(pos, "=>"):
			if arrow {
				return pos + 2
			}
		case c == '=' || c == ';' || c == ')' || c == ']' || c == '}':
			return -1
		}
		if !patternkit.IsRegexpSpace(c) {
			last = c
		}
		pos++
	}
	return -1
}

// after returns the offset after the bracket that closes the one at open,
// the end of the code when none does.
func (h *helperBodies) after(open int) int {
	if closing, ok := h.brackets.Closing(open); ok {
		return closing + 1
	}
	return len(h.code)
}

func (h *helperBodies) at(pos int, s string) bool {
	return strings.HasPrefix(h.code[pos:], s)
}

func (h *helperBodies) skipSpace(pos int) int {
	for pos < len(h.code) && patternkit.IsRegexpSpace(h.code[pos]) {
		pos++
	}
	return pos
}

// spanHolds reports whether one of matches, sorted and not overlapping, lies
// within [start, end).
func spanHolds(matches [][]int, start, end int) bool {
	i := sort.Search(len(matches), func(i int) bool { return matches[i][0] >= start })
	return i < len(matches) && matches[i][1] <= end
}

// helperCallLine holds the helper calls of a line and the offsets where the
// line reads an error message.
type helperCallLine struct {
	calls    []helperCall
	messages [][]int
}

// helperCall is a call of a helper with the span of its first argument.
type helperCall struct {
	helper     string
	start, end int
}

type helperCallTrieNode struct {
	next    map[byte]int
	failure int
	output  []string
}

// indexHelperCalls finds every call of a helper on every line: one pass of
// the helper names' automaton over the line, and the line's brackets paired
// once for the ends of the first arguments.
func indexHelperCalls(code []string, calls map[string]*regexp.Regexp) []*helperCallLine {
	trie := helperCallTrie(calls)
	lines := make([]*helperCallLine, len(code))
	for lineIndex, line := range code {
		var brackets *patternkit.JsBrackets
		state := 0
		for end := 0; end < len(line); end++ {
			for state != 0 {
				if _, ok := trie[state].next[line[end]]; ok {
					break
				}
				state = trie[state].failure
			}
			if next, ok := trie[state].next[line[end]]; ok {
				state = next
			}
			for _, name := range trie[state].output {
				start := end + 1 - len(name)
				if start < 0 || patternkit.IsWordChar(line[start]) == (start > 0 && patternkit.IsWordChar(line[start-1])) {
					continue
				}
				paren, ok := helperCallParen(line, start, end, calls[name])
				if !ok {
					continue
				}
				if brackets == nil {
					brackets = patternkit.NewJsBrackets(line)
					lines[lineIndex] = &helperCallLine{}
				}
				lines[lineIndex].calls = append(lines[lineIndex].calls, helperCall{helper: name, start: paren + 1, end: brackets.FirstItemEnd(paren)})
			}
		}
	}
	return lines
}

func helperCallTrie(calls map[string]*regexp.Regexp) []helperCallTrieNode {
	trie := []helperCallTrieNode{{next: make(map[byte]int)}}
	for _, name := range slices.Sorted(maps.Keys(calls)) {
		state := 0
		for i := 0; i < len(name); i++ {
			c := name[i]
			next, ok := trie[state].next[c]
			if !ok {
				next = len(trie)
				trie[state].next[c] = next
				trie = append(trie, helperCallTrieNode{next: make(map[byte]int)})
			}
			state = next
		}
		trie[state].output = append(trie[state].output, name)
	}
	queue := make([]int, 0, len(trie))
	for _, child := range trie[0].next {
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for char, child := range trie[state].next {
			fallback := trie[state].failure
			for fallback != 0 {
				if _, ok := trie[fallback].next[char]; ok {
					break
				}
				fallback = trie[fallback].failure
			}
			if next, ok := trie[fallback].next[char]; ok && next != child {
				trie[child].failure = next
			}
			trie[child].output = append(trie[child].output, trie[trie[child].failure].output...)
			queue = append(queue, child)
		}
	}
	return trie
}

// helperCallParen returns the '(' of the call of the helper whose name spans
// line[start:end+1], when call's expression matches there.
func helperCallParen(line string, start, end int, call *regexp.Regexp) (int, bool) {
	paren := end + 1
	for paren < len(line) && regexpSpaceByte(line[paren]) {
		paren++
	}
	if paren >= len(line) || line[paren] != '(' {
		return 0, false
	}
	prefixStart := start
	if prefixStart > 0 {
		prefixStart--
	}
	prefix := line[prefixStart : paren+1]
	m := call.FindStringIndex(prefix)
	if m == nil || m[0] != start-prefixStart || m[1] != len(prefix) {
		return 0, false
	}
	return paren, true
}

func regexpSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// wordAlternation matches any of names as a whole identifier. Like \b it
// takes '$' for no word character, so x$err holds err; a name that starts or
// ends with '$' is bounded there by \B instead: $m is a name of its own, and
// a$m does not hold it. \B also passes between two '$', which separateDollars
// leaves none of.
func wordAlternation(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = wordBoundary(name[0]) + regexp.QuoteMeta(name) + wordBoundary(name[len(name)-1])
	}
	return `(?:` + strings.Join(quoted, "|") + `)`
}

func wordBoundary(c byte) string {
	if patternkit.IsWordChar(c) {
		return `\b`
	}
	return `\B`
}

// separateDollars returns code with the first '$' of every "$$" made a word
// character. Neither \b nor \B tells '$' from '$', so in $$m an expression
// for the name $m would find it; in _$m it does not. Every name the rule
// follows comes from the same lines, so a name $$m reads _$m too.
func separateDollars(code []string) []string {
	var out []string
	for i, line := range code {
		if !strings.Contains(line, "$$") {
			continue
		}
		if out == nil {
			out = slices.Clone(code)
		}
		b := []byte(line)
		for k := 0; k+1 < len(b); k++ {
			if b[k] == '$' && b[k+1] == '$' {
				b[k] = '_'
			}
		}
		out[i] = string(b)
	}
	if out == nil {
		return code
	}
	return out
}
