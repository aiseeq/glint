package frontendrules

import (
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

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
// a helper of the file it is handed to as the first argument. It is matched
// when a branch tests it: includes, startsWith, endsWith, indexOf, match,
// search, a comparison with a string, a regular expression's test.
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
	texts := r.messageTexts(code, messageOf)

	subject := `(?:` + names + `\s*\??\.\s*message`
	if len(texts) > 0 {
		subject += `|` + wordAlternation(texts)
	}
	subject += `)`
	match := regexp.MustCompile(subject + `(?:\s*\??\.\s*(?:includes|startsWith|endsWith|indexOf|match|search)\s*\(` +
		`|\s*[!=]==?\s*['"` + "`" + `])` +
		`|['"` + "`" + `]\s*[!=]==?\s*` + subject +
		`|/[gimsuy]*\s*\.\s*test\s*\(\s*` + subject + `\s*\)`)

	var violations []*core.Violation
	for i, line := range code {
		if !mayTestText(line) {
			continue
		}
		// typeof x === 'string' tests the kind of value, not its wording.
		line = typeofOperand.ReplaceAllString(line, "")
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

// messageTexts returns the names that hold the message of an error: variables
// assigned from a message or from another such name, and the first parameter
// of a helper the file calls with a message.
//
// The names each declaration and each helper argument read are found once;
// marking a name then marks what reads it, so a chain of n names costs no n
// passes over the file.
func (r *FrontendErrorMessageMatchRule) messageTexts(code []string, messageOf *regexp.Regexp) []string {
	helperParams := r.helperParams(code)
	type declarationMatch struct {
		name  string
		value string
	}
	declarations := make([]declarationMatch, len(code))
	names := nameIndex{names: make(map[string]bool, len(helperParams))}
	for _, param := range helperParams {
		names.add(param)
	}
	for i, line := range code {
		if m := r.declaration.FindStringSubmatch(line); m != nil {
			declarations[i] = declarationMatch{name: m[1], value: m[2]}
			names.add(m[1])
		}
	}
	calls := make(map[string]*regexp.Regexp, len(helperParams))
	for helper := range helperParams {
		calls[helper] = regexp.MustCompile(`\b` + regexp.QuoteMeta(helper) + `\s*\(`)
	}
	callLines := indexHelperCalls(code, calls)

	texts := make(map[string]bool)
	var queue []string
	mark := func(name string) {
		if !texts[name] {
			texts[name] = true
			queue = append(queue, name)
		}
	}
	// readers maps a name to the declarations whose value reads it.
	readers := make(map[string][]string)
	for _, declaration := range declarations {
		if declaration.name == "" {
			continue
		}
		if messageOf.MatchString(declaration.value) {
			mark(declaration.name)
			continue
		}
		names.each(declaration.value, func(name string, _ int) {
			readers[name] = append(readers[name], declaration.name)
		})
	}
	// all holds every helper call of the file and parents the call whose first
	// argument holds each one: a name inside an inner argument is inside the
	// outer ones too. argumentsOf maps a name to the innermost calls whose
	// first argument reads it.
	var all []helperCall
	var parents []int
	argumentsOf := make(map[string][]int)
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
				argumentsOf[name] = append(argumentsOf[name], call)
			}
		})
		for _, call := range line.calls {
			if spanHolds(line.messages, call.start, call.end) {
				mark(helperParams[call.helper])
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
	dead := func(call int) bool { return texts[helperParams[all[call].helper]] }
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
		name := queue[0]
		queue = queue[1:]
		for _, reader := range readers[name] {
			mark(reader)
		}
		for _, call := range argumentsOf[name] {
			for call = live(call); call >= 0; call = live(parents[call]) {
				mark(helperParams[all[call].helper])
			}
		}
	}
	return slices.Sorted(maps.Keys(texts))
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

// helperParams maps each helper the file declares to its first parameter. A
// later declaration of a name replaces an earlier one.
func (r *FrontendErrorMessageMatchRule) helperParams(code []string) map[string]string {
	params := make(map[string]string)
	for _, line := range code {
		var found [][]int
		for _, re := range r.functions {
			found = append(found, re.FindAllStringSubmatchIndex(line, -1)...)
		}
		slices.SortStableFunc(found, func(a, b []int) int { return a[0] - b[0] })
		for _, m := range found {
			params[line[m[2]:m[3]]] = line[m[4]:m[5]]
		}
	}
	return params
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
