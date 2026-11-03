package frontendrules

import (
	"maps"
	"regexp"
	"slices"
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
	function    *regexp.Regexp
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
		function:    regexp.MustCompile(`\bfunction\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)|\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(\s*([A-Za-z_$][\w$]*)`),
	}
}

// AnalyzeFile reports the lines that test the wording of an error message.
func (r *FrontendErrorMessageMatchRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || patternkit.SkipFrontendPath(ctx) {
		return nil
	}
	code := helpers.FileJSCode(ctx)
	errorNames := r.errorNames(code)
	if len(errorNames) == 0 {
		return nil
	}
	names := alternation(errorNames)
	messageOf := regexp.MustCompile(`(?:\b(?:` + names + `)|\(\s*(?:` + names + `)\s+as\s+[\w$.<>]+\s*\))\s*\??\.\s*message\b`)
	texts := r.messageTexts(code, messageOf)

	subject := `(?:\b(?:` + names + `)\s*\??\.\s*message`
	if len(texts) > 0 {
		subject += `|\b(?:` + alternation(texts) + `)\b`
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
func (r *FrontendErrorMessageMatchRule) messageTexts(code []string, messageOf *regexp.Regexp) []string {
	texts := make(map[string]bool)
	helperParams := make(map[string]string)
	for _, line := range code {
		for _, m := range r.function.FindAllStringSubmatch(line, -1) {
			if m[1] != "" {
				helperParams[m[1]] = m[2]
			} else {
				helperParams[m[3]] = m[4]
			}
		}
	}
	type declarationMatch struct {
		name  string
		value string
	}
	declarations := make([]declarationMatch, len(code))
	for i, line := range code {
		if m := r.declaration.FindStringSubmatch(line); m != nil {
			declarations[i] = declarationMatch{name: m[1], value: m[2]}
		}
	}
	// Each helper call is matched by an expression compiled once per file.
	calls := make(map[string]*regexp.Regexp, len(helperParams))
	for helper := range helperParams {
		calls[helper] = regexp.MustCompile(`\b` + regexp.QuoteMeta(helper) + `\s*\(([^;]*)`)
	}
	// A helper call on a source line does not change between propagation
	// passes. Index helper-name occurrences once, then cache each exact regex
	// result so the propagation loop only performs lookups.
	callMatches := indexHelperCalls(code, calls)
	messageMatches := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		var holds *regexp.Regexp
		if len(texts) > 0 {
			holds = regexp.MustCompile(`\b(?:` + alternation(slices.Sorted(maps.Keys(texts))) + `)\b`)
		}
		carries := func(expr string) bool {
			messageMatch, known := messageMatches[expr]
			if !known {
				messageMatch = messageOf.MatchString(expr)
				messageMatches[expr] = messageMatch
			}
			return messageMatch || (holds != nil && holds.MatchString(expr))
		}
		for i := range code {
			declaration := declarations[i]
			if declaration.name != "" && !texts[declaration.name] && carries(declaration.value) {
				texts[declaration.name] = true
				changed = true
			}
			for _, call := range callMatches[i] {
				param := helperParams[call.helper]
				if texts[param] {
					continue
				}
				if call.matched && carries(firstArgument(call.argument)) {
					texts[param] = true
					changed = true
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(texts))
}

type helperCallMatch struct {
	helper   string
	argument string
	matched  bool
	position int
}

type helperCallTrieNode struct {
	next    map[byte]int
	failure int
	output  []string
}

func indexHelperCalls(code []string, calls map[string]*regexp.Regexp) [][]helperCallMatch {
	trie := helperCallTrie(calls)
	matches := make([][]helperCallMatch, len(code))
	for lineIndex, line := range code {
		seen := make(map[string]bool)
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
				if start < 0 || patternkit.IsWordChar(line[start]) == (start > 0 && patternkit.IsWordChar(line[start-1])) || seen[name] {
					continue
				}
				if addHelperCallMatch(&matches[lineIndex], line, start, end, name, calls[name]) {
					seen[name] = true
				}
			}
		}
		slices.SortFunc(matches[lineIndex], func(a, b helperCallMatch) int {
			return a.position - b.position
		})
	}
	return matches
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

func addHelperCallMatch(matches *[]helperCallMatch, line string, start, end int, name string, call *regexp.Regexp) bool {
	paren := end + 1
	for paren < len(line) && regexpSpaceByte(line[paren]) {
		paren++
	}
	if paren >= len(line) || line[paren] != '(' {
		return false
	}
	prefixStart := start
	if prefixStart > 0 {
		prefixStart--
	}
	prefix := line[prefixStart : paren+1]
	m := call.FindStringSubmatchIndex(prefix)
	if m == nil || m[0] != start-prefixStart || m[1] != len(prefix) {
		return false
	}
	argument := line[paren+1:]
	if semicolon := strings.IndexByte(argument, ';'); semicolon >= 0 {
		argument = argument[:semicolon]
	}
	*matches = append(*matches, helperCallMatch{helper: name, argument: argument, matched: true, position: start})
	return true
}

func regexpSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// firstArgument returns the first argument of an argument list: the text up
// to the first comma outside brackets, quotes and template literals. Only the
// first argument lands in the helper's first parameter.
func firstArgument(args string) string {
	depth := 0
	var quote byte
	for i := 0; i < len(args); i++ {
		c := args[i]
		switch {
		case quote != 0:
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth == 0 {
				return args[:i]
			}
			depth--
		case c == ',' && depth == 0:
			return args[:i]
		}
	}
	return args
}

// alternation joins names into a regular expression alternation.
func alternation(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return strings.Join(quoted, "|")
}
