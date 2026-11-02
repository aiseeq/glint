package frontendrules

import (
	"regexp"
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
	errorSet := make(map[string]bool, len(errorNames))
	for _, name := range errorNames {
		errorSet[name] = true
	}
	texts := r.messageTexts(code, errorSet)

	var violations []*core.Violation
	for i, line := range code {
		if !mayTestText(line) {
			continue
		}
		// typeof x === 'string' tests the kind of value, not its wording.
		line = typeofOperand.ReplaceAllString(line, "")
		if !lineTestsText(line, errorSet, texts) || ctx.IsSuppressed(i+1, r.Name()) {
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
		forEachJSIdentifier(line, func(name string, start, end int) {
			if isErrorName(name) {
				add(name)
			}
			if param := errorCallbackParam(line, name, start, end); param != "" {
				add(param)
			}
		})
	}
	return names
}

// messageTexts returns the names that hold the message of an error: variables
// assigned from a message or from another such name, and the first parameter
// of a helper the file calls with a message.
func (r *FrontendErrorMessageMatchRule) messageTexts(code []string, errorNames map[string]bool) map[string]bool {
	helperParams := make(map[string]string)
	for _, line := range code {
		forEachJSIdentifier(line, func(word string, _, end int) {
			name, param, ok := helperFunctionParam(line, word, end)
			if ok {
				helperParams[name] = param
			}
		})
	}
	type relation struct {
		target string
		expr   string
	}
	var relations []relation
	for _, line := range code {
		if name, expr, ok := findDeclaration(line); ok {
			relations = append(relations, relation{target: name, expr: expr})
		}
		for i := 0; i < len(line); {
			start := i
			for i < len(line) && isJSIdentifierByte(line[i], i == start) {
				i++
			}
			if i == start {
				i++
				continue
			}
			helper := line[start:i]
			param, ok := helperParams[helper]
			if !ok {
				continue
			}
			call := i
			for call < len(line) && (line[call] == ' ' || line[call] == '\t' || line[call] == '\r' || line[call] == '\n') {
				call++
			}
			if call < len(line) && line[call] == '(' {
				relations = append(relations, relation{target: param, expr: firstArgument(line[call+1:])})
			}
		}
	}

	// Build the dependency graph once, then propagate message-bearing names
	// through it. Re-scanning a minified line once per helper made this phase
	// proportional to file size times the number of helpers.
	texts := make(map[string]bool)
	dependents := make(map[string][]string)
	var pending []string
	for _, rel := range relations {
		if containsErrorMessage(rel.expr, errorNames) && !texts[rel.target] {
			texts[rel.target] = true
			pending = append(pending, rel.target)
		}
		forEachJSIdentifier(rel.expr, func(name string, _, _ int) {
			dependents[name] = append(dependents[name], rel.target)
		})
	}
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, target := range dependents[name] {
			if !texts[target] {
				texts[target] = true
				pending = append(pending, target)
			}
		}
	}
	return texts
}

func isJSIdentifierByte(c byte, first bool) bool {
	return c == '$' || c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || !first && c >= '0' && c <= '9'
}

func forEachJSIdentifier(line string, visit func(name string, start, end int)) {
	for i := 0; i < len(line); {
		if !isJSIdentifierByte(line[i], true) {
			i++
			continue
		}
		start := i
		i++
		for i < len(line) && isJSIdentifierByte(line[i], false) {
			i++
		}
		visit(line[start:i], start, i)
	}
}

func identifierAt(line string, i int) (string, int) {
	i = skipJSSpace(line, i)
	if i >= len(line) || !isJSIdentifierByte(line[i], true) {
		return "", i
	}
	start := i
	i++
	for i < len(line) && isJSIdentifierByte(line[i], false) {
		i++
	}
	return line[start:i], i
}

func errorCallbackParam(line, name string, start, end int) string {
	i := end
	if name == "catch" {
		isPromiseCatch := start > 0 && line[start-1] == '.'
		i = skipJSSpace(line, i)
		if i >= len(line) || line[i] != '(' {
			return ""
		}
		i = skipJSSpace(line, i+1)
		if isPromiseCatch && i < len(line) && line[i] == '(' {
			i = skipJSSpace(line, i+1)
		}
		param, _ := identifierAt(line, i)
		return param
	}
	callback := name == "onError" || name == "onerror"
	if !callback && len(name) > 3 && strings.HasPrefix(name, "on") && name[2] >= 'A' && name[2] <= 'Z' && strings.Contains(name[3:], "Error") && !strings.Contains(name, "$") {
		callback = true
	}
	if !callback {
		return ""
	}
	i = skipJSSpace(line, end)
	if i >= len(line) || line[i] != ':' && line[i] != '=' {
		return ""
	}
	i = skipJSSpace(line, i+1)
	if i < len(line) && line[i] == '(' {
		i = skipJSSpace(line, i+1)
	}
	param, _ := identifierAt(line, i)
	return param
}

func helperFunctionParam(line, word string, end int) (name, param string, ok bool) {
	i := end
	switch word {
	case "function":
		name, i = identifierAt(line, i)
		if name == "" {
			return "", "", false
		}
		i = skipJSSpace(line, i)
	case "const", "let":
		name, i = identifierAt(line, i)
		if name == "" {
			return "", "", false
		}
		i = skipJSSpace(line, i)
		if i >= len(line) || line[i] != '=' {
			return "", "", false
		}
		i = skipJSSpace(line, i+1)
		if strings.HasPrefix(line[i:], "async") && (i+5 == len(line) || !isJSIdentifierByte(line[i+5], false)) {
			i = skipJSSpace(line, i+5)
		}
	default:
		return "", "", false
	}
	if i >= len(line) || line[i] != '(' {
		return "", "", false
	}
	param, _ = identifierAt(line, i+1)
	return name, param, param != ""
}

func findDeclaration(line string) (name, expr string, ok bool) {
	var found bool
	forEachJSIdentifier(line, func(word string, _, end int) {
		if found || word != "const" && word != "let" && word != "var" {
			return
		}
		i := skipJSSpace(line, end)
		if i >= len(line) || !isJSIdentifierByte(line[i], true) {
			return
		}
		start := i
		i++
		for i < len(line) && isJSIdentifierByte(line[i], false) {
			i++
		}
		name = line[start:i]
		i = skipJSSpace(line, i)
		if i < len(line) && line[i] == ':' {
			for i < len(line) && line[i] != '=' {
				i++
			}
		}
		if i >= len(line) || line[i] != '=' {
			return
		}
		i = skipJSSpace(line, i+1)
		if i < len(line) {
			expr = line[i:]
			found = true
		}
	})
	return name, expr, found
}

func containsErrorMessage(expr string, errorNames map[string]bool) bool {
	found := false
	forEachJSIdentifier(expr, func(name string, start, end int) {
		if !found && errorNames[name] {
			if _, ok := messagePropertyEnd(expr, end); ok {
				found = true
				return
			}
			i := skipJSSpace(expr, end)
			if i < len(expr) && expr[i] == 'a' && strings.HasPrefix(expr[i:], "as") && (i+2 == len(expr) || !isJSIdentifierByte(expr[i+2], false)) {
				i = skipJSSpace(expr, i+2)
				if i < len(expr) && isJSIdentifierByte(expr[i], true) {
					i++
					for i < len(expr) && (isJSIdentifierByte(expr[i], false) || expr[i] == '.') {
						i++
					}
					i = skipJSSpace(expr, i)
					if i < len(expr) && expr[i] == '<' {
						for i < len(expr) && expr[i] != '>' {
							i++
						}
						if i < len(expr) {
							i++
						}
						i = skipJSSpace(expr, i)
					}
				}
				if i < len(expr) && expr[i] == ')' {
					if _, ok := messagePropertyEnd(expr, i+1); ok && start > 0 && expr[start-1] == '(' {
						found = true
					}
				}
			}
		}
	})
	return found
}

func messagePropertyEnd(line string, end int) (int, bool) {
	i := skipJSSpace(line, end)
	if i < len(line) && line[i] == '?' {
		i++
	}
	if i >= len(line) || line[i] != '.' {
		return 0, false
	}
	i = skipJSSpace(line, i+1)
	if !strings.HasPrefix(line[i:], "message") {
		return 0, false
	}
	i += len("message")
	if i < len(line) && isJSIdentifierByte(line[i], false) {
		return 0, false
	}
	return i, true
}

func skipJSSpace(line string, i int) int {
	for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n') {
		i++
	}
	return i
}

func lineTestsText(line string, errorNames, texts map[string]bool) bool {
	found := false
	forEachJSIdentifier(line, func(name string, start, end int) {
		if found {
			return
		}
		if errorNames[name] {
			if messageEnd, ok := messagePropertyEnd(line, end); ok && isTextTestAt(line, start, messageEnd) {
				found = true
				return
			}
		}
		if texts[name] && isTextTestAt(line, start, end) {
			found = true
		}
	})
	return found
}

func isTextTestAt(line string, start, end int) bool {
	i := skipJSSpace(line, end)
	if i < len(line) && line[i] == '?' {
		i++
	}
	if i < len(line) && line[i] == '.' {
		i = skipJSSpace(line, i+1)
		for _, method := range textTests[:6] {
			if strings.HasPrefix(line[i:], method) {
				call := skipJSSpace(line, i+len(method))
				if call < len(line) && line[call] == '(' {
					return true
				}
			}
		}
	}
	if comparisonAfter(line, end) || comparisonBefore(line, start) {
		return true
	}
	return regexTestBefore(line, start)
}

func comparisonAfter(line string, end int) bool {
	i := skipJSSpace(line, end)
	if i >= len(line) || line[i] != '=' && line[i] != '!' {
		return false
	}
	i++
	if i >= len(line) || line[i] != '=' {
		return false
	}
	i++
	if i < len(line) && line[i] == '=' {
		i++
	}
	i = skipJSSpace(line, i)
	return i < len(line) && (line[i] == '\'' || line[i] == '"' || line[i] == '`')
}

func comparisonBefore(line string, start int) bool {
	i := start
	for i > 0 && (line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == '\r' || line[i-1] == '\n') {
		i--
	}
	if i == 0 || line[i-1] != '=' {
		return false
	}
	i--
	if i > 0 && (line[i-1] == '=' || line[i-1] == '!') {
		i--
	}
	if i > 0 && line[i-1] == '=' {
		i--
	}
	for i > 0 && (line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == '\r' || line[i-1] == '\n') {
		i--
	}
	return i > 0 && (line[i-1] == '\'' || line[i-1] == '"' || line[i-1] == '`')
}

func regexTestBefore(line string, start int) bool {
	i := start
	for i > 0 && (line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == '\r' || line[i-1] == '\n') {
		i--
	}
	if i == 0 || line[i-1] != '(' {
		return false
	}
	i--
	for i > 0 && (line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == '\r' || line[i-1] == '\n') {
		i--
	}
	if i < len("test") || line[i-len("test"):i] != "test" {
		return false
	}
	i -= len("test")
	for i > 0 && (line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == '\r' || line[i-1] == '\n') {
		i--
	}
	if i == 0 || line[i-1] != '.' {
		return false
	}
	i--
	for i > 0 && (line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == '\r' || line[i-1] == '\n') {
		i--
	}
	for i > 0 && strings.ContainsRune("gimsuy", rune(line[i-1])) {
		i--
	}
	return i > 0 && line[i-1] == '/'
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
