package patterns

import (
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || skipFrontendPath(ctx) {
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

	subject := `(?:\b(?:` + alternation(errorNames) + `)\s*\??\.\s*message`
	if len(texts) > 0 {
		subject += `|\b(?:` + alternation(texts) + `)\b`
	}
	subject += `)`
	match := regexp.MustCompile(subject + `\s*\??\.\s*(?:includes|startsWith|endsWith|indexOf|match|search)\s*\(` +
		`|` + subject + `\s*[!=]==?\s*['"` + "`" + `]` +
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
	// Each helper call is matched by an expression compiled once per file.
	calls := make(map[string]*regexp.Regexp, len(helperParams))
	for helper := range helperParams {
		calls[helper] = regexp.MustCompile(`\b` + regexp.QuoteMeta(helper) + `\s*\(([^;]*)`)
	}
	for changed := true; changed; {
		changed = false
		var holds *regexp.Regexp
		if len(texts) > 0 {
			holds = regexp.MustCompile(`\b(?:` + alternation(mapKeys(texts)) + `)\b`)
		}
		carries := func(expr string) bool {
			return messageOf.MatchString(expr) || (holds != nil && holds.MatchString(expr))
		}
		for _, line := range code {
			if m := r.declaration.FindStringSubmatch(line); m != nil && !texts[m[1]] && carries(m[2]) {
				texts[m[1]] = true
				changed = true
			}
			for helper, param := range helperParams {
				if texts[param] || !strings.Contains(line, helper) {
					continue
				}
				if m := calls[helper].FindStringSubmatch(line); m != nil && carries(m[1]) {
					texts[param] = true
					changed = true
				}
			}
		}
	}
	return mapKeys(texts)
}

// alternation joins names into a regular expression alternation.
func alternation(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return strings.Join(quoted, "|")
}

func mapKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
