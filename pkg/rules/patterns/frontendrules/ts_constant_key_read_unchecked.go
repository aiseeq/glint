package frontendrules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// TSConstantKeyReadUncheckedRule finds dictionary lookups by literal string
// keys whose values are dereferenced without establishing that the key exists.
type TSConstantKeyReadUncheckedRule struct{ *rules.BaseRule }

// NewTSConstantKeyReadUncheckedRule creates the rule.
func NewTSConstantKeyReadUncheckedRule() *TSConstantKeyReadUncheckedRule {
	return &TSConstantKeyReadUncheckedRule{BaseRule: rules.NewBaseRule(
		"ts-constant-key-read-unchecked", "patterns",
		"Detects unchecked reads of dictionary entries by constant string key that can become undefined",
		core.SeverityMedium,
	)}
}

var (
	tsConstKeyRead = regexp.MustCompile(`\b((?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\[\s*(['"])([^'"\n]+)['"]\s*\]`)
	tsRecordType   = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*(?:Record\s*<|\{[^}]*\[\s*[A-Za-z_$][\w$]*\s*:\s*string\s*\])`)
	tsJsonValue    = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*[^;\n]*\b(?:JSON\s*\.\s*parse|\.\s*json\s*\()`)
	tsAliasRead    = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\[\s*(['"])([^'"\n]+)['"]\s*\]`)
)

type tsConstantLookup struct {
	base, key  string
	start, end int
}

// AnalyzeFile reports unchecked constant-key reads in production TS/JS. The
// scripts of a Go HTML template come here as a virtual JavaScript file.
func (r *TSConstantKeyReadUncheckedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	if ctx.IsGenerated() {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)
	var out []*core.Violation
	for _, match := range tsConstKeyRead.FindAllStringSubmatchIndex(f.Code, -1) {
		base := strings.Join(strings.Fields(f.Code[match[2]:match[3]]), "")
		key := f.Text[match[6]:match[7]]
		lookup := tsConstantLookup{base: base, key: key, start: match[0], end: match[1]}
		if !tsDictionaryVariable(f.Code, base, ctx.VirtualJavaScript) || tsLocalObjectHasKey(f.Code, f.Text, base, key) {
			continue
		}
		scopeStart, scopeEnd := 0, len(f.Code)
		fn, inFunction := f.EnclosingFunction(match[0])
		if inFunction {
			fnEnd, balanced := f.Closing(fn.Brace)
			if !balanced || match[0] < fn.Brace || match[1] > fnEnd {
				continue
			}
			scopeStart, scopeEnd = fn.Brace+1, fnEnd
		}
		body := f.Code[scopeStart:scopeEnd]
		localStart := match[0] - scopeStart
		localEnd := match[1] - scopeStart
		if tsOptionalRead(f.Code, lookup.end) || tsReadIsGuarded(f.Text, scopeStart, match[0], lookup) {
			continue
		}
		if tsDerefAfter(f.Code, lookup.end) {
			if tsReadIsInlineGuarded(f.Text[scopeStart:scopeEnd], localStart, base, key) {
				continue
			}
			out = patternkit.JsReport(out, r.BaseRule, ctx, f.Line(match[0]),
				"Dictionary key "+key+" may be absent, so this read is undefined and the property access or call fails",
				"Check that the key exists before reading it, or use ?. and handle the missing value explicitly")
			continue
		}
		// A saved lookup is reported at its declaration when it is dereferenced
		// later in this function without a check of the saved value.
		for _, alias := range tsAliasRead.FindAllStringSubmatchIndex(body, -1) {
			if body[alias[4]:alias[5]] != base || f.Text[scopeStart+alias[8]:scopeStart+alias[9]] != key {
				continue
			}
			name := body[alias[2]:alias[3]]
			declEnd := alias[1]
			if alias[0] > localStart || alias[1] < localEnd {
				continue
			}
			if tsAliasDereferenced(body[declEnd:], name) && !tsAliasGuarded(body, declEnd, name) {
				out = patternkit.JsReport(out, r.BaseRule, ctx, f.Line(scopeStart+alias[0]),
					"Dictionary key "+key+" may be absent, leaving "+name+" undefined before it is dereferenced",
					"Check that the key exists before reading it, or use ?. and handle the missing value explicitly")
			}
		}
	}
	return out
}

func tsDictionaryVariable(code, name string, templateScript bool) bool {
	root := strings.Split(name, ".")[0]
	for _, match := range tsRecordType.FindAllStringSubmatch(code, -1) {
		if match[1] == name || match[1] == root {
			return true
		}
	}
	for _, match := range tsJsonValue.FindAllStringSubmatch(code, -1) {
		if match[1] == name || match[1] == root {
			return true
		}
	}
	if templateScript && strings.Contains(name, ".") && regexp.MustCompile(`\b(?:const|let|var)\s+`+regexp.QuoteMeta(root)+`\s*=\s*null\b`).MatchString(code) {
		return true // a Go template action supplies the JSON-like script context
	}
	return false
}

func tsLocalObjectHasKey(code, text, name, key string) bool {
	if strings.Contains(name, ".") {
		return false
	}
	decl := regexp.MustCompile(`\b(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\b[^=]*=\s*\{`)
	loc := decl.FindStringIndex(code)
	if loc == nil {
		return false
	}
	open := strings.LastIndex(code[loc[0]:loc[1]], "{") + loc[0]
	flat := patternkit.JsFlat{Code: code}
	close, ok := flat.Closing(open)
	if !ok {
		return false
	}
	keyPattern := regexp.MustCompile(`(?:^|[,\n])\s*(?:['"]` + regexp.QuoteMeta(key) + `['"]|` + regexp.QuoteMeta(key) + `)\s*:`)
	return keyPattern.MatchString(text[open+1 : close])
}

func tsOptionalRead(code string, end int) bool {
	for end < len(code) && (code[end] == ' ' || code[end] == '\t' || code[end] == '\n') {
		end++
	}
	return end < len(code) && code[end] == '?'
}

func tsDerefAfter(code string, end int) bool {
	for end < len(code) && (code[end] == ' ' || code[end] == '\t' || code[end] == '\n') {
		end++
	}
	return end < len(code) && code[end] == '.' && (end+1 >= len(code) || code[end+1] != '.')
}

func tsReadIsGuarded(code string, start, pos int, lookup tsConstantLookup) bool {
	prior := code[start:pos]
	base, key := regexp.QuoteMeta(lookup.base), regexp.QuoteMeta(lookup.key)
	checks := []*regexp.Regexp{
		regexp.MustCompile(`['"]` + key + `['"]\s+in\s+` + base),
		regexp.MustCompile(base + `\s*\[\s*['"]` + key + `['"]\s*\]\s*(?:===?|!==?)\s*(?:undefined|null)`),
		regexp.MustCompile(`(?:===?|!==?)\s*(?:undefined|null)\s*` + base + `\s*\[\s*['"]` + key + `['"]\s*\]`),
		regexp.MustCompile(`!\s*` + base + `\s*\[\s*['"]` + key + `['"]\s*\]`),
		regexp.MustCompile(base + `\.hasOwnProperty\s*\(\s*['"]` + key + `['"]\s*\)`),
	}
	for _, check := range checks {
		if check.MatchString(prior) {
			return true
		}
	}
	return false
}

func tsReadIsInlineGuarded(body string, start int, base, key string) bool {
	statementStart := strings.LastIndexAny(body[:start], ";\n{}") + 1
	prefix := body[statementStart:start]
	lookup := regexp.QuoteMeta(base) + `\s*\[\s*['"]` + regexp.QuoteMeta(key) + `['"]\s*\]`
	return regexp.MustCompile(lookup+`\s*(?:&&|\?|\|\|)`).MatchString(prefix) ||
		regexp.MustCompile(`typeof\s+`+lookup+`\s*===?\s*['"][^'"]+['"]\s*&&`).MatchString(prefix)
}

func tsAliasDereferenced(after, name string) bool {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\.\s*[A-Za-z_$]`).MatchString(after)
}

func tsAliasGuarded(body string, declEnd int, name string) bool {
	quoted := regexp.QuoteMeta(name)
	deref := regexp.MustCompile(`\b` + quoted + `\s*\.\s*[A-Za-z_$]`).FindStringIndex(body[declEnd:])
	if deref == nil {
		return false
	}
	prior := body[declEnd : declEnd+deref[0]]
	checks := []*regexp.Regexp{
		regexp.MustCompile(`!\s*` + quoted + `\b`),
		regexp.MustCompile(`\b` + quoted + `\s*(?:===?|!==?)\s*(?:undefined|null)`),
		regexp.MustCompile(`(?:===?|!==?)\s*(?:undefined|null)\s*\b` + quoted + `\b`),
	}
	for _, check := range checks {
		if check.MatchString(prior) {
			return true
		}
	}
	return false
}
