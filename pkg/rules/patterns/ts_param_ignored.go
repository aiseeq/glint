package patterns

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTSParamIgnoredRule())
}

// TSParamIgnoredRule detects a public method of a TypeScript class that
// marks a parameter unused with a leading underscore while calls of a method
// of that name pass a value in its place:
//
//	async post(url: string, data?: unknown, _options?: RequestInit) {
//		return this.makeRequest(url, 'POST', data)      // options dropped
//	}
//
//	api.post('/security/action', body, { headers: { 'X-Confirm': code } })
//
// The caller believes the headers are sent; the underscore silences the
// compiler and the linters, which treat _x as deliberately unused. Calls are
// matched by method name and position anywhere in the project; a value of
// undefined does not count. Private and protected methods and constructors
// are left out.
type TSParamIgnoredRule struct {
	*rules.BaseRule
	// passed maps a method name to the argument positions some call fills.
	passed map[string]map[int]bool
}

// NewTSParamIgnoredRule creates the rule
func NewTSParamIgnoredRule() *TSParamIgnoredRule {
	return &TSParamIgnoredRule{BaseRule: rules.NewBaseRule(
		"ts-param-ignored",
		"patterns",
		"Detects a public TypeScript class method whose _-prefixed parameter is unused while calls of the method pass a value there — the argument is silently dropped",
		core.SeverityMedium,
	)}
}

var (
	tsMemberCall = regexp.MustCompile(`\.\s*([A-Za-z_$][\w$]*)\s*\(`)
	tsMethodDecl = regexp.MustCompile(`(?m)^[ \t]*((?:(?:public|static|async|override)\s+)*)([A-Za-z_$][\w$]*)\s*(?:<[^()]*>)?\s*\(`)
	tsParamName  = regexp.MustCompile(`^\s*(?:\.\.\.)?([A-Za-z_$][\w$]*)`)
	tsNotMethods = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "function": true, "return": true, "constructor": true, "super": true}
)

func tsSource(ctx *core.FileContext) bool {
	path := filepath.ToSlash(ctx.RelPath)
	return (ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile()) && !jsBuildPath(path) && !strings.HasSuffix(path, ".d.ts")
}

// UseProjectFiles collects the argument positions the project's member calls
// fill.
func (r *TSParamIgnoredRule) UseProjectFiles(files []*core.FileContext) {
	r.passed = make(map[string]map[int]bool)
	for _, ctx := range files {
		if !tsSource(ctx) {
			continue
		}
		f := newJSFlat(ctx)
		for _, m := range tsMemberCall.FindAllStringSubmatchIndex(f.code, -1) {
			name := f.code[m[2]:m[3]]
			open := m[1] - 1
			for i, arg := range f.callArgs(open) {
				text := strings.TrimSpace(f.code[arg.start:arg.end])
				if text == "" || text == "undefined" {
					continue
				}
				if r.passed[name] == nil {
					r.passed[name] = make(map[int]bool)
				}
				r.passed[name][i] = true
			}
		}
	}
}

// ResetState drops the calls of the previous root.
func (r *TSParamIgnoredRule) ResetState() { r.passed = nil }

// AnalyzeFile reports the dropped parameters of the file's class methods.
func (r *TSParamIgnoredRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !tsSource(ctx) || ctx.IsTestFile() {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range tsMethodDecl.FindAllStringSubmatchIndex(f.code, -1) {
		name := f.code[m[4]:m[5]]
		if tsNotMethods[name] || r.passed[name] == nil {
			continue
		}
		open := m[1] - 1
		closeParen, ok := f.closing(open)
		if !ok {
			continue
		}
		brace, ok := methodBodyBrace(f, closeParen)
		if !ok || !strings.Contains(classHeader(f, m[0]), "class ") {
			continue
		}
		bodyEnd, ok := f.closing(brace)
		if !ok {
			continue
		}
		body := f.code[brace:bodyEnd]
		for i, param := range splitTSParams(f.code[open+1 : closeParen]) {
			pm := tsParamName.FindStringSubmatch(param)
			if pm == nil || len(pm[1]) < 2 || !strings.HasPrefix(pm[1], "_") || !r.passed[name][i] {
				continue
			}
			if jsMentions(body, pm[1]) {
				continue
			}
			line := f.line(m[4])
			violations = jsReport(violations, r.BaseRule, ctx, line,
				"Parameter "+pm[1]+" of "+name+" is marked unused, yet calls of "+name+" pass a value there — the argument is silently dropped",
				"Use the parameter (forward it to the request), or remove it so the callers see the method does not take it")
		}
	}
	return violations
}

// jsMentions reports the identifier as a whole word of the code.
func jsMentions(code, name string) bool {
	for from := 0; ; {
		i := strings.Index(code[from:], name)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(name)
		before := start == 0 || !jsWordByte(code[start-1])
		after := end == len(code) || !jsWordByte(code[end])
		if before && after {
			return true
		}
		from = end
	}
}

func jsWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// methodBodyBrace returns the '{' of a method body after its parameter list:
// an optional return type, then the brace. A ';' (an overload or an abstract
// signature) or an arrow first means there is no body here.
func methodBodyBrace(f jsFlat, closeParen int) (int, bool) {
	depth := 0
	for i := closeParen + 1; i < len(f.code); i++ {
		switch c := f.code[i]; c {
		case '<', '(', '[':
			depth++
		case '>':
			if f.code[i-1] == '=' {
				return 0, false
			}
			depth--
		case ')', ']':
			depth--
		case ';':
			if depth == 0 {
				return 0, false
			}
		case '{':
			if depth == 0 {
				// A brace right after ':' opens an object return type.
				if strings.HasSuffix(strings.TrimSpace(f.code[closeParen+1:i]), ":") {
					end, ok := f.closing(i)
					if !ok {
						return 0, false
					}
					i = end
					continue
				}
				return i, true
			}
		}
	}
	return 0, false
}

// classHeader returns the header of the block that holds the offset.
func classHeader(f jsFlat, pos int) string {
	brace := f.enclosingBrace(pos)
	if brace < 0 {
		return ""
	}
	head, _ := f.header(brace)
	return head + " "
}

// splitTSParams splits a parameter list at its top-level commas, generic
// brackets included.
func splitTSParams(list string) []string {
	var params []string
	depth, start := 0, 0
	for i := 0; i < len(list); i++ {
		switch list[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}':
			depth--
		case '>':
			if i > 0 && list[i-1] == '=' {
				continue
			}
			depth--
		case ',':
			if depth == 0 {
				params = append(params, list[start:i])
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(list[start:]) != "" {
		params = append(params, list[start:])
	}
	return params
}
