package httprules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewResponseJSONUnguardedRule())
}

// ResponseJSONUnguardedRule detects a fetch response parsed with .json()
// with nothing to catch a body that is not JSON:
//
//	const response = await fetch('/api/codes/claim', { method: 'POST' })
//	const data = await response.json()
//
// A plain-text refusal from a middleware, a proxy's HTML page or a cut-off
// body makes .json() throw a SyntaxError, and the screen shows "Unexpected
// token ... is not valid JSON" instead of the reason. The parse is guarded by
// a .catch in its chain or a try block around it, or by the callers of a
// helper of the file when every call of it ends in a .catch — or it goes
// through a helper that reads text and turns a bad body into an error with
// the status.
// A response is a variable assigned from fetch, or one named response, resp,
// res, r or ...Response. Test code reads raw responses on purpose and is not
// checked.
type ResponseJSONUnguardedRule struct {
	*rules.BaseRule
}

// NewResponseJSONUnguardedRule creates the rule
func NewResponseJSONUnguardedRule() *ResponseJSONUnguardedRule {
	return &ResponseJSONUnguardedRule{BaseRule: rules.NewBaseRule(
		"response-json-unguarded",
		"patterns",
		"Detects a fetch response parsed with .json() with no .catch or try for a body that is not JSON",
		core.SeverityMedium,
	)}
}

var (
	responseJSONCall = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\.json\s*\(\s*\)`)
	responseName     = regexp.MustCompile(`^(?:r|res|resp|response|[\w$]*Response|[\w$]*Resp)$`)
	fetchAssign      = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?fetch\s*\(`)
	tryKeyword       = regexp.MustCompile(`\btry\s*$`)
)

// AnalyzeFile reports the unguarded parses of a TS/JS file.
func (r *ResponseJSONUnguardedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || ctx.IsTestFile() || patternkit.IsE2EPath(ctx.RelPath) {
		return nil
	}
	code := patternkit.NewJSSource(ctx).Code
	fetched := make(map[string]bool)
	for _, line := range code {
		for _, m := range fetchAssign.FindAllStringSubmatch(line, -1) {
			fetched[m[1]] = true
		}
	}
	var violations []*core.Violation
	var helpers []jsHelper
	helpersRead := false
	depth := 0
	var tries []int // depths inside the try blocks open here
	for i, line := range code {
		matches := responseJSONCall.FindAllStringSubmatchIndex(line, -1)
		firstNonSpace := strings.IndexFunc(line, notSpace)
		next := 0
		for col := 0; col <= len(line); col++ {
			for next < len(matches) && matches[next][0] == col {
				m := matches[next]
				next++
				name := line[m[2]:m[3]]
				isResponse := fetched[name] || responseName.MatchString(name)
				if len(tries) > 0 || !isResponse || caughtInChain(code, i, m[1]) {
					continue
				}
				if !helpersRead {
					helpers, helpersRead = fileHelpers(code), true
				}
				if caughtByCallers(code, helpers, i, m[0]) {
					continue
				}
				if ctx.IsSuppressed(i+1, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, i+1,
					"Response parsed with .json() and nothing catches a body that is not JSON — the user sees a parser error instead of the reason")
				v.WithCode(strings.TrimSpace(ctx.Lines[i]))
				v.WithSuggestion("Read the body through a helper that turns a body that is not JSON into an error with the status, or add .catch / try around the parse")
				violations = append(violations, v)
			}
			if col == len(line) {
				break
			}
			switch line[col] {
			case '{':
				depth++
				if endsWithTryKeyword(line, col) || (col == firstNonSpace && i > 0 && tryKeyword.MatchString(code[i-1])) {
					tries = append(tries, depth)
				}
			case '}':
				depth--
				for len(tries) > 0 && tries[len(tries)-1] > depth {
					tries = tries[:len(tries)-1]
				}
			}
		}
	}
	return violations
}

func endsWithTryKeyword(line string, end int) bool {
	start := end
	for start > 0 && patternkit.IsRegexpSpace(line[start-1]) {
		start--
	}
	if start < 3 || line[start-3:start] != "try" {
		return false
	}
	return start == 3 || !patternkit.IsWordChar(line[start-4])
}

func notSpace(r rune) bool { return r != ' ' && r != '\t' }

// caughtInChain reports a .catch, or a .then with a rejection handler, that
// continues the chain the parse belongs to: its own chain, or the chain of a
// call whose callback holds it, however many lines that callback spans. A
// statement end, or a block that is not a callback argument, cuts the link
// until the walk climbs out to the next enclosing call.
func caughtInChain(code []string, line, col int) bool {
	depth, outer := 0, 0
	broken := false
	last := min(len(code)-1, line+chainWindowLines)
	budget := chainWindowBytes
	for i := line; i <= last && budget > 0; i++ {
		text := code[i]
		from := 0
		if i == line {
			from = col
		}
		for j := from; j < len(text) && budget > 0; j++ {
			budget--
			switch c := text[j]; c {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
				if depth < outer {
					outer = depth
					broken = c == '}' && !callbackEnd(code, i, j+1, last)
				}
			case ';':
				if depth == outer {
					broken = true
				}
			case '.':
				if depth == outer && !broken && handlesRejection(code, i, j, last) {
					return true
				}
			}
		}
		if depth == outer && !continuesOnNextLine(code, i+1, last) {
			broken = true
		}
	}
	return false
}

const (
	chainWindowLines = 80
	chainWindowBytes = 1 << 14
)

var (
	catchCall = regexp.MustCompile(`^\.\s*catch\s*\(`)
	thenCall  = regexp.MustCompile(`^\.\s*then\s*\(`)
)

// handlesRejection reports a .catch( at code[line][col], or a .then( there
// with a second argument.
func handlesRejection(code []string, line, col, last int) bool {
	rest := code[line][col:]
	if catchCall.MatchString(rest) {
		return true
	}
	m := thenCall.FindStringIndex(rest)
	if m == nil {
		return false
	}
	depth := 1
	for i, from := line, col+m[1]; i <= last; i, from = i+1, 0 {
		for _, c := range []byte(code[i][from:]) {
			switch c {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
				if depth == 0 {
					return false
				}
			case ',':
				if depth == 1 {
					return true
				}
			}
		}
	}
	return false
}

// callbackEnd reports a ')' or ',' as the next code after a closing brace: the
// block was a function passed as an argument.
func callbackEnd(code []string, line, col, last int) bool {
	for i, from := line, col; i <= last; i, from = i+1, 0 {
		if rest := strings.TrimSpace(code[i][from:]); rest != "" {
			return rest[0] == ')' || rest[0] == ','
		}
	}
	return false
}

// continuesOnNextLine reports that the next code line goes on with the
// expression: a chained call, a closing bracket or another argument.
func continuesOnNextLine(code []string, line, last int) bool {
	for i := line; i <= last; i++ {
		if rest := strings.TrimSpace(code[i]); rest != "" {
			return strings.ContainsRune(".)]},", rune(rest[0]))
		}
	}
	return false
}

// jsHelper is a function of the file with a block body, from the '{' to the
// '}' of the body.
type jsHelper struct {
	name                         string
	startLine, startCol, endLine int
	endCol                       int
	exported                     bool
}

var helperHead = regexp.MustCompile(`(?:\bfunction\s+([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\(|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*(?:async\s+)?(?:function\b[^(]*\(|\())`)

// fileHelpers lists the named functions of the file whose body is a block.
func fileHelpers(code []string) []jsHelper {
	var helpers []jsHelper
	for i, text := range code {
		for _, m := range helperHead.FindAllStringSubmatchIndex(text, -1) {
			name := ""
			if m[2] >= 0 {
				name = text[m[2]:m[3]]
			} else {
				name = text[m[4]:m[5]]
			}
			bl, bc, ok := helperBody(code, i, m[1]-1)
			if !ok {
				continue
			}
			el, ec, ok := patternkit.JsBlockEnd(code, bl, bc)
			if !ok {
				continue
			}
			helpers = append(helpers, jsHelper{
				name: name, startLine: bl, startCol: bc, endLine: el, endCol: ec,
				exported: strings.Contains(text[:m[0]], "export"),
			})
		}
	}
	return helpers
}

// helperBody finds the '{' of the body after the parameter list opened at
// code[line][col]: past the list, an optional return type and an arrow.
func helperBody(code []string, line, col int) (int, int, bool) {
	el, ec, ok := closingParen(code, line, col)
	if !ok {
		return 0, 0, false
	}
	for i, from := el, ec; i < len(code) && i <= el+3; i, from = i+1, 0 {
		if j := strings.IndexAny(code[i][from:], "{;"); j >= 0 {
			if code[i][from+j] == ';' {
				return 0, 0, false
			}
			return i, from + j, true
		}
	}
	return 0, 0, false
}

// closingParen returns the position after the ')' that closes the '(' at
// code[line][col].
func closingParen(code []string, line, col int) (int, int, bool) {
	depth := 0
	for i, from := line, col; i < len(code) && i <= line+chainWindowLines; i, from = i+1, 0 {
		for j := from; j < len(code[i]); j++ {
			switch code[i][j] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return i, j + 1, true
				}
			}
		}
	}
	return 0, 0, false
}

// caughtByCallers reports a parse inside a helper of the file whose every
// use in the file is a call that ends in a .catch: the helper hands the parse
// to its callers, and they catch it. An exported helper has callers
// elsewhere, and a helper passed as a value has callers out of sight.
func caughtByCallers(code []string, helpers []jsHelper, line, col int) bool {
	var inner *jsHelper
	for k := range helpers {
		h := &helpers[k]
		if containsPos(h, line, col) && (inner == nil || containsPos(inner, h.startLine, h.startCol)) {
			inner = h
		}
	}
	if inner == nil || inner.exported {
		return false
	}
	use := regexp.MustCompile(`(?:^|[^\w$.])(` + regexp.QuoteMeta(inner.name) + `)\b(\s*\()?`)
	calls := 0
	for i, text := range code {
		for _, m := range use.FindAllStringSubmatchIndex(text, -1) {
			if declaresName(text[:m[2]]) {
				continue
			}
			if m[4] < 0 {
				return false
			}
			el, ec, ok := closingParen(code, i, m[5]-1)
			if !ok || !caughtInChain(code, el, ec) {
				return false
			}
			calls++
		}
	}
	return calls > 0
}

func containsPos(h *jsHelper, line, col int) bool {
	after := line > h.startLine || (line == h.startLine && col > h.startCol)
	before := line < h.endLine || (line == h.endLine && col < h.endCol)
	return after && before
}

// declaresName reports the text before a name that declares it.
func declaresName(before string) bool {
	before = strings.TrimRight(before, " \t")
	for _, keyword := range []string{"function", "const", "let", "var"} {
		if strings.HasSuffix(before, keyword) && (len(before) == len(keyword) || !patternkit.IsWordChar(before[len(before)-len(keyword)-1])) {
			return true
		}
	}
	return false
}
