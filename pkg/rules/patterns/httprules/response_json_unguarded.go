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
// a .catch in its chain or a try block around it — or it goes through a
// helper that reads text and turns a bad body into an error with the status.
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
