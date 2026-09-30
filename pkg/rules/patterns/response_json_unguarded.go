package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
	chainCatch       = regexp.MustCompile(`^\s*\.(?:catch|then\s*\([^)]*,)`)
	tryKeyword       = regexp.MustCompile(`\btry\s*$`)
)

// AnalyzeFile reports the unguarded parses of a TS/JS file.
func (r *ResponseJSONUnguardedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || ctx.IsTestFile() || isE2EPath(ctx.RelPath) {
		return nil
	}
	code := newJSSource(ctx).code
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
		next := 0
		for col := 0; col <= len(line); col++ {
			for next < len(matches) && matches[next][0] == col {
				m := matches[next]
				next++
				name := line[m[2]:m[3]]
				if len(tries) > 0 || !(fetched[name] || responseName.MatchString(name)) || caughtInChain(code, i, m[1]) {
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
				if tryKeyword.MatchString(line[:col]) || (col == strings.IndexFunc(line, notSpace) && i > 0 && tryKeyword.MatchString(code[i-1])) {
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

func notSpace(r rune) bool { return r != ' ' && r != '\t' }

// caughtInChain reports a .catch after the parse: later on its line, or on
// the lines that continue the chain.
func caughtInChain(code []string, line, col int) bool {
	if strings.Contains(code[line][col:], ".catch(") {
		return true
	}
	for i := line + 1; i < len(code) && i <= line+5; i++ {
		trimmed := strings.TrimSpace(code[i])
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, ".") {
			return false
		}
		if chainCatch.MatchString(code[i]) || strings.Contains(trimmed, ".catch(") {
			return true
		}
	}
	return false
}
