package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewResponseCastRule())
}

// ResponseCastRule detects an awaited call's result cast to any or to an
// object type written on the spot:
//
//	const response = await api.get(`/api/reports/daily`) as any
//	setData(response.data.items || [])
//
//	const response = await backoffice.listPayouts({ accountId }) as { payouts?: PayoutRow[] }
//
// The cast asserts a shape nothing checks: when the server sends another
// field name, or another type altogether, the read gives undefined and the
// screen shows an empty list instead of an error. The call's own result type
// (a generated contract, the client's generic parameter) is what keeps the
// reads in step with the server. A cast to a named type is not reported, nor
// one of this.<method>'s result: that is the API client typing its own
// transport, the one place each endpoint gets its type.
type ResponseCastRule struct {
	*rules.BaseRule
}

// NewResponseCastRule creates the rule
func NewResponseCastRule() *ResponseCastRule {
	return &ResponseCastRule{BaseRule: rules.NewBaseRule(
		"response-cast-untyped",
		"patterns",
		"Detects an awaited call's result cast to any or to an inline object type — the shape read is asserted, not checked against the API's type",
		core.SeverityMedium,
	)}
}

var (
	untypedCast = regexp.MustCompile(`\)\s*as\s+(?:unknown\s+as\s+)?(?:any\b|\{)`)
	awaitedCall = regexp.MustCompile(`\bawait\s+[A-Za-z_$][\w$.]*(?:\s*<[^()]*>)?\s*$`)
	startsAwait = regexp.MustCompile(`^\s*await\b`)
	calleeTail  = regexp.MustCompile(`[\w$\]>]\s*$`)
	keywordTail = regexp.MustCompile(`\b(?:return|yield|typeof|in|of|await|case|throw)\s*$`)
)

// AnalyzeFile reports the untyped casts of awaited results in a TS file.
func (r *ResponseCastRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() || ctx.IsTestFile() || isE2EPath(ctx.RelPath) {
		return nil
	}
	code := newJSSource(ctx).code
	var violations []*core.Violation
	for i, line := range code {
		for _, m := range untypedCast.FindAllStringIndex(line, -1) {
			openLine, openCol, ok := jsMatchingOpen(code, i, m[0])
			if !ok || !awaitedResult(code, openLine, openCol, i, m[0]) {
				continue
			}
			if ctx.IsSuppressed(i+1, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, i+1,
				"Awaited result cast to any or to a shape written here — a field the server names differently reads undefined, and nothing reports it")
			v.WithCode(strings.TrimSpace(ctx.Lines[i]))
			v.WithSuggestion("Type the call with the API's contract type (a generated type, the client's generic parameter) and drop the cast")
			violations = append(violations, v)
		}
	}
	return violations
}

// awaitedResult reports a parenthesis pair that is an awaited call's
// arguments, or that wraps an awaited expression.
func awaitedResult(code []string, openLine, openCol, closeLine, closeCol int) bool {
	before := code[openLine][:openCol]
	if calleeTail.MatchString(before) && !keywordTail.MatchString(before) {
		m := awaitedCall.FindString(before)
		return m != "" && !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(m), "await")), "this.")
	}
	return startsAwait.MatchString(jsSpan(code, openLine, openCol+1, closeLine, closeCol))
}

// jsMatchingOpen returns the position of the '(' that the ')' at (line, col)
// of the code view closes.
func jsMatchingOpen(code []string, line, col int) (int, int, bool) {
	depth := 0
	for i := line; i >= 0; i-- {
		to := len(code[i]) - 1
		if i == line {
			to = col
		}
		for j := to; j >= 0; j-- {
			switch code[i][j] {
			case ')':
				depth++
			case '(':
				depth--
				if depth == 0 {
					return i, j, true
				}
			}
		}
	}
	return 0, 0, false
}
