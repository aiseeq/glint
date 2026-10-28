package httprules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewHTTPClientRetriesNonIdempotentRule())
}

// HTTPClientRetriesNonIdempotentRule detects a TS/JS request function that
// sends a request again after a 5xx or a transport failure (timeout, network,
// abort) without asking which method the request has:
//
//	const retry = status === 502 || status === 504 || text.includes('timeout')
//	if (retry && attempt < 3) return this.request(path, method, body, attempt + 1)
//
// A 504 from a proxy or a dropped response does not mean the server did
// nothing: a POST that created a withdrawal is created a second time. The
// repeat is safe for GET/HEAD/OPTIONS or a request carrying an idempotency
// key; a decision, or an early exit before it, that names the method or
// idempotency keeps the rule silent. A function that never mentions a method
// sends GET only and is not reported.
//
// A retry is a call of the enclosing function itself with an attempt counter
// plus one, or a continue in a loop counting attempts; the decision is every
// if around it, with the local constants its condition names.
type HTTPClientRetriesNonIdempotentRule struct {
	*rules.BaseRule
}

// NewHTTPClientRetriesNonIdempotentRule creates the rule
func NewHTTPClientRetriesNonIdempotentRule() *HTTPClientRetriesNonIdempotentRule {
	return &HTTPClientRetriesNonIdempotentRule{BaseRule: rules.NewBaseRule(
		"http-client-retries-non-idempotent",
		"patterns",
		"Detects a request function that retries after a 5xx or a timeout whatever the method — a POST the server already executed is sent again",
		core.SeverityHigh,
	)}
}

var (
	retryCounterNext = regexp.MustCompile(`(?i)\b[\w$]*(?:retr|attempt|tries)[\w$]*\s*\+\s*1\b`)
	retryLoopHeader  = regexp.MustCompile(`(?i)^(?:for|while)\s*\(.*(?:retr|attempt|tries)`)
	retryContinue    = regexp.MustCompile(`\bcontinue\b`)
	retryTransient   = regexp.MustCompile(`(?i)\b5\d\d\b|time.?out|network|abort|econn|fetch`)
	retryMethodAware = regexp.MustCompile(`(?i)method|idempot|['"](?:GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)['"]`)
	retryExitAfter   = regexp.MustCompile(`^\s*\{?\s*(?:throw|return|break)\b`)
	retryHTTPCall    = regexp.MustCompile(`(?i)\bfetch\w*\s*\(|\baxios\b|\.request\s*\(|XMLHttpRequest`)
	retryIdemKey     = regexp.MustCompile(`(?i)idempotency[-_ ]?key`)
	retryIfOpen      = regexp.MustCompile(`\bif\s*\(`)
	jsWordRef        = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
)

// retrySite is one place that sends the request again.
type retrySite struct {
	pos   int
	fn    patternkit.JsFunc
	scope int // the brace up to which the ifs around pos decide the retry
}

// AnalyzeFile reports the retry decisions that ignore the method.
func (r *HTTPClientRetriesNonIdempotentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || patternkit.SkipFrontendPath(ctx) {
		return nil
	}
	if !retryHTTPCall.Match(ctx.Content) {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)

	reported := make(map[int]bool)
	var violations []*core.Violation
	for _, site := range retrySites(f) {
		body, ok := f.Closing(site.fn.Brace)
		if !ok {
			continue
		}
		fnText := f.Text[site.fn.Start : body+1]
		if !retryHTTPCall.MatchString(fnText) || !strings.Contains(strings.ToLower(fnText), "method") || retryIdemKey.MatchString(fnText) {
			continue
		}
		decision := retryDecision(f, site)
		if len(decision) == 0 || methodGuarded(f, site) {
			continue
		}
		line, aware := 0, false
		for _, span := range decision {
			text := f.Text[span.Start:span.End]
			if retryMethodAware.MatchString(text) {
				aware = true
				break
			}
			if loc := retryTransient.FindStringIndex(text); loc != nil {
				if l := f.Line(span.Start + loc[0]); line == 0 || l < line {
					line = l
				}
			}
		}
		if aware || line == 0 || reported[line] || ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		reported[line] = true
		name := site.fn.Name
		if name == "" {
			name = "(anonymous)"
		}
		v := r.CreateViolation(ctx.RelPath, line, fmt.Sprintf(
			"'%s' sends the request again after a 5xx or a transport failure (retry at line %d) without checking its method — a POST the server already executed behind a timeout is executed twice",
			name, f.Line(site.pos)))
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Retry only GET/HEAD/OPTIONS or a request carrying an idempotency key; let a failed write reach the caller")
		violations = append(violations, v)
	}
	return violations
}

// retrySites finds the calls of a function to itself with an attempt counter
// plus one, and the continue statements of loops counting attempts.
func retrySites(f patternkit.JsFlat) []retrySite {
	var sites []retrySite
	for _, loc := range retryCounterNext.FindAllStringIndex(f.Code, -1) {
		open, ok := f.EnclosingParen(loc[0])
		if !ok {
			continue
		}
		callee := jsWordRef.FindAllString(f.Code[max(0, open-80):open], -1)
		fn, ok := f.EnclosingFunction(loc[0])
		if !ok || fn.Name == "" || len(callee) == 0 || callee[len(callee)-1] != fn.Name ||
			strings.TrimSpace(f.Code[open-len(fn.Name):open]) != fn.Name {
			continue
		}
		sites = append(sites, retrySite{pos: loc[0], fn: fn, scope: fn.Brace})
	}
	for _, loc := range retryContinue.FindAllStringIndex(f.Code, -1) {
		for brace := f.EnclosingBrace(loc[0]); brace >= 0; brace = f.EnclosingBrace(brace) {
			head, _ := f.Header(brace)
			if !patternkit.JsControlHeader.MatchString(head) {
				break
			}
			if !strings.HasPrefix(head, "for") && !strings.HasPrefix(head, "while") {
				continue
			}
			if retryLoopHeader.MatchString(head) {
				if fn, ok := f.EnclosingFunction(brace); ok {
					sites = append(sites, retrySite{pos: loc[0], fn: fn, scope: brace})
				}
			}
			break
		}
	}
	return sites
}

// retryDecision returns the conditions of the ifs between the retry and its
// scope — braced ones and an unbraced "if (...) return" right before it —
// with the initializers of the local constants they name, two levels deep.
func retryDecision(f patternkit.JsFlat, site retrySite) []patternkit.JsSpanRange {
	var conds []patternkit.JsSpanRange
	for brace := f.EnclosingBrace(site.pos); brace > site.scope; brace = f.EnclosingBrace(brace) {
		if span, ok := f.IfCondition(brace); ok {
			conds = append(conds, span)
		}
	}
	if span, ok := unbracedIf(f, site.pos); ok {
		conds = append(conds, span)
	}

	decision := append([]patternkit.JsSpanRange(nil), conds...)
	seen := make(map[string]bool)
	frontier := conds
	for level := 0; level < 2 && len(frontier) > 0; level++ {
		var next []patternkit.JsSpanRange
		for _, span := range frontier {
			for _, loc := range jsWordRef.FindAllStringIndex(f.Code[span.Start:span.End], -1) {
				at := span.Start + loc[0]
				name := f.Code[at : span.Start+loc[1]]
				if seen[name] || (at > 0 && f.Code[at-1] == '.') {
					continue
				}
				seen[name] = true
				if init, ok := localInitializer(f, name, site.fn.Brace, site.pos); ok {
					next = append(next, init)
				}
			}
		}
		decision = append(decision, next...)
		frontier = next
	}
	sort.Slice(decision, func(i, j int) bool { return decision[i].Start < decision[j].Start })
	return decision
}

// unbracedIf returns the condition of "if (...) return <retry>" that ends
// right before pos.
func unbracedIf(f patternkit.JsFlat, pos int) (patternkit.JsSpanRange, bool) {
	from := f.EnclosingBrace(pos) + 1
	ifs := retryIfOpen.FindAllStringIndex(f.Code[from:pos], -1)
	if len(ifs) == 0 {
		return patternkit.JsSpanRange{}, false
	}
	span, ok := f.Parenthesized(from+ifs[len(ifs)-1][0], pos)
	if !ok || span.End >= pos {
		return patternkit.JsSpanRange{}, false
	}
	between := strings.FieldsSeq(f.Code[span.End+1 : pos])
	for word := range between {
		if word != "return" && word != "await" && !strings.HasPrefix(word, "this.") && !patternkit.JsIdentifier.MatchString(strings.TrimSuffix(word, "(")) {
			return patternkit.JsSpanRange{}, false
		}
	}
	return span, true
}

// localInitializer returns the initializer of the last "const|let|var name ="
// in [from, to), unless it awaits: a request's result is not part of a
// decision about repeating it.
func localInitializer(f patternkit.JsFlat, name string, from, to int) (patternkit.JsSpanRange, bool) {
	decl := regexp.MustCompile(`\b(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\s*(?::[^=;\n]*)?=[^=>]`)
	locs := decl.FindAllStringIndex(f.Code[from:to], -1)
	if len(locs) == 0 {
		return patternkit.JsSpanRange{}, false
	}
	start := from + locs[len(locs)-1][1] - 1
	end := jsExpressionEnd(f.Code, start)
	if strings.Contains(f.Code[start:end], "await") {
		return patternkit.JsSpanRange{}, false
	}
	return patternkit.JsSpanRange{Start: start, End: end}, true
}

// jsExpressionEnd returns where the expression starting at start ends: a ';'
// or a closing bracket of the enclosing level, or a line break that neither
// ends in an operator nor is followed by one.
func jsExpressionEnd(code string, start int) int {
	depth := 0
	for i := start; i < len(code); i++ {
		switch c := code[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		case ';', ',':
			if depth == 0 {
				return i
			}
		case '\n':
			if depth > 0 {
				continue
			}
			before := strings.TrimSpace(code[start:i])
			after := strings.TrimSpace(code[i+1:])
			if !endsWithOperator(before) && !startsWithOperator(after) {
				return i
			}
		}
	}
	return len(code)
}

func endsWithOperator(s string) bool {
	return s == "" || strings.ContainsAny(s[len(s)-1:], "|&=+-*/?:<>!(,")
}

func startsWithOperator(s string) bool {
	return s != "" && strings.ContainsAny(s[:1], "|&?:.+-*/")
}

// methodGuarded reports an "if (<method>) throw|return|break" between the
// start of the retry's scope and the retry: the unsafe methods leave before
// the decision is taken.
func methodGuarded(f patternkit.JsFlat, site retrySite) bool {
	from := site.scope
	for brace := f.EnclosingBrace(site.pos); brace > site.scope; brace = f.EnclosingBrace(brace) {
		from = brace
	}
	for _, loc := range retryIfOpen.FindAllStringIndex(f.Code[from:site.pos], -1) {
		span, ok := f.Parenthesized(from+loc[0], site.pos)
		if !ok || span.End >= site.pos {
			continue
		}
		if retryMethodAware.MatchString(f.Text[span.Start:span.End]) && retryExitAfter.MatchString(f.Code[span.End+1:site.pos]) {
			return true
		}
	}
	return false
}
