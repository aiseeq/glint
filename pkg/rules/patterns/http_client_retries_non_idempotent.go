package patterns

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
	fn    jsFunc
	scope int // the brace up to which the ifs around pos decide the retry
}

// AnalyzeFile reports the retry decisions that ignore the method.
func (r *HTTPClientRetriesNonIdempotentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || skipFrontendPath(ctx) {
		return nil
	}
	if !retryHTTPCall.Match(ctx.Content) {
		return nil
	}
	f := newJSFlat(ctx)

	reported := make(map[int]bool)
	var violations []*core.Violation
	for _, site := range retrySites(f) {
		body, ok := f.closing(site.fn.brace)
		if !ok {
			continue
		}
		fnText := f.text[site.fn.start : body+1]
		if !retryHTTPCall.MatchString(fnText) || !strings.Contains(strings.ToLower(fnText), "method") || retryIdemKey.MatchString(fnText) {
			continue
		}
		decision := retryDecision(f, site)
		if len(decision) == 0 || methodGuarded(f, site) {
			continue
		}
		line, aware := 0, false
		for _, span := range decision {
			text := f.text[span.start:span.end]
			if retryMethodAware.MatchString(text) {
				aware = true
				break
			}
			if loc := retryTransient.FindStringIndex(text); loc != nil {
				if l := f.line(span.start + loc[0]); line == 0 || l < line {
					line = l
				}
			}
		}
		if aware || line == 0 || reported[line] || ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		reported[line] = true
		name := site.fn.name
		if name == "" {
			name = "(anonymous)"
		}
		v := r.CreateViolation(ctx.RelPath, line, fmt.Sprintf(
			"'%s' sends the request again after a 5xx or a transport failure (retry at line %d) without checking its method — a POST the server already executed behind a timeout is executed twice",
			name, f.line(site.pos)))
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Retry only GET/HEAD/OPTIONS or a request carrying an idempotency key; let a failed write reach the caller")
		violations = append(violations, v)
	}
	return violations
}

// retrySites finds the calls of a function to itself with an attempt counter
// plus one, and the continue statements of loops counting attempts.
func retrySites(f jsFlat) []retrySite {
	var sites []retrySite
	for _, loc := range retryCounterNext.FindAllStringIndex(f.code, -1) {
		open, ok := f.enclosingParen(loc[0])
		if !ok {
			continue
		}
		callee := jsWordRef.FindAllString(f.code[max(0, open-80):open], -1)
		fn, ok := f.enclosingFunction(loc[0])
		if !ok || fn.name == "" || len(callee) == 0 || callee[len(callee)-1] != fn.name ||
			strings.TrimSpace(f.code[open-len(fn.name):open]) != fn.name {
			continue
		}
		sites = append(sites, retrySite{pos: loc[0], fn: fn, scope: fn.brace})
	}
	for _, loc := range retryContinue.FindAllStringIndex(f.code, -1) {
		for brace := f.enclosingBrace(loc[0]); brace >= 0; brace = f.enclosingBrace(brace) {
			head, _ := f.header(brace)
			if !jsControlHeader.MatchString(head) {
				break
			}
			if !strings.HasPrefix(head, "for") && !strings.HasPrefix(head, "while") {
				continue
			}
			if retryLoopHeader.MatchString(head) {
				if fn, ok := f.enclosingFunction(brace); ok {
					sites = append(sites, retrySite{pos: loc[0], fn: fn, scope: brace})
				}
			}
			break
		}
	}
	return sites
}

// enclosingParen returns the offset of the innermost '(' that holds pos.
func (f jsFlat) enclosingParen(pos int) (int, bool) {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch f.code[i] {
		case ')':
			depth++
		case '(':
			if depth == 0 {
				return i, true
			}
			depth--
		case '{', '}', ';':
			if depth == 0 {
				return 0, false
			}
		}
	}
	return 0, false
}

// retryDecision returns the conditions of the ifs between the retry and its
// scope — braced ones and an unbraced "if (...) return" right before it —
// with the initializers of the local constants they name, two levels deep.
func retryDecision(f jsFlat, site retrySite) []jsSpanRange {
	var conds []jsSpanRange
	for brace := f.enclosingBrace(site.pos); brace > site.scope; brace = f.enclosingBrace(brace) {
		if span, ok := f.ifCondition(brace); ok {
			conds = append(conds, span)
		}
	}
	if span, ok := unbracedIf(f, site.pos); ok {
		conds = append(conds, span)
	}

	decision := append([]jsSpanRange(nil), conds...)
	seen := make(map[string]bool)
	frontier := conds
	for level := 0; level < 2 && len(frontier) > 0; level++ {
		var next []jsSpanRange
		for _, span := range frontier {
			for _, loc := range jsWordRef.FindAllStringIndex(f.code[span.start:span.end], -1) {
				at := span.start + loc[0]
				name := f.code[at : span.start+loc[1]]
				if seen[name] || (at > 0 && f.code[at-1] == '.') {
					continue
				}
				seen[name] = true
				if init, ok := localInitializer(f, name, site.fn.brace, site.pos); ok {
					next = append(next, init)
				}
			}
		}
		decision = append(decision, next...)
		frontier = next
	}
	sort.Slice(decision, func(i, j int) bool { return decision[i].start < decision[j].start })
	return decision
}

// unbracedIf returns the condition of "if (...) return <retry>" that ends
// right before pos.
func unbracedIf(f jsFlat, pos int) (jsSpanRange, bool) {
	from := f.enclosingBrace(pos) + 1
	ifs := retryIfOpen.FindAllStringIndex(f.code[from:pos], -1)
	if len(ifs) == 0 {
		return jsSpanRange{}, false
	}
	span, ok := f.parenthesized(from+ifs[len(ifs)-1][0], pos)
	if !ok || span.end >= pos {
		return jsSpanRange{}, false
	}
	between := strings.Fields(f.code[span.end+1 : pos])
	for _, word := range between {
		if word != "return" && word != "await" && !strings.HasPrefix(word, "this.") && !jsIdentifier.MatchString(strings.TrimSuffix(word, "(")) {
			return jsSpanRange{}, false
		}
	}
	return span, true
}

// localInitializer returns the initializer of the last "const|let|var name ="
// in [from, to), unless it awaits: a request's result is not part of a
// decision about repeating it.
func localInitializer(f jsFlat, name string, from, to int) (jsSpanRange, bool) {
	decl := regexp.MustCompile(`\b(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\s*(?::[^=;\n]*)?=[^=>]`)
	locs := decl.FindAllStringIndex(f.code[from:to], -1)
	if len(locs) == 0 {
		return jsSpanRange{}, false
	}
	start := from + locs[len(locs)-1][1] - 1
	end := jsExpressionEnd(f.code, start)
	if strings.Contains(f.code[start:end], "await") {
		return jsSpanRange{}, false
	}
	return jsSpanRange{start, end}, true
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
func methodGuarded(f jsFlat, site retrySite) bool {
	from := site.scope
	for brace := f.enclosingBrace(site.pos); brace > site.scope; brace = f.enclosingBrace(brace) {
		from = brace
	}
	for _, loc := range retryIfOpen.FindAllStringIndex(f.code[from:site.pos], -1) {
		span, ok := f.parenthesized(from+loc[0], site.pos)
		if !ok || span.end >= site.pos {
			continue
		}
		if retryMethodAware.MatchString(f.text[span.start:span.end]) && retryExitAfter.MatchString(f.code[span.end+1:site.pos]) {
			return true
		}
	}
	return false
}
