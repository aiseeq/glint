package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTestAssertsWallClockRule())
	rules.Register(NewBrowserWaitAfterActionRule())
	rules.Register(NewBrowserRouteGlobGluedRule())
}

// jsTestFile reports a TS/JS file of a test tree.
func jsTestFile(ctx *core.FileContext) bool {
	return (ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile()) && (ctx.IsTestFile() || isE2EPath(ctx.RelPath))
}

// --- test-asserts-wall-clock -----------------------------------------------

// TestAssertsWallClockRule detects a test asserting that measured time stays
// under a bound:
//
//	const firstTime = performance.now() - startFirst
//	...
//	expect(secondTime).toBeLessThanOrEqual(firstTime * 2)
//
// The duration depends on the machine and its load, not on the code: the
// test fails on a busy CI runner for no fault. Assert the behaviour that
// makes it fast (a cache hit, a call count) instead.
type TestAssertsWallClockRule struct {
	*rules.BaseRule
	elapsedVar    *regexp.Regexp
	upperOnVar    *regexp.Regexp
	upperOnInline *regexp.Regexp
}

// NewTestAssertsWallClockRule creates the rule
func NewTestAssertsWallClockRule() *TestAssertsWallClockRule {
	clock := `(?:performance\.now|Date\.now)\s*\(\s*\)`
	return &TestAssertsWallClockRule{
		BaseRule: rules.NewBaseRule(
			"test-asserts-wall-clock",
			"patterns",
			"Detects a test asserting an upper bound on measured wall-clock time — it fails by machine load, not by behaviour",
			core.SeverityMedium,
		),
		elapsedVar:    regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*` + clock + `\s*-`),
		upperOnVar:    regexp.MustCompile(`expect\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\.\s*toBeLessThan(?:OrEqual)?\s*\(`),
		upperOnInline: regexp.MustCompile(`expect\s*\(\s*` + clock + `\s*-[^)]*\)\s*\.\s*toBeLessThan(?:OrEqual)?\s*\(`),
	}
}

// AnalyzeFile reports the wall-clock bounds of a test file.
func (r *TestAssertsWallClockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !jsTestFile(ctx) {
		return nil
	}
	code := newJSSource(ctx).code
	elapsed := make(map[string]bool)
	var violations []*core.Violation
	for i, line := range code {
		if m := r.elapsedVar.FindStringSubmatch(line); m != nil {
			elapsed[m[1]] = true
		}
		m := r.upperOnVar.FindStringSubmatch(line)
		if (m == nil || !elapsed[m[1]]) && !r.upperOnInline.MatchString(line) {
			continue
		}
		if ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		violations = append(violations, testReport(r.BaseRule, ctx, i+1,
			"Test asserts that measured time stays under a bound — the duration follows machine load, and the test fails on a busy runner",
			"Assert what makes it fast (a cache hit, how many times the slow call ran) instead of the stopwatch"))
	}
	return violations
}

// --- browser-wait-registered-after-action ----------------------------------

// BrowserWaitAfterActionRule detects a browser test that starts waiting for
// a response only after the action that sends the request:
//
//	await page.locator('button').click()
//	await page.waitForResponse(r => r.url().includes('/metrics'))
//
// A fast response arrives while click() is still being awaited; the wait
// then misses it and times out. Start the wait first and await both:
// const response = page.waitForResponse(...); await click(); await response.
type BrowserWaitAfterActionRule struct {
	*rules.BaseRule
	awaited *regexp.Regexp
	action  *regexp.Regexp
	wait    *regexp.Regexp
}

// NewBrowserWaitAfterActionRule creates the rule
func NewBrowserWaitAfterActionRule() *BrowserWaitAfterActionRule {
	return &BrowserWaitAfterActionRule{
		BaseRule: rules.NewBaseRule(
			"browser-wait-registered-after-action",
			"patterns",
			"Detects waitForResponse/waitForRequest/waitForEvent started after the awaited action that triggers it — a fast response is missed",
			core.SeverityMedium,
		),
		awaited: regexp.MustCompile(`^\s*await\s`),
		action:  regexp.MustCompile(`\.(?:click|dblclick|tap|press|fill|check|uncheck|selectOption|setInputFiles|goto|reload|submit)\s*\(`),
		wait:    regexp.MustCompile(`^\s*(?:(?:const|let|var)\s+[^=]+=\s*)?await\s+[\w$.]*\.waitFor(?:Response|Request|Event|Navigation)\s*\(`),
	}
}

// AnalyzeFile reports the waits started after their action.
func (r *BrowserWaitAfterActionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !jsTestFile(ctx) {
		return nil
	}
	code := newJSSource(ctx).code
	var violations []*core.Violation
	for i := 0; i < len(code); i++ {
		if !r.awaited.MatchString(code[i]) || r.wait.MatchString(code[i]) {
			continue
		}
		end := statementEnd(code, i)
		if !r.action.MatchString(strings.Join(code[i:end+1], " ")) {
			continue
		}
		next := end + 1
		for next < len(code) && strings.TrimSpace(code[next]) == "" {
			next++
		}
		if next >= len(code) || !r.wait.MatchString(code[next]) || ctx.IsSuppressed(next+1, r.Name()) {
			continue
		}
		violations = append(violations, testReport(r.BaseRule, ctx, next+1,
			"The wait starts after the action that triggers it has completed — a fast response arrives first and the wait times out",
			"Start the wait before the action: const response = page.waitForResponse(...); await action; await response"))
	}
	return violations
}

// statementEnd returns the line where the brackets opened on line i close.
func statementEnd(code []string, i int) int {
	depth := 0
	for j := i; j < len(code); j++ {
		depth += strings.Count(code[j], "(") + strings.Count(code[j], "{") + strings.Count(code[j], "[") -
			strings.Count(code[j], ")") - strings.Count(code[j], "}") - strings.Count(code[j], "]")
		if depth <= 0 {
			return j
		}
	}
	return len(code) - 1
}

// --- browser-route-glob-glued ----------------------------------------------

// BrowserRouteGlobGluedRule detects a Playwright URL glob whose ** touches
// other characters:
//
//	await page.route('**/factors**', handler)
//
// Playwright reads ** as "any path" only as a whole segment (**/ or /**);
// glued to a word it is a single * that stops at '/', so
// /factors/{id}/challenge is not matched and the request reaches the real
// service. Write '**/factors/**' or a regular expression.
//
// A glob ending in name** is reported when its handler looks for a sub-path
// of name; without one the glob matches what the test sends.
type BrowserRouteGlobGluedRule struct {
	*rules.BaseRule
	globCall    *regexp.Regexp
	pathLiteral *regexp.Regexp
	endsWith    *regexp.Regexp
}

// NewBrowserRouteGlobGluedRule creates the rule
func NewBrowserRouteGlobGluedRule() *BrowserRouteGlobGluedRule {
	quote := `['"` + "`" + `]`
	return &BrowserRouteGlobGluedRule{
		BaseRule: rules.NewBaseRule(
			"browser-route-glob-glued",
			"patterns",
			"Detects a Playwright route/waitForURL glob with ** glued to a word — it does not cross '/', so sub-paths slip past",
			core.SeverityMedium,
		),
		globCall:    regexp.MustCompile(`\.(?:route|unroute|waitForURL)\s*\(\s*(['"` + "`" + `])([^'"` + "`" + `]*)['"` + "`" + `]`),
		pathLiteral: regexp.MustCompile(quote + `(/[\w\-./]*)` + quote),
		endsWith:    regexp.MustCompile(`\.endsWith\s*\(\s*` + quote + `(/[\w\-./]*)` + quote),
	}
}

// AnalyzeFile reports the glued globs of a test file.
func (r *BrowserRouteGlobGluedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !jsTestFile(ctx) {
		return nil
	}
	source := newJSSource(ctx)
	var violations []*core.Violation
	for i, line := range source.text {
		for _, m := range r.globCall.FindAllStringSubmatch(line, -1) {
			glued, trailingName := gluedDoubleStar(m[2])
			if !glued || ctx.IsSuppressed(i+1, r.Name()) {
				continue
			}
			if trailingName != "" {
				handler := strings.Join(source.text[i:statementEnd(source.code, i)+1], " ")
				if !r.expectsSubPath(handler, trailingName) {
					continue
				}
			}
			violations = append(violations, testReport(r.BaseRule, ctx, i+1,
				"URL glob '"+m[2]+"' glues ** to a word — Playwright then reads it as * that stops at '/', and sub-paths are not matched",
				"Keep ** a whole segment ('**/factors/**') or use a regular expression"))
		}
	}
	return violations
}

// expectsSubPath reports a handler that looks for a URL below name: a path
// containing name/, or an endsWith whose last segment does not start with
// name. A glob ending in name** matches neither.
func (r *BrowserRouteGlobGluedRule) expectsSubPath(handler, name string) bool {
	for _, m := range r.pathLiteral.FindAllStringSubmatch(handler, -1) {
		if strings.Contains(m[1], name+"/") {
			return true
		}
	}
	for _, m := range r.endsWith.FindAllStringSubmatch(handler, -1) {
		last := m[1][strings.LastIndex(m[1], "/")+1:]
		if last != "" && !strings.HasPrefix(last, name) {
			return true
		}
	}
	return false
}

// gluedDoubleStar reports a ** with something other than '/' or an end on
// either side. For a glob ending in name** it also returns name, the segment
// the ** is glued to; a glob ending in ?** matches a query, where stopping
// at '/' is intended, and is not glued.
func gluedDoubleStar(glob string) (glued bool, trailingName string) {
	for i := 0; i+1 < len(glob); i++ {
		if glob[i] != '*' || glob[i+1] != '*' {
			continue
		}
		end := i + 2
		for end < len(glob) && glob[end] == '*' {
			end++
		}
		beforeOK := i == 0 || glob[i-1] == '/'
		afterOK := end == len(glob) || glob[end] == '/'
		switch {
		case beforeOK && afterOK, end == len(glob) && glob[i-1] == '?':
			i = end
		case end == len(glob):
			return true, glob[strings.LastIndex(glob[:i], "/")+1 : i]
		default:
			return true, ""
		}
	}
	return false, ""
}
