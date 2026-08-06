package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewE2EBlindWaitRule())
}

// E2EBlindWaitRule detects browser-test waits that are not tied to the fact under test:
// `waitForLoadState('networkidle')`, `goto(..., { waitUntil: 'networkidle' })` and
// `waitForTimeout(N)`.
//
// Такое ожидание врёт в обе стороны. На странице с фоновыми запросами тишина в сети
// не наступает вовсе, и тест падает по таймауту, ничего не проверив; на странице,
// которая рисует данные вторым кадром, тишина наступает раньше отрисовки, и тест
// читает пустую разметку. Слепая пауза `waitForTimeout` добавляет к этому зависимость
// от скорости машины.
//
// Проверяемый факт всегда конкретен: появился локатор, сменился URL, пришло значение.
// На него и надо ждать — тогда ожидание и есть проверка.
//
// Третий случай того же семейства — проверка нового URL сразу после действия,
// которое этот переход запускает. Клиентский роутер уводит со страницы асинхронно,
// поэтому `expect(page.url()).toContain('/onboarding')` читает ещё старый адрес;
// ждать надо сам переход через waitForURL.
//
// networkidle внутри try/catch не флагуется: там это мягкая синхронизация с явным
// запасным путём, а не единственное условие готовности.
type E2EBlindWaitRule struct {
	*rules.BaseRule

	networkIdle  *regexp.Regexp
	blindTimeout *regexp.Regexp
	tryStart     *regexp.Regexp
	testStart    *regexp.Regexp
	navigation   *regexp.Regexp
	urlWait      *regexp.Regexp
	urlAssert    *regexp.Regexp
	urlCapture   *regexp.Regexp
	varAssert    *regexp.Regexp
	gotoCall     *regexp.Regexp
	assertArg    *regexp.Regexp
}

// NewE2EBlindWaitRule creates the rule.
func NewE2EBlindWaitRule() *E2EBlindWaitRule {
	return &E2EBlindWaitRule{
		BaseRule: rules.NewBaseRule(
			"e2e-blind-wait",
			"patterns",
			"Detects browser-test waits not tied to the fact under test (networkidle, waitForTimeout)",
			core.SeverityMedium,
		),
		networkIdle:  regexp.MustCompile(`waitForLoadState\s*\(\s*['"` + "`" + `]networkidle|waitUntil\s*:\s*['"` + "`" + `]networkidle`),
		blindTimeout: regexp.MustCompile(`\bwaitForTimeout\s*\(`),
		tryStart:     regexp.MustCompile(`^\s*(?:\}\s*)?try\s*\{`),
		testStart:    regexp.MustCompile(`^\s*(?:it|test)(?:\.\w+)?\s*\(`),
		// Действия, после которых адрес меняет клиентский роутер, а не сервер.
		navigation: regexp.MustCompile(`\.(?:goto|click|dblclick|press|selectOption)\s*\(`),
		urlWait:    regexp.MustCompile(`waitForURL\s*\(`),
		// Позитивное утверждение о новом адресе: expect(page.url()).toContain('/x').
		// Отрицание (`.not.`) означает «переход не должен произойти» — там ждать нечего.
		urlAssert: regexp.MustCompile(`expect\s*\(\s*(?:[\w$]*[Pp]age)\s*\.\s*url\s*\(\s*\)\s*\)\s*\.\s*(?:to\w+)\s*\(`),
		// `const currentUrl = page.url()` — адрес снят в переменную, проверка ниже.
		urlCapture: regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[\w$]*[Pp]age)\s*\.\s*url\s*\(\s*\)`),
		varAssert:  regexp.MustCompile(`expect\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\.\s*(?:to\w+)\s*\(`),
		gotoCall:   regexp.MustCompile(`\.goto\s*\((.*)$`),
		assertArg:  regexp.MustCompile(`\.\s*to\w+\s*\(\s*(?:['"` + "`" + `]([^'"` + "`" + `]+)|([A-Za-z_$][\w$]*))`),
	}
}

// AnalyzeFile scans browser tests and their helpers line by line.
// navState tracks, inside one test case, what the test already did with the address bar.
type navState struct {
	navigated  bool
	urlAwaited bool
	lastGoto   string
	// Переменные, в которые адрес снят до ожидания перехода: проверка такой
	// переменной равносильна проверке page.url() на месте.
	staleURLVars map[string]bool
}

func newNavState() *navState {
	return &navState{staleURLVars: map[string]bool{}}
}

const urlAssertMessage = "Browser test asserts the new URL without waiting for the navigation it just triggered"
const urlAssertSuggestion = "Await the transition first: page.waitForURL(/expected/, { timeout }) — then the assertion reports behaviour, not timing"

// observe updates the navigation state from one line of a test.
func (r *E2EBlindWaitRule) observe(nav *navState, trimmed string) {
	if r.testStart.MatchString(trimmed) {
		// Границы теста: состояние про навигацию не переносится между кейсами.
		*nav = *newNavState()
	}
	if r.urlWait.MatchString(trimmed) {
		nav.urlAwaited = true
	}
	if m := r.urlCapture.FindStringSubmatch(trimmed); m != nil {
		if nav.navigated && !nav.urlAwaited {
			nav.staleURLVars[m[1]] = true
		} else {
			delete(nav.staleURLVars, m[1])
		}
	}
}

// advance records the navigation the line performs — it applies to the lines below, not this one.
func (r *E2EBlindWaitRule) advance(nav *navState, trimmed string) {
	if m := r.gotoCall.FindStringSubmatch(trimmed); m != nil {
		nav.lastGoto = m[1]
	}
	if r.navigation.MatchString(trimmed) {
		nav.navigated = true
	}
}

// assertsUnawaitedURL reports an assertion about an address the test never waited for.
func (r *E2EBlindWaitRule) assertsUnawaitedURL(nav *navState, trimmed string) bool {
	if strings.Contains(trimmed, ".not.") || r.assertsCurrentPage(trimmed, nav.lastGoto) {
		return false
	}
	if m := r.varAssert.FindStringSubmatch(trimmed); m != nil && nav.staleURLVars[m[1]] {
		return true
	}
	return r.urlAssert.MatchString(trimmed) && nav.navigated && !nav.urlAwaited
}

// AnalyzeFile scans browser tests and their helpers line by line.
func (r *E2EBlindWaitRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	// Хелперы ожидания живут рядом со спеками и в utils/, поэтому одного IsTestFile мало.
	if !ctx.IsTestFile() && !isE2EPath(ctx.RelPath) {
		return nil
	}

	var violations []*core.Violation
	depth := 0
	tryDepth := -1
	nav := newNavState()

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "*") {
			inTry := tryDepth >= 0 && depth >= tryDepth
			if r.networkIdle.MatchString(line) && !inTry {
				violations = append(violations, r.report(ctx, i+1,
					"Browser test waits for 'networkidle' — network silence is not the fact under test",
					"Wait for what the step produces: a locator (waitFor/toBeVisible), the URL (waitForURL), or a value via expect with a timeout"))
			}
			if r.blindTimeout.MatchString(line) {
				violations = append(violations, r.report(ctx, i+1,
					"Browser test pauses for a fixed time — the wait passes or fails by machine speed, not by behaviour",
					"Replace the pause with a wait for the expected state: locator.waitFor, page.waitForURL, or expect(...).toX({ timeout })"))
			}
			if r.tryStart.MatchString(trimmed) {
				tryDepth = depth + 1
			}
			r.observe(nav, trimmed)
			if r.assertsUnawaitedURL(nav, trimmed) {
				violations = append(violations, r.report(ctx, i+1, urlAssertMessage, urlAssertSuggestion))
			}
			r.advance(nav, trimmed)
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if tryDepth >= 0 && depth < tryDepth {
			tryDepth = -1
		}
	}

	return violations
}

// assertsCurrentPage reports whether the assertion names the address the test navigated to:
// такая проверка утверждает «мы остались здесь», перехода она не ждёт.
//
// Проверку, у которой ожидаемое значение не уместилось в строку, тоже пропускаем:
// разобрать её нечем, а обвинять тест по половине выражения нельзя.
func (r *E2EBlindWaitRule) assertsCurrentPage(line, lastGoto string) bool {
	m := r.assertArg.FindStringSubmatch(line)
	if m == nil {
		return true
	}
	if lastGoto == "" {
		return false
	}
	arg := m[1]
	if arg == "" {
		arg = m[2]
	}
	if arg == "" {
		return false
	}
	return strings.Contains(lastGoto, arg)
}

func (r *E2EBlindWaitRule) report(ctx *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", "e2e_blind_wait")
	return v
}

// isE2EPath reports whether the file belongs to a browser-test tree.
func isE2EPath(relPath string) bool {
	normalized := strings.ReplaceAll(relPath, "\\", "/")
	for _, marker := range []string{"/e2e/", "e2e/", "/playwright/", "playwright/", "/cypress/", "cypress/"} {
		if strings.HasPrefix(normalized, marker) || strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
