package patterns

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReactEffectAsyncWithoutCleanupRule())
	rules.Register(NewReactRenderBranchesOnWindowRule())
	rules.Register(NewReactSetStateUpdaterSideEffectRule())
	rules.Register(NewServiceWorkerRespondWithMaybeEmptyRule())
	rules.Register(NewPeriodicPageReloadRule())
	rules.Register(NewReactFetchedAmountStartsAtZeroRule())
}

// componentSetters maps the block of each component or hook to its state
// names and their setters: const [name, setName] = useState(...).
func componentSetters(f jsFlat) map[int]map[string]string {
	setters := make(map[int]map[string]string)
	for _, m := range reactStatePair.FindAllStringSubmatchIndex(f.code, -1) {
		scope := f.enclosingBrace(m[0])
		if setters[scope] == nil {
			setters[scope] = make(map[string]string)
		}
		setters[scope][f.code[m[2]:m[3]]] = f.code[m[4]:m[5]]
	}
	return setters
}

func newFrontendViolation(rule *rules.BaseRule, ctx *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := rule.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	return v
}

// ReactEffectAsyncWithoutCleanupRule detects an effect that loads data
// asynchronously and writes it to state with nothing to stop a late answer:
//
//	useEffect(() => {
//	  const load = async () => { const r = await api.get(`/address?network=${network}`); setAddress(r.address) }
//	  load()
//	}, [network])
//
// When the dependency changes before the answer arrives, the answer for the
// old value lands after the one for the new value and overwrites it. A
// cleanup that aborts the request (AbortController), a flag the cleanup
// clears (let active = true ... return () => { active = false }) or a request
// id compared with the latest settles it. An effect with an empty dependency
// list runs once and is not reported.
type ReactEffectAsyncWithoutCleanupRule struct{ *rules.BaseRule }

// NewReactEffectAsyncWithoutCleanupRule creates the rule
func NewReactEffectAsyncWithoutCleanupRule() *ReactEffectAsyncWithoutCleanupRule {
	return &ReactEffectAsyncWithoutCleanupRule{rules.NewBaseRule(
		"react-effect-async-without-cleanup",
		"patterns",
		"Detects an effect that awaits a load and sets state with no cleanup to abort it or ignore a late answer — a stale response overwrites the current one",
		core.SeverityMedium,
	)}
}

var (
	jsAsyncWork = regexp.MustCompile(`\bawait\b|\.then\s*\(`)
	// jsThenCallback matches the text before the brace of a function passed
	// straight to .then.
	jsThenCallback = regexp.MustCompile(`\.then\s*\(\s*(?:async\s+)?(?:(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>|function\b[^{]*)\s*$`)
	// jsEffectCleanup is what settles a late answer: an abort, a cleanup, a
	// flag the cleanup clears, a mounted ref, a request id compared with the
	// latest, or a ref that lets the effect run once.
	jsEffectCleanup = regexp.MustCompile(`AbortController|\bsignal\b|\breturn\s*(?:\([^()]*\)\s*=>|function\b|[A-Za-z_$][\w$]*\s*(?:;|\n|$))|\b(?:cancell?ed|ignore|isActive|active|alive|stale|unsubscribed)\b|(?i:mounted)|[!=]==?\s*[A-Za-z_$][\w$]*\.current\b|\.current\s*=\s*true\b`)
	jsEmptyArray    = regexp.MustCompile(`^\s*\[\s*\]\s*$`)
	// jsStableDep names a dependency that keeps its identity across renders by
	// convention: the router, a dispatch, a state setter, a ref.
	jsStableDep = regexp.MustCompile(`^(?:router|navigate|dispatch|set[A-Z][\w$]*|[\w$]*Ref)$`)
)

// runsOnce reports a dependency list that never changes: empty, or made of
// stable values only.
func runsOnce(f jsFlat, deps jsSpanRange) bool {
	text := f.code[deps.start:deps.end]
	if jsEmptyArray.MatchString(text) {
		return true
	}
	idents := f.arrayIdents(deps)
	if len(idents) == 0 {
		return false
	}
	open, close := deps.start+strings.Index(text, "["), deps.start+strings.LastIndex(text, "]")
	if len(idents) != len(f.items(open, close)) {
		return false // a member access or a call among the dependencies
	}
	for _, dep := range idents {
		if !jsStableDep.MatchString(dep.name) {
			return false
		}
	}
	return true
}

// setsAfterLoad reports an effect body, starting at start, that calls the
// setter once a load answered.
func setsAfterLoad(f jsFlat, scope, start int, body, setter string) bool {
	call := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(setter) + `\s*\(`)
	for _, c := range call.FindAllStringIndex(body, -1) {
		if calledAfterLoad(f, scope, start+c[0]) {
			return true
		}
	}
	return false
}

// AnalyzeFile reports the effects of a file that set state after an await
// and never cancel.
func (r *ReactEffectAsyncWithoutCleanupRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !frontendSource(ctx) || !strings.Contains(string(ctx.Content), "useEffect") {
		return nil
	}
	f := newJSFlat(ctx)
	pairs := reactStatePair.FindAllStringSubmatchIndex(f.code, -1)
	var violations []*core.Violation
	for _, m := range reactEffect.FindAllStringSubmatchIndex(f.code, -1) {
		args := f.callArgs(m[1] - 1)
		if len(args) == 0 {
			continue
		}
		// An effect with no dependencies, or only ones that never change, runs
		// once: no newer answer for it to overwrite, and a late one after
		// unmount is dropped by React.
		if len(args) >= 2 && (runsOnce(f, args[len(args)-1]) || loadersRunOnce(f, f.enclosingBrace(m[0]), args[len(args)-1])) {
			continue
		}
		body := f.code[args[0].start:args[0].end]
		if jsEffectCleanup.MatchString(body) {
			continue
		}
		scope, setter := f.enclosingBrace(m[0]), ""
		// The load is the effect's own, or that of a useCallback loader of
		// the component the effect calls.
		loads := []jsSpanRange{args[0]}
		if !jsAsyncWork.MatchString(body) {
			loads = callbackLoaders(f, scope, body)
		}
		for _, load := range loads {
			loadBody := f.code[load.start:load.end]
			if load != args[0] && jsLoaderGuard.MatchString(loadBody) {
				continue
			}
			for _, pair := range pairs {
				if name := f.code[pair[4]:pair[5]]; f.enclosingBrace(pair[0]) == scope && setsAfterLoad(f, scope, load.start, loadBody, name) {
					setter = name
					break
				}
			}
			if setter != "" {
				break
			}
		}
		if setter == "" {
			continue
		}
		line := f.line(m[0])
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		violations = append(violations, newFrontendViolation(r.BaseRule, ctx, line,
			fmt.Sprintf("%s loads asynchronously and calls %s with no cleanup — an answer that arrives after the dependencies changed or the component unmounted still sets state", f.code[m[2]:m[3]], setter),
			"Abort the request in the cleanup (AbortController), or set a flag in the cleanup and skip the state update when it is cleared"))
	}
	return violations
}

// ReactRenderBranchesOnWindowRule detects markup that depends on typeof
// window:
//
//	{typeof window !== 'undefined' && isAuthenticated && <Links />}
//
// The server renders without window and the client's first render with it,
// so the HTML hydrates against a different tree; suppressHydrationWarning
// only hides the mismatch. Render the client-only part after mount (a
// useEffect that sets a flag) or with a dynamic import without SSR.
type ReactRenderBranchesOnWindowRule struct{ *rules.BaseRule }

// NewReactRenderBranchesOnWindowRule creates the rule
func NewReactRenderBranchesOnWindowRule() *ReactRenderBranchesOnWindowRule {
	return &ReactRenderBranchesOnWindowRule{rules.NewBaseRule(
		"react-render-branches-on-window",
		"patterns",
		"Detects JSX that branches on typeof window — server and client render different trees and hydration fails",
		core.SeverityMedium,
	)}
}

var jsxWindowBranch = regexp.MustCompile(`(?:^|[^$])(\{\s*\(?\s*typeof\s+window\s*[!=]==?\s*['"]undefined['"]\s*\)?\s*(?:&&|\?))`)

// AnalyzeFile reports the JSX expressions of a component file that test
// typeof window.
func (r *ReactRenderBranchesOnWindowRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !frontendSource(ctx) || (!strings.HasSuffix(ctx.RelPath, ".tsx") && !strings.HasSuffix(ctx.RelPath, ".jsx")) {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsxWindowBranch.FindAllStringSubmatchIndex(f.text, -1) {
		line := f.line(m[2])
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		violations = append(violations, newFrontendViolation(r.BaseRule, ctx, line,
			"JSX branches on typeof window — the server renders one tree and the client's first render another, and hydration fails",
			"Render the client-only part after mount (a mounted flag set in useEffect) or load it with a dynamic import without SSR"))
	}
	return violations
}

// ReactSetStateUpdaterSideEffectRule detects a state updater function with
// side effects:
//
//	setAttempt((cur) => { if (cur < max) { timer.current = setTimeout(connect, 1000); return cur + 1 }; setError(err); return cur })
//
// React may call an updater more than once (Strict Mode, a render that is
// thrown away), so the timer is scheduled twice and the other state set from
// inside. An updater returns the next value and does nothing else.
type ReactSetStateUpdaterSideEffectRule struct{ *rules.BaseRule }

// NewReactSetStateUpdaterSideEffectRule creates the rule
func NewReactSetStateUpdaterSideEffectRule() *ReactSetStateUpdaterSideEffectRule {
	return &ReactSetStateUpdaterSideEffectRule{rules.NewBaseRule(
		"react-setstate-updater-side-effect",
		"patterns",
		"Detects a setState updater function that schedules timers, writes refs, fetches or sets other state — React may run an updater twice",
		core.SeverityMedium,
	)}
}

var jsUpdaterSideEffect = regexp.MustCompile(`\b(?:setTimeout|setInterval|fetch)\s*\(|\.current\s*=[^=]`)

// AnalyzeFile reports the updater functions with side effects.
func (r *ReactSetStateUpdaterSideEffectRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !frontendSource(ctx) || !strings.Contains(string(ctx.Content), "useState") {
		return nil
	}
	f := newJSFlat(ctx)
	setters := componentSetters(f)
	var violations []*core.Violation
	for _, pair := range reactStatePair.FindAllStringSubmatchIndex(f.code, -1) {
		scope, setter := f.enclosingBrace(pair[0]), f.code[pair[4]:pair[5]]
		scopeEnd, ok := f.closing(scope)
		if scope < 0 || !ok {
			continue
		}
		updater := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(setter) + `\s*\(\s*(?:\(\s*[A-Za-z_$][\w$]*\s*(?::[^()]*)?\)|[A-Za-z_$][\w$]*)\s*=>\s*\{`)
		for _, m := range updater.FindAllStringIndex(f.code[scope:scopeEnd], -1) {
			start, open := scope+m[0], scope+m[1]-1
			closing, ok := f.closing(open)
			if !ok {
				continue
			}
			body := f.code[open+1 : closing]
			if !jsUpdaterSideEffect.MatchString(body) && !callsOtherSetter(body, setters[scope], setter) {
				continue
			}
			line := f.line(start)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, newFrontendViolation(r.BaseRule, ctx, line,
				fmt.Sprintf("The updater passed to %s has side effects — React may call it twice, and the timer, ref write or other state update runs twice", setter),
				"Compute the next value in the updater only; decide and run the side effects outside it, from the current value"))
		}
	}
	return violations
}

func callsOtherSetter(body string, states map[string]string, own string) bool {
	for _, setter := range states {
		if setter != own && callsFunction(body, setter) {
			return true
		}
	}
	return false
}

// ServiceWorkerRespondWithMaybeEmptyRule detects a fetch handler that answers
// with caches.match as is:
//
//	event.respondWith(fetch(event.request).catch(() => caches.match(event.request)))
//
// caches.match resolves undefined for a request that was never cached, and
// respondWith(undefined) fails the navigation with a network error — offline,
// the user gets the browser's error page instead of the app's offline page.
type ServiceWorkerRespondWithMaybeEmptyRule struct{ *rules.BaseRule }

// NewServiceWorkerRespondWithMaybeEmptyRule creates the rule
func NewServiceWorkerRespondWithMaybeEmptyRule() *ServiceWorkerRespondWithMaybeEmptyRule {
	return &ServiceWorkerRespondWithMaybeEmptyRule{rules.NewBaseRule(
		"service-worker-respond-with-maybe-empty",
		"patterns",
		"Detects respondWith answering with caches.match without a fallback — a request not in the cache gets undefined and fails",
		core.SeverityMedium,
	)}
}

var (
	jsRespondWith = regexp.MustCompile(`\brespondWith\s*\(`)
	jsCachesMatch = regexp.MustCompile(`(?:=>|\breturn)\s*caches\s*\.\s*match\s*\(`)
	jsHasFallback = regexp.MustCompile(`^\s*(?:\.\s*then\b|\|\||\?\?)`)
)

// AnalyzeFile reports the caches.match results a respondWith returns as is.
func (r *ServiceWorkerRespondWithMaybeEmptyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !frontendSource(ctx) || !strings.Contains(string(ctx.Content), "respondWith") {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsRespondWith.FindAllStringIndex(f.code, -1) {
		closing, ok := f.closing(m[1] - 1)
		if !ok {
			continue
		}
		for _, cm := range jsCachesMatch.FindAllStringIndex(f.code[m[1]:closing], -1) {
			open := m[1] + cm[1] - 1
			end, ok := f.closing(open)
			if !ok || jsHasFallback.MatchString(f.code[end+1:closing]) {
				continue
			}
			line := f.line(open)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, newFrontendViolation(r.BaseRule, ctx, line,
				"respondWith answers with caches.match as is — a request that is not cached resolves undefined and the navigation fails with a network error",
				"Fall back when the cache has nothing: caches.match(req).then(r => r || offlineResponse())"))
		}
	}
	return violations
}

// PeriodicPageReloadRule detects a page reload on a timer:
//
//	setInterval(function () { if (navigator.onLine) reload() }, 5000)
//
// While the failure that brought the page here lasts — a server down, a
// broken deploy — the page reloads forever, every few seconds, for every open
// tab. A reload tied to an event (online, a click) or to a budget kept in
// sessionStorage ends. The inline scripts of pages a service worker serves
// as strings are read too.
type PeriodicPageReloadRule struct{ *rules.BaseRule }

// NewPeriodicPageReloadRule creates the rule
func NewPeriodicPageReloadRule() *PeriodicPageReloadRule {
	return &PeriodicPageReloadRule{rules.NewBaseRule(
		"periodic-page-reload",
		"patterns",
		"Detects a page reload on setInterval — while the failure lasts the page reloads forever",
		core.SeverityMedium,
	)}
}

var jsSetInterval = regexp.MustCompile(`\bsetInterval\s*\(`)

// maxIntervalCallback bounds the text read as a setInterval callback.
const maxIntervalCallback = 2000

// AnalyzeFile reports the setInterval callbacks that reload the page.
func (r *PeriodicPageReloadRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !frontendSource(ctx) || !strings.Contains(string(ctx.Content), "reload") {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsSetInterval.FindAllStringIndex(f.text, -1) {
		callback := parenthesizedText(f.text, m[1]-1, maxIntervalCallback)
		if !jsReloadCall.MatchString(callback) {
			continue
		}
		line := f.line(m[0])
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		violations = append(violations, newFrontendViolation(r.BaseRule, ctx, line,
			"The page reloads on a timer — while the failure lasts it reloads forever",
			"Reload on an event (online, a click), or keep a reload budget in sessionStorage and stop when it is spent"))
	}
	return violations
}

var jsReloadCall = regexp.MustCompile(`\breload\s*(?:\(|,|\))`)

// parenthesizedText returns the text inside the parentheses opening at open,
// or up to limit bytes of it when they do not close. It reads the text view,
// where the code of a script kept in a string is visible.
func parenthesizedText(text string, open, limit int) string {
	depth := 0
	for i := open; i < len(text) && i-open < limit; i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return text[open+1 : i]
			}
		}
	}
	end := open + limit
	if end > len(text) {
		end = len(text)
	}
	return text[open+1 : end]
}

// ReactFetchedAmountStartsAtZeroRule detects an amount kept in state that
// starts at 0 and only a load fills:
//
//	const [availableBalance, setAvailableBalance] = useState(0)
//	useEffect(() => { load().then(r => setAvailableBalance(r.available)) }, [])
//
// Until the request answers, the page renders a real zero: "no funds", an
// empty state, a disabled button, an analytics event with balance 0. Start
// at null and render a loading state until the value arrives.
type ReactFetchedAmountStartsAtZeroRule struct{ *rules.BaseRule }

// NewReactFetchedAmountStartsAtZeroRule creates the rule
func NewReactFetchedAmountStartsAtZeroRule() *ReactFetchedAmountStartsAtZeroRule {
	return &ReactFetchedAmountStartsAtZeroRule{rules.NewBaseRule(
		"react-fetched-amount-starts-at-zero",
		"patterns",
		"Detects a money state that starts at 0 and is set only from a load — until it answers the page shows a real zero",
		core.SeverityMedium,
	)}
}

// reactAmountName is a state name for an amount of money; a total of items,
// pages or rows is a count, which 0 describes truthfully enough.
var reactAmountName = regexp.MustCompile(`(?i)balance|amount|funds|price|usd|cost|fee|profit|payout|equity|apy|yield`)

var reactZeroState = regexp.MustCompile(`\bconst\s*\[\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\]\s*=\s*(?:React\s*\.\s*)?useState\s*(?:<\s*number\s*>)?\s*\(\s*0\s*\)`)

// AnalyzeFile reports the zero-initialized amounts only a load sets.
func (r *ReactFetchedAmountStartsAtZeroRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !frontendSource(ctx) || !strings.Contains(string(ctx.Content), "useState") {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range reactZeroState.FindAllStringSubmatchIndex(f.code, -1) {
		name, setter := f.code[m[2]:m[3]], f.code[m[4]:m[5]]
		if !reactAmountName.MatchString(name) || !setOnlyAfterLoad(f, f.enclosingBrace(m[0]), setter) {
			continue
		}
		line := f.line(m[0])
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		violations = append(violations, newFrontendViolation(r.BaseRule, ctx, line,
			fmt.Sprintf("'%s' starts at 0 and only a load sets it — until the request answers the page shows a real zero", name),
			"Start at null and render a loading state until the value arrives"))
	}
	return violations
}

// setOnlyAfterLoad reports a setter that the component calls at least once,
// every time after an await or inside a .then callback.
func setOnlyAfterLoad(f jsFlat, scope int, setter string) bool {
	call := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(setter) + `\s*\(`)
	scopeEnd, ok := f.closing(scope)
	if scope < 0 || !ok {
		return false
	}
	calls := call.FindAllStringIndex(f.code[scope:scopeEnd], -1)
	for _, c := range calls {
		if !calledAfterLoad(f, scope, scope+c[0]) {
			return false
		}
	}
	return len(calls) > 0
}

// calledAfterLoad reports a call at pos that runs once a load answered: after
// an await in its function, or inside a .then callback. A call made directly
// in the block at scope is not.
func calledAfterLoad(f jsFlat, scope, pos int) bool {
	fn, found := f.enclosingFunction(pos)
	if !found || fn.brace <= scope {
		return false
	}
	return strings.Contains(f.code[fn.brace:pos], "await") ||
		jsThenCallback.MatchString(f.code[max(scope, fn.start-40):fn.brace]) ||
		strings.Contains(f.code[max(scope, pos-80):pos], ".then(")
}

var (
	jsCallName       = regexp.MustCompile(`(?:^|[^\w$.])([A-Za-z_$][\w$]*)\s*\((\s*\))?`)
	jsCallbackLoader = `\bconst\s+%s\s*=\s*(?:React\s*\.\s*)?useCallback\s*\(\s*async\b`
	// jsLoaderGuard is what lets a loader drop a late answer: an abort, a
	// flag, or a request id compared with the latest.
	jsLoaderGuard = regexp.MustCompile(`AbortController|\bsignal\b|\b(?:cancell?ed|ignore|isActive|active|alive|stale|unsubscribed)\b|(?i:mounted)|[!=]==?\s*[A-Za-z_$][\w$]*\.current\b|\.current\s*[!=]==?`)
)

// loadersRunOnce reports effect dependencies that are all useCallback
// loaders of the component whose own dependencies never change: the loaders
// keep their identity, and the effect runs once.
func loadersRunOnce(f jsFlat, scope int, deps jsSpanRange) bool {
	idents := f.arrayIdents(deps)
	text := f.code[deps.start:deps.end]
	open, close := deps.start+strings.Index(text, "["), deps.start+strings.LastIndex(text, "]")
	if len(idents) == 0 || len(idents) != len(f.items(open, close)) {
		return false
	}
	for _, dep := range idents {
		def := regexp.MustCompile(fmt.Sprintf(jsCallbackLoader, regexp.QuoteMeta(dep.name))).FindStringIndex(f.code)
		if def == nil || f.enclosingBrace(def[0]) != scope {
			return false
		}
		args := f.callArgs(def[0] + strings.Index(f.code[def[0]:], "("))
		if len(args) < 2 || !runsOnce(f, args[len(args)-1]) {
			return false
		}
	}
	return true
}

// callbackLoaders returns the bodies of the async useCallback functions of
// the component at scope that an effect body calls: useEffect(() => {
// loadData() }, [loadData]) loads through them. A loader whose dependencies
// never change, called with no arguments, asks the same thing every time: a
// late answer is not one for another key.
func callbackLoaders(f jsFlat, scope int, body string) []jsSpanRange {
	var loads []jsSpanRange
	seen := make(map[string]bool)
	for _, call := range jsCallName.FindAllStringSubmatch(body, -1) {
		name, noArgs := call[1], call[2] != ""
		if seen[name] {
			continue
		}
		seen[name] = true
		def := regexp.MustCompile(fmt.Sprintf(jsCallbackLoader, regexp.QuoteMeta(name))).FindStringIndex(f.code)
		if def == nil || f.enclosingBrace(def[0]) != scope {
			continue
		}
		args := f.callArgs(def[0] + strings.Index(f.code[def[0]:], "("))
		if len(args) == 0 || (noArgs && len(args) >= 2 && runsOnce(f, args[len(args)-1])) {
			continue
		}
		loads = append(loads, args[0])
	}
	return loads
}
