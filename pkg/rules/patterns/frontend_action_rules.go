package patterns

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFrontendActionOnlyLogsRule())
	rules.Register(NewFrontendInflightGuardFabricatesResultRule())
	rules.Register(NewFrontendCheckSkippedWhenMissingRule())
}

// FrontendActionOnlyLogsRule detects an async function in production frontend
// code whose body only writes to the console:
//
//	handleTransfer: async () => { console.warn('Deposits are being updated') },
//
// The caller awaits it, gets no error and goes on as if the work were done:
// the page reports a transfer that never left. An action that is not
// available must say so to its caller — throw, or remove it from the
// interface so the button disappears. An empty async function is left out:
// it is the usual placeholder of a context value before hydration.
type FrontendActionOnlyLogsRule struct {
	*rules.BaseRule
}

// NewFrontendActionOnlyLogsRule creates the rule
func NewFrontendActionOnlyLogsRule() *FrontendActionOnlyLogsRule {
	return &FrontendActionOnlyLogsRule{BaseRule: rules.NewBaseRule(
		"frontend-action-only-logs",
		"patterns",
		"Detects an async function in production frontend code that only logs — callers await it and take the work as done",
		core.SeverityMedium,
	)}
}

var (
	jsAsyncArrow    = regexp.MustCompile(`\basync\s*(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=;{}()]+)?=>\s*\{`)
	jsAsyncFunction = regexp.MustCompile(`\basync\s+(?:function\b\s*\*?\s*[A-Za-z_$]*|[A-Za-z_$][\w$]*)\s*\([^()]*\)\s*(?::\s*[^{;=()]+)?\{`)
	jsConsoleCall   = regexp.MustCompile(`\bconsole\s*\.\s*\w+\s*\(`)
)

// AnalyzeFile reports the async functions of a file that do nothing.
func (r *FrontendActionOnlyLogsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	seen := make(map[int]bool)
	for _, re := range []*regexp.Regexp{jsAsyncArrow, jsAsyncFunction} {
		for _, m := range re.FindAllStringIndex(f.code, -1) {
			brace := m[1] - 1
			if seen[brace] {
				continue
			}
			seen[brace] = true
			end, ok := f.closing(brace)
			if !ok {
				continue
			}
			body := f.code[brace+1 : end]
			if !jsConsoleCall.MatchString(body) || strings.TrimSpace(withoutCalls(body, jsConsoleCall)) != "" {
				continue
			}
			line := f.line(m[0])
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, "Async function only logs — the caller awaits it, gets no error and takes the work as done")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Throw an error that says the action is unavailable, or remove the action so the interface does not offer it")
			violations = append(violations, v)
		}
	}
	return violations
}

// withoutCalls removes from a code span the calls the pattern starts and the
// semicolons between statements.
func withoutCalls(span string, call *regexp.Regexp) string {
	var out strings.Builder
	for {
		loc := call.FindStringIndex(span)
		if loc == nil {
			out.WriteString(span)
			break
		}
		end, ok := closingIn(span, loc[1]-1)
		if !ok {
			out.WriteString(span)
			break
		}
		out.WriteString(span[:loc[0]])
		span = span[end+1:]
	}
	return strings.NewReplacer(";", "", ",", "").Replace(out.String())
}

// closingIn returns the offset in s of the bracket closing the one at open.
func closingIn(s string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// productionFrontendFile reports a TS/JS file outside tests, mocks and
// stories.
func productionFrontendFile(ctx *core.FileContext) bool {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || skipFrontendPath(ctx) {
		return false
	}
	path := "/" + strings.ToLower(filepath.ToSlash(ctx.RelPath))
	return !strings.Contains(path, "/__mocks__/") && !strings.Contains(path, "/mocks/") &&
		!strings.Contains(path, "/stubs/") && !strings.Contains(path, ".stories.")
}

// FrontendInflightGuardFabricatesResultRule detects a guard against a
// concurrent call that answers with a made-up result:
//
//	if (listInProgress.current) {
//	    return { needsMfa: false, factors: [] }
//	}
//	listInProgress.current = true
//
// The second caller gets "no MFA needed" while the real request is still
// running, and acts on it. Return the promise of the call in flight, or a
// result that says "busy", not a fabricated answer.
type FrontendInflightGuardFabricatesResultRule struct {
	*rules.BaseRule
}

// NewFrontendInflightGuardFabricatesResultRule creates the rule
func NewFrontendInflightGuardFabricatesResultRule() *FrontendInflightGuardFabricatesResultRule {
	return &FrontendInflightGuardFabricatesResultRule{BaseRule: rules.NewBaseRule(
		"frontend-inflight-guard-fabricates-result",
		"patterns",
		"Detects a guard against a concurrent call that returns a made-up result while the real call is still running",
		core.SeverityHigh,
	)}
}

var (
	jsBusyFlagIf     = regexp.MustCompile(`\bif\s*\(\s*([A-Za-z_$][\w$]*(?:\.current)?)\s*\)\s*`)
	busyFlagName     = regexp.MustCompile(`(?i)(inprogress|inflight|pending|loading|running|busy|fetching|submitting|saving|locked)`)
	jsFabricatedBody = regexp.MustCompile(`\breturn\s*(?:\{|\[|true\b|false\b|\d|'|"|` + "`" + `)`)
)

// AnalyzeFile reports the busy guards of a file that return a made-up value.
func (r *FrontendInflightGuardFabricatesResultRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsBusyFlagIf.FindAllStringSubmatchIndex(f.code, -1) {
		flag := f.code[m[2]:m[3]]
		if !busyFlagName.MatchString(flag) {
			continue
		}
		body, ok := f.statementAt(m[1])
		if !ok || !jsFabricatedBody.MatchString(f.text[body.start:body.end]) {
			continue
		}
		fn, ok := f.enclosingFunction(m[0])
		if !ok {
			continue
		}
		fnEnd, ok := f.closing(fn.brace)
		if !ok || !setsTrue(f.code[body.end:fnEnd], flag) {
			continue
		}
		line := f.line(m[0])
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, "While "+flag+" is set the call answers with a made-up result — the caller acts on it as if it were real")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Keep the promise of the call in flight and return it to the second caller, or return a result that says the call is busy")
		violations = append(violations, v)
	}
	return violations
}

// setsTrue reports an assignment flag = true in the code.
func setsTrue(code, flag string) bool {
	for from := 0; ; {
		at := strings.Index(code[from:], flag)
		if at < 0 {
			return false
		}
		at += from
		from = at + len(flag)
		if at > 0 && (isJSIdentByte(code[at-1]) || code[at-1] == '.') {
			continue
		}
		rest := strings.TrimLeft(code[from:], " \t")
		if !strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "==") {
			continue
		}
		value := strings.TrimLeft(rest[1:], " \t")
		if strings.HasPrefix(value, "true") && (len(value) == 4 || !isJSIdentByte(value[4])) {
			return true
		}
	}
}

func isJSIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// statementAt returns the statement that starts at pos: a block, or a single
// statement up to its ';' or line end.
func (f jsFlat) statementAt(pos int) (jsSpanRange, bool) {
	for pos < len(f.code) && (f.code[pos] == ' ' || f.code[pos] == '\t') {
		pos++
	}
	if pos >= len(f.code) {
		return jsSpanRange{}, false
	}
	if f.code[pos] == '{' {
		end, ok := f.closing(pos)
		return jsSpanRange{pos + 1, end}, ok
	}
	end := strings.IndexAny(f.code[pos:], ";\n")
	if end < 0 {
		end = len(f.code) - pos
	}
	return jsSpanRange{pos, pos + end}, true
}

// FrontendCheckSkippedWhenMissingRule detects a check that runs only when a
// dependency is there, while the other branch warns and goes on:
//
//	if (provider) {
//	    if (!await this.checkNetwork()) return false
//	} else {
//	    console.warn('Provider unavailable, proceeding')
//	}
//
// Without the dependency the code continues as if the check had passed. When
// the check matters, a missing dependency must stop the operation too.
type FrontendCheckSkippedWhenMissingRule struct {
	*rules.BaseRule
}

// NewFrontendCheckSkippedWhenMissingRule creates the rule
func NewFrontendCheckSkippedWhenMissingRule() *FrontendCheckSkippedWhenMissingRule {
	return &FrontendCheckSkippedWhenMissingRule{BaseRule: rules.NewBaseRule(
		"frontend-check-skipped-when-missing",
		"patterns",
		"Detects a check that runs only when a dependency is present while the else branch only warns and proceeds as if it had passed",
		core.SeverityMedium,
	)}
}

var (
	jsPresenceIf   = regexp.MustCompile(`\bif\s*\(\s*([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*)\s*\)\s*\{`)
	jsRejection    = regexp.MustCompile(`\breturn\s+false\b|\bthrow\b`)
	jsExit         = regexp.MustCompile(`\breturn\b|\bthrow\b`)
	jsNoticeCall   = regexp.MustCompile(`(?i)[\w$.]*(?:console\s*\.\s*\w+|toast|notify|notification|warn|alert|message|log)[\w$.]*\s*\(`)
	jsElseAfterEnd = regexp.MustCompile(`^\s*else\s*\{`)
)

// AnalyzeFile reports the checks of a file skipped without their dependency.
func (r *FrontendCheckSkippedWhenMissingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, m := range jsPresenceIf.FindAllStringIndex(f.code, -1) {
		thenOpen := m[1] - 1
		thenEnd, ok := f.closing(thenOpen)
		if !ok || !jsRejection.MatchString(f.code[thenOpen:thenEnd]) {
			continue
		}
		elseLoc := jsElseAfterEnd.FindStringIndex(f.code[thenEnd+1:])
		if elseLoc == nil {
			continue
		}
		elseOpen := thenEnd + 1 + elseLoc[1] - 1
		elseEnd, ok := f.closing(elseOpen)
		if !ok {
			continue
		}
		elseBody := f.code[elseOpen+1 : elseEnd]
		if jsExit.MatchString(elseBody) || !jsConsoleCall.MatchString(elseBody) ||
			strings.TrimSpace(withoutCalls(elseBody, jsNoticeCall)) != "" {
			continue
		}
		line := f.line(thenEnd + 1 + strings.Index(f.code[thenEnd+1:], "else"))
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, "Without the dependency the check is skipped: the else branch only warns and the operation goes on as if it had passed")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Stop the operation when the dependency is missing (return false or throw), the way the check itself does")
		violations = append(violations, v)
	}
	return violations
}
