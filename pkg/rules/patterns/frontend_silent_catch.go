package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewFrontendSilentCatchRule())
}

// FrontendSilentCatchRule detects frontend catch blocks that only log errors.
// UI code must either surface the failure to the user or rethrow it to a caller
// that can do so. A promise .catch handler is the same block: the logger
// itself (.catch(console.error)) or an arrow function that only logs. A
// logger is console, logger, or a file logger bound from createLogger or
// getLogger (const log = createLogger('page')). Handing the error back as a
// value (return errorText(err)), calling the caller's handler (onUnknown())
// or reloading counts as handling, and so does a try that only guards a
// best-effort side channel: storage, analytics, consent.
type FrontendSilentCatchRule struct {
	*rules.BaseRule
	catchStart       *regexp.Regexp
	userFeedbackCall *regexp.Regexp
}

// NewFrontendSilentCatchRule creates the rule
func NewFrontendSilentCatchRule() *FrontendSilentCatchRule {
	return &FrontendSilentCatchRule{
		BaseRule: rules.NewBaseRule(
			"frontend-silent-catch",
			"patterns",
			"Detects frontend catch blocks that log errors without user-visible handling",
			core.SeverityHigh,
		),
		catchStart:       regexp.MustCompile(`\bcatch\b(?:\s*\([^)]*\))?\s*\{`),
		userFeedbackCall: regexp.MustCompile(`\b(?:set[A-Za-z0-9_]*(?:Error|Errors|Err|Failed|Failure|Message|Notice|Alert|Toast|Status)|setShow[A-Z]|(?:say|notify|show[A-Z][A-Za-z0-9_]*|display[A-Z][A-Za-z0-9_]*)\s*\(|toast\.|showToast\s*\(|alert\s*\(|throw\b|Promise\.reject\s*\(|\bon[A-Z][A-Za-z0-9_]*\s*\(|(?:reload|retry|refetch|redirect|navigate)[A-Za-z0-9_]*\s*\(|router\.(?:push|replace)\s*\()`),
	}
}

// AnalyzeFile checks for catch blocks that log without user-visible handling
func (r *FrontendSilentCatchRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if r.shouldSkip(ctx) || sideChannelModule.MatchString(ctx.RelPath) {
		return nil
	}

	// Structure only: a brace or a "throw" inside a string or a comment is not code.
	code := helpers.FileJSCode(ctx)
	text := helpers.FileJSText(ctx)
	loggers := fileLoggers(code)

	var violations []*core.Violation
	reported := make(map[int]bool)
	for i, line := range code {
		for _, loc := range r.catchStart.FindAllStringIndex(line, -1) {
			open := loc[1] - 1 // the pattern ends with the block's '{'
			endLine, endCol, ok := jsBlockEnd(code, i, open)
			if !ok {
				continue
			}
			block := catchBlock{code: jsSpan(code, i, open, endLine, endCol), text: jsSpan(text, i, open, endLine, endCol), errName: caughtName(line[loc[0]:loc[1]])}
			if r.isSilentCatch(block, loggers) && !guardsSideChannel(code, i, loc[0]) && !reported[i] {
				reported[i] = true
				violations = append(violations, r.violation(ctx, i+1, ctx.Lines[i]))
			}
		}
	}
	src := jsSource{code: code, text: text}
	for i, line := range code {
		for _, loc := range promiseCatch.FindAllStringIndex(line, -1) {
			handler, ok := jsFirstArgument(src, i, loc[1]-1, 15)
			if ok && !reported[i] && !sideChannel.MatchString(chainBefore(code, i, loc[0])) && r.isSilentHandler(handler, loggers) {
				reported[i] = true
				violations = append(violations, r.violation(ctx, i+1, ctx.Lines[i]))
			}
		}
	}

	return violations
}

var (
	promiseCatch = regexp.MustCompile(`\.catch\s*\(`)
	// arrowHandler is an arrow function: (err) =>, err =>, async (e: unknown) =>.
	arrowHandler = regexp.MustCompile(`^(?:async\s*)?(?:\(\s*[\w$]*\s*(?::\s*[\w$]+)?\s*\)|[\w$]+)\s*=>`)
	// fileLoggerBinding is a logger made for the file: const log = createLogger('page').
	fileLoggerBinding = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:createLogger|getLogger|makeLogger)\s*\(`)
	// sideChannel is a best-effort channel whose failure the user need not see:
	// storage, analytics and consent, the service worker, a sign-out.
	sideChannel = regexp.MustCompile(`\b(?:localStorage|sessionStorage|analytics|Analytics|gtag|posthog|plausible|dataLayer|serviceWorker|registration\.update|signOut|logout|logOut)\b|[Cc]onsent`)
	// sideChannelModule is a module of such a channel.
	sideChannelModule = regexp.MustCompile(`(?i)(?:analytics|consent|telemetry|tracking)[^/]*$`)
	// failureReturn hands a failure back to the caller: return false, an
	// error key or text, a failed result.
	failureReturn = regexp.MustCompile(`\breturn\s+(?:false\b|['"` + "`" + `]|[^;\n]*(?:[Ff]ail|[Ee]rr))`)
)

// loggerSet is the logger objects of a file: console, logger and the file's
// own loggers.
type loggerSet struct{ call, bare *regexp.Regexp }

// fileLoggers returns the loggers of a file.
func fileLoggers(code []string) loggerSet {
	names := []string{"console", "logger"}
	for _, m := range fileLoggerBinding.FindAllStringSubmatch(strings.Join(code, "\n"), -1) {
		names = append(names, regexp.QuoteMeta(m[1]))
	}
	alt := strings.Join(names, "|")
	return loggerSet{
		call: regexp.MustCompile(`\b(?:` + alt + `)\.error\s*\(`),
		bare: regexp.MustCompile(`^(?:` + alt + `)\.error$`),
	}
}

// chainBefore returns the promise chain a .catch at (line, col) ends: the
// line up to it and the lines above it back to the start of the statement,
// at most a few.
func chainBefore(code []string, line, col int) string {
	chain := code[line][:col]
	for i := line - 1; i >= 0 && i >= line-8; i-- {
		above := strings.TrimSpace(code[i])
		if above == "" || strings.HasSuffix(above, ";") || strings.HasSuffix(above, "{") && !strings.HasSuffix(above, "=> {") {
			break
		}
		chain = code[i] + "\n" + chain
	}
	return chain
}

// guardsSideChannel reports a catch at (line, col) whose try block only
// touches a best-effort side channel.
func guardsSideChannel(code []string, line, col int) bool {
	flat := strings.Join(code[:line], "\n")
	if line < len(code) {
		flat += "\n" + code[line][:col]
	}
	closeBrace := strings.LastIndexByte(flat, '}')
	if closeBrace < 0 {
		return false
	}
	depth := 0
	for i := closeBrace; i >= 0; i-- {
		switch flat[i] {
		case '}':
			depth++
		case '{':
			depth--
			if depth == 0 {
				return strings.HasSuffix(strings.TrimRight(flat[:i], " \t\n"), "try") && sideChannel.MatchString(flat[i:closeBrace])
			}
		}
	}
	return false
}

// isSilentHandler reports a promise .catch handler that only logs: the logger
// itself, or an arrow function that logs and gives the user nothing.
func (r *FrontendSilentCatchRule) isSilentHandler(handler string, loggers loggerSet) bool {
	if loggers.bare.MatchString(handler) {
		return true
	}
	return arrowHandler.MatchString(handler) && r.isSilentCatch(catchBlock{code: handler, text: handler, errName: caughtName(handler)}, loggers)
}

// catchBlock is a catch block or a handler in the code view (literals
// blanked) and the text view, with the name it binds the error to.
type catchBlock struct {
	code, text, errName string
}

// caughtBinding is the name a catch clause or a handler binds the error to.
var caughtBinding = regexp.MustCompile(`^(?:catch\s*\(\s*|(?:async\s*)?\(?\s*)([A-Za-z_$][\w$]*)`)

// caughtName returns the error's name in a catch header or a handler, "" when
// it binds none.
func caughtName(head string) string {
	m := caughtBinding.FindStringSubmatch(strings.TrimSpace(head))
	if m == nil || m[1] == "catch" || m[1] == "async" {
		return ""
	}
	return m[1]
}

// errorStateSet is a state setter given an error state: setState({ kind:
// 'error' }), setPhase('failed').
var errorStateSet = regexp.MustCompile(`\bset[A-Z][\w$]*\s*\([^;\n]*['"](?:error|failed|failure)['"]`)

// isSilentCatch reports a block that logs and neither shows, rethrows nor
// hands the failure back to the caller in a return value.
func (r *FrontendSilentCatchRule) isSilentCatch(block catchBlock, loggers loggerSet) bool {
	if block.errName != "" && regexp.MustCompile(`\breturn\b[^;\n]*\b`+regexp.QuoteMeta(block.errName)+`\b`).MatchString(block.code) {
		return false
	}
	return loggers.call.MatchString(block.code) && !r.userFeedbackCall.MatchString(block.code) &&
		!failureReturn.MatchString(block.text) && !errorStateSet.MatchString(block.text)
}

func (r *FrontendSilentCatchRule) shouldSkip(ctx *core.FileContext) bool {
	return skipFrontendPath(ctx)
}

func (r *FrontendSilentCatchRule) violation(ctx *core.FileContext, lineNum int, line string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, "Frontend catch block logs an error without user-visible handling")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Show the error via component state/toast/alert, or rethrow it to a caller that does so.")
	v.WithContext("pattern", "frontend-silent-catch")
	v.WithContext("language", "typescript")
	return v
}
