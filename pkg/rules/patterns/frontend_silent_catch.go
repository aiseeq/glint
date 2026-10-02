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
// itself (.catch(console.error)) or an arrow function that only logs.
type FrontendSilentCatchRule struct {
	*rules.BaseRule
	catchStart       *regexp.Regexp
	loggerCall       *regexp.Regexp
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
		loggerCall:       regexp.MustCompile(`\b(?:console|logger)\.error\s*\(`),
		userFeedbackCall: regexp.MustCompile(`\b(?:set[A-Za-z0-9_]*(?:Error|Errors|Failed|Failure|Message|Notice|Alert|Toast|Status)|toast\.|showToast\s*\(|alert\s*\(|throw\b|Promise\.reject\s*\(|\bon[A-Za-z0-9_]*(?:Error|Failure|Failed|Fail)\s*\()`),
	}
}

// AnalyzeFile checks for catch blocks that log without user-visible handling
func (r *FrontendSilentCatchRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if r.shouldSkip(ctx) {
		return nil
	}

	// Structure only: a brace or a "throw" inside a string or a comment is not code.
	code := helpers.FileJSCode(ctx)

	var violations []*core.Violation
	reported := make(map[int]bool)
	for i, line := range code {
		for _, loc := range r.catchStart.FindAllStringIndex(line, -1) {
			open := loc[1] - 1 // the pattern ends with the block's '{'
			endLine, endCol, ok := jsBlockEnd(code, i, open)
			if !ok {
				continue
			}
			if r.isSilentCatch(jsSpan(code, i, open, endLine, endCol)) && !reported[i] {
				reported[i] = true
				violations = append(violations, r.violation(ctx, i+1, ctx.Lines[i]))
			}
		}
	}
	src := jsSource{code: code, text: helpers.FileJSText(ctx)}
	for i, line := range code {
		for _, loc := range promiseCatch.FindAllStringIndex(line, -1) {
			handler, ok := jsFirstArgument(src, i, loc[1]-1, 15)
			if ok && !reported[i] && r.isSilentHandler(handler) {
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
	bareLogger   = regexp.MustCompile(`^(?:console|logger)\.error$`)
)

// isSilentHandler reports a promise .catch handler that only logs: the logger
// itself, or an arrow function that logs and gives the user nothing.
func (r *FrontendSilentCatchRule) isSilentHandler(handler string) bool {
	if bareLogger.MatchString(handler) {
		return true
	}
	return arrowHandler.MatchString(handler) && r.isSilentCatch(handler)
}

// errorStateSet is a state setter given an error state: setState({ kind:
// 'error' }), setPhase('failed').
var errorStateSet = regexp.MustCompile(`\bset[A-Z][\w$]*\s*\([^;\n]*['"](?:error|failed|failure)['"]`)

func (r *FrontendSilentCatchRule) isSilentCatch(block string) bool {
	return r.loggerCall.MatchString(block) && !r.userFeedbackCall.MatchString(block) && !errorStateSet.MatchString(block)
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
