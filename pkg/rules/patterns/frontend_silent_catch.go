package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFrontendSilentCatchRule())
}

// FrontendSilentCatchRule detects frontend catch blocks that only log errors.
// UI code must either surface the failure to the user or rethrow it to a caller
// that can do so.
type FrontendSilentCatchRule struct {
	*rules.BaseRule
	catchStart       *regexp.Regexp
	loggerCall       *regexp.Regexp
	userFeedbackCall *regexp.Regexp
}

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
		userFeedbackCall: regexp.MustCompile(`\b(?:set[A-Za-z0-9_]*(?:Error|Message|Notice|Alert|Toast|Status)|toast\.|showToast\s*\(|alert\s*\(|throw\b|Promise\.reject\s*\()`),
	}
}

func (r *FrontendSilentCatchRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if r.shouldSkip(ctx) {
		return nil
	}

	var violations []*core.Violation
	for i := 0; i < len(ctx.Lines); i++ {
		line := ctx.Lines[i]
		if !r.catchStart.MatchString(line) {
			continue
		}

		block, end := collectBraceBlock(ctx.Lines, i)
		if end > i {
			i = end
		}
		if r.isSilentCatch(block) {
			violations = append(violations, r.violation(ctx, i+1, line))
		}
	}

	return violations
}

func collectBraceBlock(lines []string, start int) (string, int) {
	var builder strings.Builder
	depth := 0
	started := false
	for i := start; i < len(lines); i++ {
		line := lines[i]
		builder.WriteString(line)
		builder.WriteByte('\n')

		for _, char := range line {
			switch char {
			case '{':
				depth++
				started = true
			case '}':
				if started {
					depth--
				}
			}
		}
		if started && depth <= 0 {
			return builder.String(), i
		}
	}
	return builder.String(), start
}

func (r *FrontendSilentCatchRule) isSilentCatch(block string) bool {
	return r.loggerCall.MatchString(block) && !r.userFeedbackCall.MatchString(block)
}

func (r *FrontendSilentCatchRule) shouldSkip(ctx *core.FileContext) bool {
	path := ctx.RelPath
	if ctx.IsTestFile() {
		return true
	}
	return strings.Contains(path, "/node_modules/") ||
		(strings.Contains(path, "/e2e/") || strings.HasPrefix(path, "e2e/")) ||
		strings.Contains(path, "/.next/") ||
		strings.Contains(path, "/out/") ||
		strings.Contains(path, "/dist/") ||
		strings.Contains(path, "/generated/") ||
		strings.Contains(path, "generated-") ||
		strings.Contains(path, ".generated") ||
		strings.HasSuffix(path, "jest.setup.js")
}

func (r *FrontendSilentCatchRule) violation(ctx *core.FileContext, lineNum int, line string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, "Frontend catch block logs an error without user-visible handling")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Show the error via component state/toast/alert, or rethrow it to a caller that does so.")
	v.WithContext("pattern", "frontend-silent-catch")
	v.WithContext("language", "typescript")
	return v
}
