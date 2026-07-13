package security

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSensitiveQueryParameterRule())
}

// SensitiveQueryParameterRule detects credentials and action tokens passed in
// URLs, where they can leak through logs, browser history, caches, and Referer.
type SensitiveQueryParameterRule struct {
	*rules.BaseRule
	queryGetter *regexp.Regexp
	urlLiteral  *regexp.Regexp
}

// NewSensitiveQueryParameterRule creates the rule.
func NewSensitiveQueryParameterRule() *SensitiveQueryParameterRule {
	sensitiveName := `(?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token|authz[_-]?token|api[_-]?key|secret|password|passwd|pwd|otp|otp[_-]?code)`
	return &SensitiveQueryParameterRule{
		BaseRule: rules.NewBaseRule(
			"sensitive-query-param",
			"security",
			"Detects credentials and action tokens exposed through URL query parameters",
			core.SeverityHigh,
		),
		queryGetter: regexp.MustCompile(`(?i)(?:query\(\)|searchparams)\s*\.\s*(?:get)\(\s*["']` + sensitiveName + `["']\s*\)`),
		urlLiteral:  regexp.MustCompile(`(?i)[?&]` + sensitiveName + `=`),
	}
}

// AnalyzeFile checks Go, JavaScript, and TypeScript source files.
func (r *SensitiveQueryParameterRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() && !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation
	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}
		lineNum := i + 1
		if ctx.IsSuppressed(lineNum, r.Name()) {
			continue
		}

		pattern := ""
		switch {
		case r.queryGetter.MatchString(line):
			pattern = "query-read"
		case r.urlLiteral.MatchString(line):
			pattern = "url-literal"
		default:
			continue
		}

		v := r.CreateViolation(ctx.RelPath, lineNum,
			"Sensitive value exposed through URL query parameter")
		v.WithCode("sensitive query parameter usage")
		v.WithSuggestion("Use an Authorization header, secure cookie, POST body, or URL fragment when the server does not need the value")
		v.WithContext("pattern", pattern)
		v.WithContext("cwe", "CWE-598")
		violations = append(violations, v)
	}
	return violations
}
