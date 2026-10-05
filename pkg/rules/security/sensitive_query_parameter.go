package security

import (
	"go/ast"
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
	sensitiveName := nameAlternation(bareTokenNames, tokenNames, apiKeyNames, apiSecretNames, secretNames, passwordNames, oneTimeCodeNames)
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

	// Needles every match contains: the getter needs query() or searchParams in
	// the file, a URL literal needs '=' after '?' or '&' on its line.
	lower := strings.ToLower(string(ctx.Content))
	getterPossible := strings.Contains(lower, "query()") || strings.Contains(lower, "searchparams")
	var violations []*core.Violation
	redirected := secretsInRedirects(ctx)
	for i, line := range ctx.Lines {
		urlPossible := strings.IndexByte(line, '=') >= 0 && strings.ContainsAny(line, "?&")
		if !getterPossible && !urlPossible && !redirected[i+1] {
			continue
		}
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
		case redirected[lineNum]:
			pattern = "redirect-value"
		case getterPossible && r.queryGetter.MatchString(line):
			pattern = "query-read"
		case urlPossible && r.urlLiteral.MatchString(line):
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

// secretVariableName names a variable holding a secret value: password,
// newPassword, tempToken, apiKey.
var secretVariableName = regexp.MustCompile(`(?i)^(?:new|temp|tmp|generated|plain|initial|raw|one_?time)?_?(?:password|passwd|secret|token|api_?key|otp)$`)

// secretsInRedirects returns the lines of calls to http.Redirect or a
// redirect helper (redirectUsers(w, r, "success", msg)) that are given a
// secret variable inside an argument: the helper puts the message into the
// query of the redirect URL, whatever the parameter is called.
func secretsInRedirects(ctx *core.FileContext) map[int]bool {
	lines := make(map[int]bool)
	if ctx.GoAST == nil {
		return lines
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !strings.Contains(strings.ToLower(calleeName(call)), "redirect") {
			return true
		}
		for _, arg := range call.Args {
			if mentionsSecretVariable(arg) {
				lines[ctx.LineFor(call)] = true
				break
			}
		}
		return true
	})
	return lines
}

// calleeName returns the name of the called function or method.
func calleeName(call *ast.CallExpr) string {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// mentionsSecretVariable reports an identifier with a secret's name in the
// expression; a field of another value (user.Password) counts too.
func mentionsSecretVariable(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && secretVariableName.MatchString(ident.Name) {
			found = true
		}
		return !found
	})
	return found
}
