package security

import (
	"go/ast"
	"go/token"
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
	// valuesKey matches a quoted url.Values key that names a credential.
	valuesKey *regexp.Regexp
	// paramsGetter is the get call of a sensitive name; its receiver must be
	// a variable holding the page's search params.
	paramsGetter *regexp.Regexp
}

// idTokenNames are the OpenID Connect token: a bearer credential of the user
// handed over in a redirect.
var idTokenNames = []string{`id[-_]?token`}

// searchParamsVariable is a variable that holds the search params of the
// page: new URLSearchParams(window.location.search), useSearchParams().
var searchParamsVariable = regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*(?:new\s+URLSearchParams\(\s*(?:window\.|document\.)?location\.search\s*\)|useSearchParams\(\s*\))`)

// NewSensitiveQueryParameterRule creates the rule.
func NewSensitiveQueryParameterRule() *SensitiveQueryParameterRule {
	sensitiveName := nameAlternation(bareTokenNames, tokenNames, idTokenNames, apiKeyNames, apiSecretNames, secretNames, passwordNames, oneTimeCodeNames)
	return &SensitiveQueryParameterRule{
		BaseRule: rules.NewBaseRule(
			"sensitive-query-param",
			"security",
			"Detects credentials and action tokens exposed through URL query parameters",
			core.SeverityHigh,
		),
		queryGetter:  regexp.MustCompile(`(?i)(?:query\(\)|searchparams)\s*\.\s*(?:get)\(\s*["']` + sensitiveName + `["']\s*\)`),
		urlLiteral:   regexp.MustCompile(`(?i)[?&]` + sensitiveName + `=`),
		valuesKey:    regexp.MustCompile(`(?i)^["` + "`" + `]` + sensitiveName + `["` + "`" + `]$`),
		paramsGetter: regexp.MustCompile(`(?i)\b(\w+)\s*\.\s*get\(\s*["']` + sensitiveName + `["']\s*\)`),
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
	for line := range r.valuesIntoRedirects(ctx) {
		redirected[line] = true
	}
	paramsVars := searchParamsVariables(ctx)
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
		case getterPossible && (r.queryGetter.MatchString(line) || r.readsParamsVariable(line, paramsVars)):
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

// searchParamsVariables returns the names of the variables of a JavaScript or
// TypeScript file that hold the page's search params.
func searchParamsVariables(ctx *core.FileContext) map[string]bool {
	names := make(map[string]bool)
	if ctx.IsGoFile() {
		return names
	}
	for _, m := range searchParamsVariable.FindAllStringSubmatch(string(ctx.Content), -1) {
		names[m[1]] = true
	}
	return names
}

// readsParamsVariable reports a line that gets a sensitive name from a
// variable holding the page's search params.
func (r *SensitiveQueryParameterRule) readsParamsVariable(line string, vars map[string]bool) bool {
	for _, m := range r.paramsGetter.FindAllStringSubmatch(line, -1) {
		if vars[m[1]] {
			return true
		}
	}
	return false
}

// valuesIntoRedirects returns the lines of url.Values literals with a
// credential key that reach a redirect call of the same function, directly or
// through the variable the redirect is given: the values become the query of
// the URL the browser is sent to. Values encoded after a '#' are the fragment,
// which the browser does not send.
func (r *SensitiveQueryParameterRule) valuesIntoRedirects(ctx *core.FileContext) map[int]bool {
	lines := make(map[int]bool)
	if ctx.GoAST == nil {
		return lines
	}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		assigned := make(map[string][]ast.Expr)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
				for i, lhs := range as.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						assigned[ident.Name] = append(assigned[ident.Name], as.Rhs[i])
					}
				}
			}
			return true
		})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !strings.Contains(strings.ToLower(calleeName(call)), "redirect") {
				return true
			}
			for _, arg := range call.Args {
				exprs := []ast.Expr{arg}
				if ident, ok := ast.Unparen(arg).(*ast.Ident); ok {
					exprs = append(exprs, assigned[ident.Name]...)
				}
				for _, expr := range exprs {
					r.queryValuesKeys(expr, func(key ast.Expr) { lines[ctx.LineFor(key)] = true })
				}
			}
			return true
		})
	}
	return lines
}

// queryValuesKeys calls found for every credential key of a url.Values
// literal in expr that is not encoded after a '#' of a concatenation.
func (r *SensitiveQueryParameterRule) queryValuesKeys(expr ast.Expr, found func(ast.Expr)) {
	if bin, ok := ast.Unparen(expr).(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		r.queryValuesKeys(bin.X, found)
		if !endsInFragment(bin.X) {
			r.queryValuesKeys(bin.Y, found)
		}
		return
	}
	ast.Inspect(expr, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !isURLValues(lit.Type) {
			return true
		}
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.BasicLit); ok && r.valuesKey.MatchString(key.Value) {
					found(key)
				}
			}
		}
		return true
	})
}

// endsInFragment reports a concatenation operand that holds a string literal
// with '#': what is appended after it is the fragment.
func endsInFragment(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "#") {
			found = true
		}
		return !found
	})
	return found
}

// isURLValues reports the type url.Values.
func isURLValues(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Values" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "url"
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
