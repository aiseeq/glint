package security

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSecretInQueryURLRule())
}

// SecretInQueryURLRule detects functions that put an API key or token into the
// URL query string and then perform the HTTP request directly, without
// sanitizing the transport error. http.Client.Do wraps transport failures in
// *url.Error, which carries the full URL — so a timeout or DNS failure leaks
// the key into every log line that prints the error.
//
// Real case (backoffice, 2026-08-05): Helius authorizes only via ?api-key=...;
// a transport failure logged the key through the wrapped *url.Error. The fix
// added a SanitizeTransportError helper that strips the query from the
// *url.Error before the error is wrapped.
//
// The rule is silent when the function routes the error through a sanitizer
// (any call whose name contains "Sanitize"), and when the request goes through
// a shared HTTP helper instead of a raw Do — the helper is the right single
// place for sanitation.
type SecretInQueryURLRule struct {
	*rules.BaseRule
	secretParam   *regexp.Regexp
	secretLiteral *regexp.Regexp
}

// NewSecretInQueryURLRule creates the rule.
func NewSecretInQueryURLRule() *SecretInQueryURLRule {
	// Built by concatenation so the source of this rule does not itself match
	// line-based secret detectors.
	secretName := `(?:api[-_]?key|apikey|api[-_]?secret|access[-_]?token|auth[-_]?token|token|secret|private[-_]?key)`
	return &SecretInQueryURLRule{
		BaseRule: rules.NewBaseRule(
			"secret-in-query-url",
			"security",
			"Detects an API key in the URL query combined with an unsanitized transport error — *url.Error carries the full URL into logs",
			core.SeverityMedium,
		),
		secretParam:   regexp.MustCompile(`(?i)^` + secretName + `$`),
		secretLiteral: regexp.MustCompile(`(?i)(?:^|[?&])` + secretName + `=`),
	}
}

// AnalyzeFile checks each function for the secret-in-query + raw transport
// call combination.
func (r *SecretInQueryURLRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Body != nil {
			violations = append(violations, r.checkFunction(ctx, fn)...)
			return false
		}
		return true
	})
	return violations
}

func (r *SecretInQueryURLRule) checkFunction(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	secretInQuery := false
	sanitized := false
	var transportCalls []*ast.CallExpr

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if r.isSecretQuerySet(node) {
				secretInQuery = true
			}
			if callNameContainsSanitize(node) {
				sanitized = true
			}
			if isRawTransportCall(node) {
				transportCalls = append(transportCalls, node)
			}
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if text, err := strconv.Unquote(node.Value); err == nil && r.secretLiteral.MatchString(text) {
					secretInQuery = true
				}
			}
		}
		return true
	})

	if !secretInQuery || sanitized || len(transportCalls) == 0 {
		return nil
	}

	var violations []*core.Violation
	for _, call := range transportCalls {
		line := ctx.LineFor(call)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line,
			"API key travels in the URL query — a transport failure here wraps the full URL in *url.Error and leaks the key into logs")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Sanitize the transport error before wrapping or logging it (a SanitizeTransportError helper that strips the query from *url.Error), or move the secret out of the URL into a header")
		v.WithContext("pattern", "secret-in-query-url")
		v.WithContext("function", fn.Name.Name)
		violations = append(violations, v)
	}
	return violations
}

// isSecretQuerySet recognizes values.Set("api-key", ...) / values.Add(...)
// with a secret-looking parameter name. Header writes (req.Header.Set) are
// excluded: a header does not end up inside *url.Error.
func (r *SecretInQueryURLRule) isSecretQuerySet(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Set" && sel.Sel.Name != "Add") || len(call.Args) < 2 {
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	name, err := strconv.Unquote(lit.Value)
	if err != nil || !r.secretParam.MatchString(name) {
		return false
	}
	return !strings.Contains(strings.ToLower(receiverChain(sel.X)), "header")
}

// isRawTransportCall recognizes the direct HTTP transport calls whose errors
// carry *url.Error: client.Do(req), http.Get/Post/PostForm/Head(url).
func isRawTransportCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name == "Do" && len(call.Args) == 1 {
		return true
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "http" {
		return false
	}
	switch sel.Sel.Name {
	case "Get", "Post", "PostForm", "Head":
		return true
	}
	return false
}

func callNameContainsSanitize(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return strings.Contains(fun.Name, "Sanitize")
	case *ast.SelectorExpr:
		return strings.Contains(fun.Sel.Name, "Sanitize")
	}
	return false
}

// receiverChain flattens a selector chain (req.Header) into a dotted string
// for coarse receiver classification.
func receiverChain(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.SelectorExpr:
		return receiverChain(node.X) + "." + node.Sel.Name
	case *ast.CallExpr:
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
			return receiverChain(sel.X) + "." + sel.Sel.Name + "()"
		}
		return ""
	case *ast.ParenExpr:
		return receiverChain(node.X)
	default:
		return ""
	}
}
