package security

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
// Some providers accept a key only as ?api-key=...; there a transport failure
// logs the key through the wrapped *url.Error unless a sanitizer strips the
// query from the *url.Error before the error is wrapped.
//
// The rule is silent when the function routes the error through a sanitizer
// (any call whose name contains "Sanitize"), and when the request goes through
// a shared HTTP helper instead of a raw Do — the helper is the right single
// place for sanitation.
//
// A transport call is recognized by its callee's type: a method of
// *net/http.Client (Do, Get, Post, PostForm, Head), an interface method
// Do(*http.Request), or the net/http package functions Get, Post, PostForm,
// Head. Without type information only the package functions are recognized.
type SecretInQueryURLRule struct {
	*rules.BaseRule
	secretParam   *regexp.Regexp
	secretLiteral *regexp.Regexp
}

// NewSecretInQueryURLRule creates the rule.
func NewSecretInQueryURLRule() *SecretInQueryURLRule {
	// Built by concatenation so the source of this rule does not itself match
	// line-based secret detectors.
	secretName := nameAlternation(apiKeyNames, apiSecretNames, tokenNames, bareTokenNames, secretNames)
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

// AnalyzeFile checks one file without type information: only the net/http
// package functions are recognized as transport calls.
func (r *SecretInQueryURLRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SecretInQueryURLRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; transport calls are recognized by the
// type of their receiver.
func (r *SecretInQueryURLRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks each function for the secret-in-query + raw transport call
// combination. info is nil for a file without type information.
func (r *SecretInQueryURLRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	transport := transportCallMatcher{info: info, httpAliases: helpers.PackageAliases(ctx.GoAST, `"net/http"`, "http")}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Body != nil {
			violations = append(violations, r.checkFunction(ctx, fn, transport)...)
			return false
		}
		return true
	})
	return violations
}

func (r *SecretInQueryURLRule) checkFunction(ctx *core.FileContext, fn *ast.FuncDecl, transport transportCallMatcher) []*core.Violation {
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
			if transport.matches(node) {
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

// httpTransportFuncs are the net/http functions and *http.Client methods that
// send a request and wrap a transport failure in *url.Error.
var httpTransportFuncs = map[string]bool{"Do": true, "Get": true, "Post": true, "PostForm": true, "Head": true}

// transportCallMatcher recognizes the direct HTTP transport calls whose errors
// carry *url.Error. info is nil for a file without type information; then only
// the package functions under an import of net/http are recognized.
type transportCallMatcher struct {
	info        *types.Info
	httpAliases map[string]bool
}

func (m transportCallMatcher) matches(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !httpTransportFuncs[sel.Sel.Name] {
		return false
	}
	if m.info == nil {
		pkg, ok := sel.X.(*ast.Ident)
		return ok && sel.Sel.Name != "Do" && m.httpAliases[pkg.Name]
	}
	fn, ok := m.info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	if fn.Pkg() != nil && fn.Pkg().Path() == "net/http" {
		// Package functions http.Get/...; methods of *http.Client. Other
		// net/http methods with these names (Header.Get) are not transport.
		return sig.Recv() == nil || isNamedType(sig.Recv().Type(), "net/http", "Client")
	}
	return sel.Sel.Name == "Do" && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) &&
		sig.Params().Len() == 1 && isNamedType(sig.Params().At(0).Type(), "net/http", "Request")
}

// isNamedType reports whether t is the named type path.name or a pointer to it.
func isNamedType(t types.Type, path, name string) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == path && named.Obj().Name() == name
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
