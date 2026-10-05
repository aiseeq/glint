package security

import (
	"go/ast"
	"net"
	"net/url"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewExternalAPIURLPlainHTTPRule())
}

// ExternalAPIURLPlainHTTPRule detects an external API reached over plain
// http:// - the request, its credentials and the answer travel in clear text
// and can be changed on the way:
//
//	defaultURL = "http://www.rates.example-bank.ru/daily.xml"
//
// A URL counts when a constant, a variable or a field named as an address
// (URL, Endpoint, Host, Base, Addr) holds it, or when it is the argument of
// http.Get, http.Post or http.NewRequest. Local and private hosts, a
// single-label container name, reserved example domains and XML namespaces
// are left alone.
type ExternalAPIURLPlainHTTPRule struct {
	*rules.BaseRule
}

// NewExternalAPIURLPlainHTTPRule creates the rule.
func NewExternalAPIURLPlainHTTPRule() *ExternalAPIURLPlainHTTPRule {
	return &ExternalAPIURLPlainHTTPRule{BaseRule: rules.NewBaseRule(
		"external-api-url-plain-http",
		"security",
		"Detects an external API URL with the http:// scheme — the request, its credentials and the answer travel in clear text",
		core.SeverityMedium,
	)}
}

const plainHTTPSuggestion = "Use https:// (the host serves it), or name why the call stays local"

// addressWords name a value that holds where a request goes.
var addressWords = map[string]bool{"url": true, "uri": true, "endpoint": true, "host": true, "base": true, "addr": true, "address": true}

// AnalyzeFile reports plain-http URLs of public hosts.
func (r *ExternalAPIURLPlainHTTPRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	check := func(node ast.Expr) {
		if raw := stringLiteral(node); publicPlainHTTP(raw) {
			lr.report(node, "The external API "+raw+" is reached over plain http:// — the request and its answer travel in clear text", plainHTTPSuggestion, "plain_http_url")
		}
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if i < len(node.Values) && namesAddress(name.Name) {
					check(node.Values[i])
				}
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok && namesAddress(key.Name) {
				check(node.Value)
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && i < len(node.Rhs) && namesAddress(id.Name) {
					check(node.Rhs[i])
				}
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" && helpers.NetHTTPRequestFuncs[sel.Sel.Name] {
				for _, arg := range node.Args {
					check(arg)
				}
			}
		}
		return true
	})
	return lr.violations
}

// namesAddress reports a name holding an address word: defaultURL, BaseURL,
// apiEndpoint.
func namesAddress(name string) bool {
	for _, word := range helpers.IdentifierWords(name) {
		if addressWords[word] {
			return true
		}
	}
	return false
}

// reservedHosts are the example domains of RFC 2606 and the namespace hosts
// of XML and JSON schemas: names, not services.
var reservedHosts = []string{"example.com", "example.org", "example.net", "w3.org", "xmlsoap.org", "json-schema.org", "purl.org", "xmlns.com", "schemas.microsoft.com", "schemas.openxmlformats.org"}

// reservedSuffixes are the top-level domains that never reach the internet.
var reservedSuffixes = []string{".local", ".internal", ".localhost", ".test", ".example", ".invalid", ".lan", ".home.arpa"}

// publicPlainHTTP reports an http:// URL of a public host.
func publicPlainHTTP(raw string) bool {
	if !strings.HasPrefix(raw, "http://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if !strings.Contains(host, ".") || host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
	}
	for _, reserved := range reservedHosts {
		if host == reserved || strings.HasSuffix(host, "."+reserved) {
			return false
		}
	}
	for _, suffix := range reservedSuffixes {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return true
}
