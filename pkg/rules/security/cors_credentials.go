package security

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewCORSCredentialsRule())
}

// CORSCredentialsRule detects CORS that lets any origin make credentialed
// requests, and an Allow-Origin that changes with the request without Vary:
//
//	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))   // any site
//	w.Header().Set("Access-Control-Allow-Credentials", "true")
//	if allowed == "*" || allowed == origin { return true }                  // "*" in the allowlist
//	cors.Options{AllowedOrigins: []string{"*"}, AllowCredentials: true}
//
// The request's own Origin sent back unchecked, or a "*" entry that lets every
// origin through the allowlist, gives any site the user's cookies. A literal
// "*" with credentials is refused by browsers and breaks the credentialed
// call. An Allow-Origin taken from the request must come with Vary: Origin, or
// a cache hands one origin's answer to the next. Sending the Origin back is
// checked when a condition around it looks it up — an allowlist call, a map,
// a comparison; a test that it is not empty checks nothing.
type CORSCredentialsRule struct {
	*rules.BaseRule
}

// NewCORSCredentialsRule creates the rule
func NewCORSCredentialsRule() *CORSCredentialsRule {
	return &CORSCredentialsRule{
		BaseRule: rules.NewBaseRule(
			"cors-credentials-origin",
			"security",
			"Detects CORS allowing credentials for any origin (wildcard, unchecked reflected Origin, \"*\" in the allowlist) and a reflected Origin without Vary",
			core.SeverityHigh,
		),
	}
}

// originCheckName names a function deciding whether an origin is allowed.
var originCheckName = regexp.MustCompile(`(?i)origin`)

// AnalyzeFile reports the CORS headers of a Go file that open it to any origin.
func (r *CORSCredentialsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	report := lr.report
	credentials := setsHeader(ctx.GoAST, "Access-Control-Allow-Credentials", "true")
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok && libraryWildcardWithCredentials(lit) {
			report(lit, "The CORS configuration allows credentials for \"*\" — the library sends back whatever Origin the request names",
				"List the allowed origins explicitly", "library_wildcard")
		}
		return true
	})
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if credentials && originCheckName.MatchString(fn.Name.Name) {
			for _, node := range wildcardEntries(fn.Body) {
				report(node, "A \"*\" entry lets every origin through the allowlist, and the allowed origin is sent back with credentials",
					"Drop the wildcard entry; allow only listed origins when credentials are on", "wildcard_allowlist_entry")
			}
		}
		r.checkAllowOrigin(fn.Body, report)
	}
	return lr.violations
}

func (r *CORSCredentialsRule) checkAllowOrigin(body *ast.BlockStmt, report func(ast.Node, string, string, string)) {
	parents := helpers.ParentMap(body)
	origins := make(map[string]bool)
	assignedValues(body, func(name *ast.Ident, value ast.Expr) {
		if call, ok := ast.Unparen(value).(*ast.CallExpr); ok && strings.EqualFold(headerGet(call), "Origin") {
			origins[name.Name] = true
		}
	})
	isOrigin := func(expr ast.Expr) bool {
		switch e := ast.Unparen(expr).(type) {
		case *ast.CallExpr:
			return strings.EqualFold(headerGet(e), "Origin")
		case *ast.Ident:
			return origins[e.Name]
		}
		return false
	}
	credentials := setsHeader(body, "Access-Control-Allow-Credentials", "true")
	vary := setsHeader(body, "Vary", "Origin")
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, value := headerSet(call)
		if !strings.EqualFold(name, "Access-Control-Allow-Origin") {
			return true
		}
		switch {
		case stringLiteral(value) == "*" && credentials:
			report(call, "Allow-Origin \"*\" with credentials — browsers refuse it, so the credentialed request fails",
				"Send back an origin from the allowlist instead of \"*\"", "wildcard_with_credentials")
		case isOrigin(value) && credentials && !originChecked(call, parents, isOrigin):
			report(call, "The request's Origin is sent back unchecked with credentials — any site can call the API with the user's cookies",
				"Send the Origin back only when it is in the allowlist", "reflected_origin")
		case isOrigin(value) && !vary:
			report(call, "Allow-Origin changes with the request but Vary: Origin is not set — a cache hands one origin's answer to another",
				"Add w.Header().Add(\"Vary\", \"Origin\") where the origin is sent back", "missing_vary")
		}
		return true
	})
}

// headerSet returns the header name and value of X.Set, X.Add or c.Header.
func headerSet(call *ast.CallExpr) (string, ast.Expr) {
	switch callName(call) {
	case "Set", "Add", "Header":
	default:
		return "", nil
	}
	if len(call.Args) != 2 {
		return "", nil
	}
	return stringLiteral(call.Args[0]), call.Args[1]
}

// setsHeader reports a header set whose literal value contains want.
func setsHeader(root ast.Node, header, want string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			name, value := headerSet(call)
			found = found || strings.EqualFold(name, header) && strings.Contains(strings.ToLower(stringLiteral(value)), strings.ToLower(want))
		}
		return !found
	})
	return found
}

// originChecked reports a header set inside an if whose condition looks the
// origin up: a call given the origin, an index by it, a comparison of it
// with something other than "".
func originChecked(node ast.Node, parents map[ast.Node]ast.Node, isOrigin func(ast.Expr) bool) bool {
	for p := parents[node]; p != nil; p = parents[p] {
		ifStmt, ok := p.(*ast.IfStmt)
		if !ok {
			continue
		}
		checked := false
		inspect := func(root ast.Node) {
			if root == nil {
				return
			}
			ast.Inspect(root, func(m ast.Node) bool {
				switch e := m.(type) {
				case *ast.CallExpr:
					for _, arg := range e.Args {
						checked = checked || isOrigin(arg)
					}
				case *ast.IndexExpr:
					checked = checked || isOrigin(e.Index)
				case *ast.BinaryExpr:
					if (e.Op == token.EQL || e.Op == token.NEQ) && (isOrigin(e.X) || isOrigin(e.Y)) {
						other := e.Y
						if !isOrigin(e.X) {
							other = e.X
						}
						checked = checked || stringLiteral(other) != "" || !isStringLit(other)
					}
				}
				return !checked
			})
		}
		inspect(ifStmt.Cond)
		if ifStmt.Init != nil {
			inspect(ifStmt.Init)
		}
		if checked {
			return true
		}
	}
	return false
}

func isStringLit(expr ast.Expr) bool {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// wildcardEntries returns the comparisons of an allowlist entry with "*".
func wildcardEntries(body *ast.BlockStmt) []ast.Node {
	var entries []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if ok && bin.Op == token.EQL && (stringLiteral(bin.X) == "*" || stringLiteral(bin.Y) == "*") {
			entries = append(entries, bin)
		}
		return true
	})
	return entries
}

// libraryWildcardWithCredentials reports a CORS library configuration that
// lists "*" as an allowed origin and turns credentials on.
func libraryWildcardWithCredentials(lit *ast.CompositeLit) bool {
	wildcard, credentials := false, false
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "AllowedOrigins", "AllowOrigins":
			if list, ok := kv.Value.(*ast.CompositeLit); ok {
				for _, origin := range list.Elts {
					wildcard = wildcard || stringLiteral(origin) == "*"
				}
			}
		case "AllowCredentials":
			ident, ok := kv.Value.(*ast.Ident)
			credentials = ok && ident.Name == "true"
		}
	}
	return wildcard && credentials
}
