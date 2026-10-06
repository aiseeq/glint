package security

import (
	"go/ast"
	"go/token"
	"regexp"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewClientURLLoggedRule())
}

// ClientURLLoggedRule detects a URL a client reports about itself written to
// a log line as it came:
//
//	var env cspEnvelope
//	json.Unmarshal(body, &env)
//	logger.Warn("csp violation", "document_uri", truncate(env.Report.DocumentURI))
//	logger.Info("login page", "referer", r.Referer())
//
// The URL of the page the browser was on keeps its query and fragment: an
// OAuth token, a confirmation code or a reset link put there lands in the log
// and in whatever collects it. Cut the query and the fragment before logging
// (a helper named after the URL it returns, urlWithoutQuery or similar, counts
// as cutting); a field that is not a URL is not judged.
type ClientURLLoggedRule struct {
	*rules.BaseRule
}

// NewClientURLLoggedRule creates the rule
func NewClientURLLoggedRule() *ClientURLLoggedRule {
	return &ClientURLLoggedRule{BaseRule: rules.NewBaseRule(
		"client-url-logged-with-query",
		"security",
		"Detects a URL from the request (a reported document URI, the Referer) logged with its query — tokens and codes in it go into the log",
		core.SeverityMedium,
	)}
}

var (
	// clientURLField names a field that holds a URL: DocumentURI, BlockedURL, Referrer.
	clientURLField = regexp.MustCompile(`(?i)(?:uri|url|referr?er)$`)
	// urlCutter names a call that turns a URL into something without its
	// query: urlWithoutQuery, stripQuery, redactURL, pathOf.
	urlCutter = regexp.MustCompile(`(?i)url|uri|strip|redact|sanitiz|mask|path|host|origin`)
)

// AnalyzeFile reports the request URLs the handlers of a file log.
func (r *ClientURLLoggedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		var typ *ast.FuncType
		var body *ast.BlockStmt
		switch fn := n.(type) {
		case *ast.FuncDecl:
			typ, body = fn.Type, fn.Body
		case *ast.FuncLit:
			typ, body = fn.Type, fn.Body
		default:
			return true
		}
		request := httpRequestParam(typ)
		if request == "" || body == nil {
			return true
		}
		decoded := requestDecodedVars(body, request)
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !helpers.IsLoggerCall(call) {
				return true
			}
			for _, arg := range call.Args {
				if url := loggedClientURL(arg, decoded, request); url != nil {
					lr.report(url, "A URL from the request is logged with its query and fragment — a token or a code in it goes into the log",
						"Cut the query and the fragment (strings.IndexAny(u, \"?#\")) before logging the URL", "client_url_logged")
				}
			}
			return true
		})
		return true
	})
	return lr.violations
}

// httpRequestParam returns the name of a *http.Request parameter.
func httpRequestParam(typ *ast.FuncType) string {
	if typ == nil || typ.Params == nil {
		return ""
	}
	for _, field := range typ.Params.List {
		star, ok := field.Type.(*ast.StarExpr)
		if ok && helpers.ExprText(star.X) == "http.Request" && len(field.Names) == 1 {
			return field.Names[0].Name
		}
	}
	return ""
}

// requestDecodedVars returns the variables a body fills from the request: the
// body read (io.ReadAll(r.Body)), what it is decoded into (json.Unmarshal(body,
// &v), json.NewDecoder(r.Body).Decode(&v)) and the values taken from those.
func requestDecodedVars(body *ast.BlockStmt, request string) map[string]bool {
	vars := map[string]bool{}
	fromRequest := func(expr ast.Expr) bool {
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.SelectorExpr:
				if helpers.ExprText(e) == request+".Body" {
					found = true
				}
			case *ast.Ident:
				if vars[e.Name] {
					found = true
				}
			}
			return !found
		})
		return found
	}
	for range 3 { // values taken from values taken from the body
		ast.Inspect(body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if len(node.Lhs) == len(node.Rhs) || len(node.Rhs) == 1 {
					for i, lhs := range node.Lhs {
						rhs := node.Rhs[0]
						if len(node.Lhs) == len(node.Rhs) {
							rhs = node.Rhs[i]
						}
						if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && fromRequest(rhs) {
							vars[id.Name] = true
						}
					}
				}
			case *ast.CallExpr:
				name := callName(node)
				if (name == "Unmarshal" || name == "Decode") && len(node.Args) > 0 && decodesFromRequest(node, fromRequest) {
					if target, ok := ast.Unparen(node.Args[len(node.Args)-1]).(*ast.UnaryExpr); ok && target.Op == token.AND {
						if id, ok := target.X.(*ast.Ident); ok {
							vars[id.Name] = true
						}
					}
				}
			}
			return true
		})
	}
	return vars
}

// decodesFromRequest reports json.Unmarshal(body, ...) of a request body, or
// Decode on a decoder of one.
func decodesFromRequest(call *ast.CallExpr, fromRequest func(ast.Expr) bool) bool {
	if callName(call) == "Unmarshal" {
		return fromRequest(call.Args[0])
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && fromRequest(sel.X)
}

// loggedClientURL returns the URL from the request an argument of a log call
// writes as it came: a URL-named field of a decoded value, or r.Referer().
// Calls wrapping it that cut the URL take it out.
func loggedClientURL(arg ast.Expr, decoded map[string]bool, request string) ast.Expr {
	switch e := ast.Unparen(arg).(type) {
	case *ast.SelectorExpr:
		if clientURLField.MatchString(e.Sel.Name) && rootIdentIn(e.X, decoded) {
			return e
		}
	case *ast.CallExpr:
		name := callName(e)
		if name == "Referer" && len(e.Args) == 0 {
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok && helpers.ExprText(sel.X) == request {
				return e
			}
		}
		if urlCutter.MatchString(name) {
			return nil
		}
		for _, inner := range e.Args {
			if url := loggedClientURL(inner, decoded, request); url != nil {
				return url
			}
		}
	}
	return nil
}

// rootIdentIn reports a selector chain whose root identifier is in the set.
func rootIdentIn(expr ast.Expr, set map[string]bool) bool {
	for {
		switch e := ast.Unparen(expr).(type) {
		case *ast.Ident:
			return set[e.Name]
		case *ast.SelectorExpr:
			expr = e.X
		default:
			return false
		}
	}
}
