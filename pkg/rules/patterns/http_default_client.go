package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewHTTPDefaultClientRule())
}

// HTTPDefaultClientRule detects an outgoing request through net/http's
// default client:
//
//	resp, err := http.Post(nodeURL, "application/json", bytes.NewBuffer(body))
//
// http.Get, Head, Post, PostForm and http.DefaultClient have no timeout and
// take no context: a peer that accepts the connection and never answers
// holds the goroutine, and the request handler behind it, forever. Use a
// client with a Timeout, or http.NewRequestWithContext with a deadline.
// http.DefaultClient.Do(req) is left alone when the function built req with
// http.NewRequestWithContext or req.WithContext: cancellation and the
// deadline come from the context. Tests are not checked.
type HTTPDefaultClientRule struct {
	*rules.BaseRule
}

// NewHTTPDefaultClientRule creates the rule
func NewHTTPDefaultClientRule() *HTTPDefaultClientRule {
	return &HTTPDefaultClientRule{BaseRule: rules.NewBaseRule(
		"http-default-client",
		"patterns",
		"Detects requests through net/http's default client (http.Get, http.Post, http.DefaultClient) — no timeout, no context",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the calls through the default client.
func (r *HTTPDefaultClientRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		withContext := contextRequests(ctx.GoAST, decl)
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := defaultClientCall(ctx.GoAST, call, withContext)
			if name == "" {
				return true
			}
			line := ctx.LineFor(call)
			if ctx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(ctx.RelPath, line, name+" sends through http.DefaultClient — no timeout and no context, a peer that never answers holds the call forever")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Send through a client with a Timeout, or build the request with http.NewRequestWithContext and a deadline")
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

// defaultClientCall returns the spelling of a call that sends through the
// default client without a context, or "".
func defaultClientCall(file *ast.File, call *ast.CallExpr, withContext map[string]bool) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	switch x := sel.X.(type) {
	case *ast.Ident: // http.Post(...)
		if helpers.NetHTTPSendFuncs[sel.Sel.Name] && isNetHTTP(file, x) {
			return x.Name + "." + sel.Sel.Name
		}
	case *ast.SelectorExpr: // http.DefaultClient.Do(...)
		pkg, ok := x.X.(*ast.Ident)
		if !ok || x.Sel.Name != "DefaultClient" || !isNetHTTP(file, pkg) {
			return ""
		}
		if sel.Sel.Name == "Do" && len(call.Args) == 1 {
			if req, ok := call.Args[0].(*ast.Ident); ok && withContext[req.Name] {
				return ""
			}
		}
		return pkg.Name + ".DefaultClient." + sel.Sel.Name
	}
	return ""
}

// contextRequests returns the names the declaration assigns a request that
// carries a context: http.NewRequestWithContext(...) or req.WithContext(ctx).
func contextRequests(file *ast.File, decl ast.Decl) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(decl, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		target, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, isIdent := sel.X.(*ast.Ident)
		if sel.Sel.Name == "WithContext" || (sel.Sel.Name == "NewRequestWithContext" && isIdent && isNetHTTP(file, pkg)) {
			names[target.Name] = true
		}
		return true
	})
	return names
}

// isNetHTTP reports an identifier naming the file's import of net/http, not
// a local variable of the same name.
func isNetHTTP(file *ast.File, id *ast.Ident) bool {
	if id.Obj != nil {
		return false
	}
	importPath, ok := fileImportPath(file, id.Name)
	return ok && importPath == "net/http"
}
