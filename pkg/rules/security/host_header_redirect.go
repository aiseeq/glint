package security

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewHostHeaderRedirectRule())
}

// HostHeaderRedirectRule detects a redirect whose target is built from the
// Host header of the request:
//
//	httpsURL := "https://" + r.Host + r.RequestURI
//	http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
//
// The client writes Host (and X-Forwarded-Host) itself: the redirect sends the
// browser wherever the header points, and a cache in front keeps that answer
// for everyone. The host counts as checked when a condition of the function
// tests it — against the configured domain or an allowlist.
type HostHeaderRedirectRule struct {
	*rules.BaseRule
}

// NewHostHeaderRedirectRule creates the rule
func NewHostHeaderRedirectRule() *HostHeaderRedirectRule {
	return &HostHeaderRedirectRule{
		BaseRule: rules.NewBaseRule(
			"host-header-redirect",
			"security",
			"Detects redirects whose target is built from the request Host header without checking it",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile reports the redirects of a Go file built from the Host header.
func (r *HostHeaderRedirectRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		for _, node := range hostRedirects(fn.Body) {
			line := ctx.LineFor(node)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, "The redirect target is built from the Host header the client sends — it redirects wherever the client says")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Build the target from the configured domain, or check Host against it before redirecting")
			violations = append(violations, v)
		}
	}
	return violations
}

// isHostSource reports r.Host and a read of the Host or X-Forwarded-Host header.
func isHostSource(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name == "Host" && isRequestExpr(e.X)
	case *ast.CallExpr:
		header := strings.ToLower(headerGet(e))
		return header == "host" || header == "x-forwarded-host"
	}
	return false
}

// hostRedirects returns where a body builds a redirect target from the Host
// header: the assignment that put the host in a name the redirect uses, or
// the redirect itself when it reads the host in place. A body that tests the
// host in a condition checks it.
func hostRedirects(body *ast.BlockStmt) []ast.Node {
	// origins maps a name holding the host to the assignment that built it.
	origins := make(map[string]ast.Node)
	holdsHost := func(expr ast.Expr) (ast.Node, bool) {
		var origin ast.Node
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			if found {
				return false
			}
			if e, ok := n.(ast.Expr); ok && isHostSource(e) {
				found = true
				return false
			}
			if ident, ok := n.(*ast.Ident); ok && origins[ident.Name] != nil {
				origin, found = origins[ident.Name], true
			}
			return true
		})
		return origin, found
	}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			if ident, ok := assign.Lhs[i].(*ast.Ident); ok {
				if _, holds := holdsHost(rhs); holds {
					origins[ident.Name] = assign
				}
			}
		}
		return true
	})
	checked := false
	ast.Inspect(body, func(n ast.Node) bool {
		var cond ast.Expr
		switch node := n.(type) {
		case *ast.IfStmt:
			cond = node.Cond
		case *ast.SwitchStmt:
			cond = node.Tag
		}
		if cond != nil {
			if _, holds := holdsHost(cond); holds {
				checked = true
			}
		}
		return !checked
	})
	if checked {
		return nil
	}
	var redirects []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var target []ast.Expr
		switch {
		case callName(call) == "Redirect":
			target = call.Args
		case (callName(call) == "Set" || callName(call) == "Add") && len(call.Args) == 2 &&
			strings.EqualFold(stringLiteral(call.Args[0]), "Location"):
			target = call.Args[1:]
		}
		for _, arg := range target {
			if isRequestExpr(arg) {
				continue
			}
			if origin, holds := holdsHost(arg); holds {
				if origin == nil {
					origin = call
				}
				redirects = append(redirects, origin)
				break
			}
		}
		return true
	})
	return redirects
}
