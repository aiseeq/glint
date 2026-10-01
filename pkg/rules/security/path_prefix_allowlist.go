package security

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPathPrefixAllowlistRule())
}

// PathPrefixAllowlistRule detects a list of paths matched by prefix that
// holds the root path:
//
//	skip := []string{"/health", "/", "/_next/"}
//	for _, p := range skip {
//	    if strings.HasPrefix(r.URL.Path, p) { next.ServeHTTP(w, r); return }
//	}
//
// Every path starts with "/", so the list lets every request through: a rate
// limit, an authentication or an audit meant to skip the home page skips the
// whole site. The root belongs in a list of exact matches.
type PathPrefixAllowlistRule struct {
	*rules.BaseRule
}

// NewPathPrefixAllowlistRule creates the rule
func NewPathPrefixAllowlistRule() *PathPrefixAllowlistRule {
	return &PathPrefixAllowlistRule{BaseRule: rules.NewBaseRule(
		"path-prefix-allowlist-matches-all",
		"security",
		"Detects a list of paths matched by strings.HasPrefix that holds \"/\" or \"\" — every path matches and the exemption covers the whole site",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports the prefix matches against a list holding the root.
func (r *PathPrefixAllowlistRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lists := rootPathLists(ctx.GoAST)
	lr := newLineReporter(ctx, r.BaseRule)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		value, ok := loop.Value.(*ast.Ident)
		if !ok || !holdsRoot(loop.X, lists) {
			return true
		}
		ast.Inspect(loop.Body, func(m ast.Node) bool {
			expr, ok := m.(ast.Expr)
			if !ok {
				return true
			}
			if call, ok := isStringsCall(expr, "HasPrefix"); ok && len(call.Args) == 2 {
				if prefix, ok := call.Args[1].(*ast.Ident); ok && prefix.Name == value.Name {
					lr.report(call, "Paths matched by prefix against a list that holds the root \"/\" — every path starts with it, so the exemption covers every request",
						"Keep the root in a list of exact matches and only real prefixes (\"/static/\") in the prefix list", "path_prefix_allowlist")
				}
			}
			return true
		})
		return true
	})
	return lr.violations
}

// rootPathLists returns the names bound to a []string literal that holds "/"
// or "": local variables and package variables of the file.
func rootPathLists(file *ast.File) map[string]bool {
	lists := make(map[string]bool)
	bind := func(names []ast.Expr, values []ast.Expr) {
		for i, value := range values {
			if i < len(names) && literalHoldsRoot(value) {
				if ident, ok := names[i].(*ast.Ident); ok {
					lists[ident.Name] = true
				}
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			bind(node.Lhs, node.Rhs)
		case *ast.ValueSpec:
			names := make([]ast.Expr, len(node.Names))
			for i, name := range node.Names {
				names[i] = name
			}
			bind(names, node.Values)
		}
		return true
	})
	return lists
}

// holdsRoot reports a ranged expression that is, or names, a list holding the
// root path.
func holdsRoot(expr ast.Expr, lists map[string]bool) bool {
	if ident, ok := expr.(*ast.Ident); ok {
		return lists[ident.Name]
	}
	return literalHoldsRoot(expr)
}

// literalHoldsRoot reports a composite literal with a "/" or "" element.
func literalHoldsRoot(expr ast.Expr) bool {
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, elt := range lit.Elts {
		basic, ok := elt.(*ast.BasicLit)
		if !ok || basic.Kind != token.STRING {
			continue
		}
		switch basic.Value {
		case `"/"`, `""`, "`/`", "``":
			return true
		}
	}
	return false
}
