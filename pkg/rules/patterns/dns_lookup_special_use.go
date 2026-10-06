package patterns

import (
	"go/ast"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDNSLookupOfSpecialUseDomainRule())
}

// DNSLookupOfSpecialUseDomainRule detects a DNS lookup of a name the
// function caches only on success, with no filter of the special-use zones:
//
//	records, err := c.resolver.LookupMX(ctx, domainOf(email))
//	if err != nil { return nil }          // the failure is not remembered
//	c.remember(domain, verdict(records))  // only answers are
//
// A user-supplied .local name goes to multicast DNS and waits out the whole
// timeout, .test or .invalid fail after a round trip, and since the failure
// is not cached every request pays it again. The special-use zones (RFC
// 6761: local, test, invalid, localhost, example) never have public records;
// skip them before the lookup, or cache the failure as well.
type DNSLookupOfSpecialUseDomainRule struct {
	*rules.BaseRule
}

// NewDNSLookupOfSpecialUseDomainRule creates the rule
func NewDNSLookupOfSpecialUseDomainRule() *DNSLookupOfSpecialUseDomainRule {
	return &DNSLookupOfSpecialUseDomainRule{BaseRule: rules.NewBaseRule(
		"dns-lookup-of-special-use-domain",
		"patterns",
		"Detects a DNS lookup whose answers are cached and whose failures are not, with no filter of the special-use zones (.local, .test, .invalid) — such a name waits out the timeout on every request",
		core.SeverityMedium,
	)}
}

// dnsLookups are the resolver methods and net functions that ask DNS.
var dnsLookups = map[string]bool{
	"LookupMX": true, "LookupHost": true, "LookupIP": true, "LookupIPAddr": true, "LookupNetIP": true,
	"LookupTXT": true, "LookupNS": true, "LookupCNAME": true, "LookupSRV": true,
}

// specialUseZones are the names of the zones a filter compares with.
var specialUseZones = map[string]bool{
	"local": true, ".local": true, "localhost": true, ".localhost": true, "invalid": true, ".invalid": true,
	"test": true, ".test": true, "example": true, ".example": true, "onion": true, ".onion": true,
}

// AnalyzeFile reports the lookups of a file's functions.
func (r *DNSLookupOfSpecialUseDomainRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || filtersSpecialUse(fn.Body) {
			continue
		}
		for _, call := range uncachedFailureLookups(fn.Body) {
			line := ctx.LineFor(call)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"The lookup's answers are cached and its failures are not, and nothing filters the special-use zones — a .local name waits out the timeout (mDNS) on every request")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Skip the special-use zones (local, test, invalid, localhost, example) before the lookup, or cache the failure for a while too")
			violations = append(violations, v)
		}
	}
	return violations
}

// filtersSpecialUse reports a body comparing a name with a special-use zone
// or calling a function named for such a check.
func filtersSpecialUse(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if text, ok := goStringLiteral(node); ok && specialUseZones[strings.ToLower(text)] {
				found = true
			}
		case *ast.CallExpr:
			if slices.ContainsFunc(helpers.IdentifierWords(callName(node)), func(w string) bool {
				return w == "special" || w == "reserved"
			}) {
				found = true
			}
		}
		return !found
	})
	return found
}

// uncachedFailureLookups returns the lookups of a body whose name a later
// statement of the block caches while the error branch right after the
// lookup returns without caching it.
func uncachedFailureLookups(body *ast.BlockStmt) []*ast.CallExpr {
	var found []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			call, name := lookupAssignment(stmt)
			if call == nil || i+1 >= len(block.List) {
				continue
			}
			branch, ok := block.List[i+1].(*ast.IfStmt)
			if !ok || !isErrNotNil(branch.Cond) || !endsInReturn(branch.Body) || cachesName(branch.Body, name) {
				continue
			}
			rest := &ast.BlockStmt{List: block.List[i+2:]}
			if cachesName(rest, name) {
				found = append(found, call)
			}
		}
		return true
	})
	return found
}

// lookupAssignment returns the DNS lookup a statement assigns, with the
// variable holding the name it looks up.
func lookupAssignment(stmt ast.Stmt) (*ast.CallExpr, string) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return nil, ""
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil, ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !dnsLookups[sel.Sel.Name] {
		return nil, ""
	}
	name, ok := call.Args[len(call.Args)-1].(*ast.Ident)
	if !ok {
		return nil, ""
	}
	return call, name.Name
}

// cacheWords name a call that remembers a value.
var cacheWords = map[string]bool{"cache": true, "remember": true, "memo": true, "memoize": true, "store": true, "put": true}

// cachesName reports a statement of the block keeping something under the
// name: m[name] = v, or a call named for caching that is handed the name.
func cachesName(block *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if index, ok := lhs.(*ast.IndexExpr); ok && isIdentNamed(index.Index, name) {
					found = true
				}
			}
		case *ast.CallExpr:
			named := slices.ContainsFunc(helpers.IdentifierWords(callName(node)), func(w string) bool { return cacheWords[w] })
			if named && slices.ContainsFunc(node.Args, func(arg ast.Expr) bool { return isIdentNamed(arg, name) }) {
				found = true
			}
		}
		return !found
	})
	return found
}
