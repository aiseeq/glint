package security

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewCookieDeletedWithOtherAttributesRule())
}

// CookieDeletedWithOtherAttributesRule detects a cookie deleted with another
// Domain or Path than it was set with:
//
//	func SetJWTCookie(w http.ResponseWriter, name, value string) {
//	    c := &http.Cookie{Name: name, Value: value, Path: "/"}
//	    c.Domain = "." + baseDomain
//	    http.SetCookie(w, c)
//	}
//	func ClearJWTCookie(w http.ResponseWriter, name string) {
//	    http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1})   // no Domain
//	}
//
// A browser replaces a cookie only by one with the same name, Domain and
// Path; the deletion above creates a host-only cookie that expires at once
// and leaves the domain-wide one in place, so logout keeps the session. A
// deletion is a cookie literal with a negative MaxAge or Expires at the Unix
// epoch. Cookies pair by a constant Name, or by a name the code passes in
// when both are in one file (a set and a clear helper). The deletion is
// reported when cookies of its name are set and none of them has its Domain
// presence and Path.
type CookieDeletedWithOtherAttributesRule struct {
	*rules.BaseRule
}

// NewCookieDeletedWithOtherAttributesRule creates the rule
func NewCookieDeletedWithOtherAttributesRule() *CookieDeletedWithOtherAttributesRule {
	return &CookieDeletedWithOtherAttributesRule{BaseRule: rules.NewBaseRule(
		"cookie-deleted-with-other-attributes",
		"security",
		"Detects a cookie deletion (MaxAge < 0, Expires at the epoch) whose Domain or Path differs from every place the cookie is set — the browser keeps the original cookie",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the cookie is set and deleted in different files.
func (r *CookieDeletedWithOtherAttributesRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *CookieDeletedWithOtherAttributesRule) RequiresSSA() bool { return false }

// cookieSite is one http.Cookie literal with the attributes that identify the
// cookie in the browser.
type cookieSite struct {
	fileCtx  *core.FileContext
	node     ast.Node
	name     string // constant name, "" when passed in
	path     string
	domain   bool
	deletion bool
}

// AnalyzeGoProject pairs the deletions of the project with the cookies set.
func (r *CookieDeletedWithOtherAttributesRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	var sites []cookieSite
	_, err := rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if fileCtx.IsTestFile() {
			return nil
		}
		for _, decl := range fileCtx.GoAST.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				sites = append(sites, cookieSites(fileCtx, fn.Body, info)...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var violations []*core.Violation
	for _, del := range sites {
		if !del.deletion || !mismatchedDeletion(del, sites) {
			continue
		}
		line := del.fileCtx.LineFor(del.node)
		if del.fileCtx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(del.fileCtx.RelPath, line,
			"The cookie is deleted with another Domain or Path than it is set with — the browser keeps the original cookie and the logout does not end the session")
		v.WithCode(strings.TrimSpace(del.fileCtx.GetLine(line)))
		v.WithSuggestion("Delete the cookie with the same Domain and Path the code that sets it uses, from the same configuration")
		v.WithContext("pattern", "cookie_deleted_with_other_attributes")
		violations = append(violations, v)
	}
	return violations, nil
}

// mismatchedDeletion reports a deletion whose cookie is set somewhere, but
// never with the deletion's Domain presence and Path.
func mismatchedDeletion(del cookieSite, sites []cookieSite) bool {
	paired := false
	for _, set := range sites {
		if set.deletion || set.name != del.name {
			continue
		}
		// A name passed in is the same cookie only for the helpers of one
		// file; elsewhere it is any cookie.
		if del.name == "" && set.fileCtx != del.fileCtx {
			continue
		}
		paired = true
		if set.domain == del.domain && set.path == del.path {
			return false
		}
	}
	return paired
}

// cookieSites returns the http.Cookie literals of a function body; a Domain
// or Path assigned later to the variable holding the literal counts as its own.
func cookieSites(fileCtx *core.FileContext, body *ast.BlockStmt, info *types.Info) []cookieSite {
	var sites []cookieSite
	byVar := make(map[types.Object]int)
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !isNamedType(info.TypeOf(lit), "net/http", "Cookie") {
			return true
		}
		sites = append(sites, cookieLiteral(fileCtx, lit, info))
		return true
	})
	// Variables holding a literal: c := &http.Cookie{...} or c := http.Cookie{...}.
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			lit := cookieLiteralOf(rhs)
			ident, ok := assign.Lhs[i].(*ast.Ident)
			if lit == nil || !ok {
				continue
			}
			for j := range sites {
				if sites[j].node == lit {
					byVar[info.ObjectOf(ident)] = j
				}
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				continue
			}
			j, ok := byVar[info.ObjectOf(ident)]
			if !ok {
				continue
			}
			switch sel.Sel.Name {
			case "Domain":
				sites[j].domain = !emptyString(assign.Rhs[i], info)
			case "Path":
				sites[j].path = constantText(assign.Rhs[i], info)
			}
		}
		return true
	})
	return sites
}

func cookieLiteralOf(expr ast.Expr) *ast.CompositeLit {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = unary.X
	}
	lit, _ := expr.(*ast.CompositeLit)
	return lit
}

func cookieLiteral(fileCtx *core.FileContext, lit *ast.CompositeLit, info *types.Info) cookieSite {
	site := cookieSite{fileCtx: fileCtx, node: lit}
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
		case "Name":
			site.name = constantText(kv.Value, info)
		case "Path":
			site.path = constantText(kv.Value, info)
		case "Domain":
			site.domain = !emptyString(kv.Value, info)
		case "MaxAge":
			if tv := info.Types[kv.Value]; tv.Value != nil && constant.Sign(tv.Value) < 0 {
				site.deletion = true
			}
		case "Expires":
			site.deletion = site.deletion || epochTime(kv.Value, info)
		}
	}
	return site
}

// constantText returns the value of a string constant, "" otherwise.
func constantText(expr ast.Expr, info *types.Info) string {
	if tv := info.Types[expr]; tv.Value != nil && tv.Value.Kind() == constant.String {
		return constant.StringVal(tv.Value)
	}
	return ""
}

func emptyString(expr ast.Expr, info *types.Info) bool {
	tv := info.Types[expr]
	return tv.Value != nil && tv.Value.Kind() == constant.String && constant.StringVal(tv.Value) == ""
}

// epochTime reports time.Unix(0, 0), possibly followed by a method (.UTC()).
func epochTime(expr ast.Expr, info *types.Info) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && len(call.Args) == 0 {
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			call = inner
		}
	}
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "time" || fn.Name() != "Unix" || len(call.Args) != 2 {
		return false
	}
	tv := info.Types[call.Args[0]]
	return tv.Value != nil && constant.Sign(tv.Value) <= 0
}
