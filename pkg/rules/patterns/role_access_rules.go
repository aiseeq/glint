package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewRoleRouteDenylistRule())
	rules.Register(NewContentDispositionUnescapedRule())
	rules.Register(NewWebStorageHoldsTokenRule())
	rules.Register(NewRoleClaimTrustedWithoutRecheckRule())
	rules.Register(NewWritePermissionIsReadRule())
	rules.Register(NewAllowlistRegrantsRevokedRoleRule())
}

// restrictedRoleWords name a kind of user a middleware branches on.
var restrictedRoleWords = wordSet("role", "admin", "partner", "investor", "lp", "staff", "restricted",
	"readonly", "viewer", "guest", "client", "member", "operator", "owner", "tenant")

// NewRoleRouteDenylistRule creates role-route-denylist: a middleware that,
// for a restricted kind of user, forbids a list of path prefixes and passes
// every other request on:
//
//	if !IsPartnerUser(ctx) { next.ServeHTTP(w, r); return }
//	for _, prefix := range ownerOnly {
//	    if strings.HasPrefix(r.URL.Path, prefix) { http.Error(w, "", 403); return }
//	}
//	next.ServeHTTP(w, r)
//
// The restricted user reaches every route nobody listed, a route added
// tomorrow included. The paths that user may open belong in an allowlist,
// and everything else is refused.
func NewRoleRouteDenylistRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"role-route-denylist",
			"security",
			"Detects a middleware that refuses a restricted role a list of path prefixes and passes every other request on — the role reaches every route nobody listed",
			core.SeverityMedium,
		),
		suggestion: "List the paths the restricted role may open and refuse everything else (deny by default)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		for _, body := range handlerBodies(scope.info, fn) {
			if !branchesOnRole(body) {
				continue
			}
			inspectOwnBody(body, func(n ast.Node) {
				loop, ok := n.(*ast.RangeStmt)
				if !ok || !isPathList(scope.info, fn, loop.X) || !forbids(loop.Body) || !servesAfter(body, loop.End()) {
					return
				}
				findings = append(findings, funcFinding{node: loop, message: "A restricted role is refused only the listed path prefixes and every other request is passed on — a route nobody listed is open to it"})
			})
		}
		return findings
	}
	return r
}

// handlerBodies returns the bodies of fn and of its function literals that
// take an http.ResponseWriter and an *http.Request.
func handlerBodies(info *types.Info, fn *ast.FuncDecl) []*ast.BlockStmt {
	var bodies []*ast.BlockStmt
	if isHandlerType(info, fn.Type) {
		bodies = append(bodies, fn.Body)
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.FuncLit); ok && isHandlerType(info, lit.Type) {
			bodies = append(bodies, lit.Body)
		}
		return true
	})
	return bodies
}

// isHandlerType reports a function type with an http.ResponseWriter and an
// *http.Request parameter.
func isHandlerType(info *types.Info, ft *ast.FuncType) bool {
	writer, request := false, false
	for _, field := range ft.Params.List {
		switch types.TypeString(info.TypeOf(field.Type), nil) {
		case "net/http.ResponseWriter":
			writer = true
		case "*net/http.Request":
			request = true
		}
	}
	return writer && request
}

// inspectOwnBody visits the nodes of a body, not those of function literals
// inside it.
func inspectOwnBody(body *ast.BlockStmt, visit func(ast.Node)) {
	ast.Inspect(body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		if n != nil {
			visit(n)
		}
		return true
	})
}

// branchesOnRole reports a body with an if on a kind of user: a predicate
// named after a role (IsPartnerUser) or a role field.
func branchesOnRole(body *ast.BlockStmt) bool {
	found := false
	inspectOwnBody(body, func(n ast.Node) {
		check, ok := n.(*ast.IfStmt)
		if !ok || found {
			return
		}
		ast.Inspect(check.Cond, func(m ast.Node) bool {
			switch e := m.(type) {
			case *ast.CallExpr:
				found = found || hasTokenIn(calledName(e), restrictedRoleWords)
			case *ast.SelectorExpr:
				found = found || hasTokenIn(e.Sel.Name, wordSet("role"))
			}
			return !found
		})
	})
	return found
}

// isPathList reports a ranged list of path literals ("/firms", "/sync"):
// the literal itself, a local variable assigned it once, or a package
// variable initialized with it.
func isPathList(info *types.Info, fn *ast.FuncDecl, expr ast.Expr) bool {
	if lit, ok := ast.Unparen(expr).(*ast.CompositeLit); ok {
		return pathLiterals(lit)
	}
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.ObjectOf(ident).(*types.Var)
	if !ok {
		return false
	}
	if value := singleAssignment(info, fn, v); value != nil {
		lit, ok := ast.Unparen(value).(*ast.CompositeLit)
		return ok && pathLiterals(lit)
	}
	for _, init := range info.InitOrder {
		if len(init.Lhs) == 1 && init.Lhs[0] == v {
			lit, ok := ast.Unparen(init.Rhs).(*ast.CompositeLit)
			return ok && pathLiterals(lit)
		}
	}
	return false
}

// pathLiterals reports a literal of two or more string paths.
func pathLiterals(lit *ast.CompositeLit) bool {
	if len(lit.Elts) < 2 {
		return false
	}
	for _, elt := range lit.Elts {
		basic, ok := elt.(*ast.BasicLit)
		if !ok || basic.Kind != token.STRING {
			return false
		}
		value, err := strconv.Unquote(basic.Value)
		if err != nil || !strings.HasPrefix(value, "/") {
			return false
		}
	}
	return true
}

// forbids reports a block that answers 403.
func forbids(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.SelectorExpr:
			found = found || e.Sel.Name == "StatusForbidden"
		case *ast.BasicLit:
			found = found || (e.Kind == token.INT && e.Value == "403")
		}
		return !found
	})
	return found
}

// servesAfter reports a ServeHTTP call of the body after pos.
func servesAfter(body *ast.BlockStmt, pos token.Pos) bool {
	found := false
	inspectOwnBody(body, func(n ast.Node) {
		if call, ok := n.(*ast.CallExpr); ok && call.Pos() > pos && calledName(call) == "ServeHTTP" {
			found = true
		}
	})
	return found
}

// NewContentDispositionUnescapedRule creates content-disposition-unescaped:
// a download name written into Content-Disposition with %s or concatenation,
// from text the server does not choose:
//
//	filename := fmt.Sprintf("report-%s.csv", report.HolderName)
//	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
//
// A quote or a semicolon in the name ends the parameter and adds another, and
// a non-ASCII name arrives garbled. mime.FormatMediaType quotes the value and
// encodes what needs it.
func NewContentDispositionUnescapedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"content-disposition-unescaped",
			"security",
			"Detects a Content-Disposition header built with %s or concatenation from text the server does not choose — a quote or a semicolon breaks the header",
			core.SeverityMedium,
		),
		suggestion: `Build the header with mime.FormatMediaType("attachment", map[string]string{"filename": name})`,
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !setsContentDisposition(scope.info, call) {
				return true
			}
			if (&nameText{info: scope.info, fn: fn}).unescaped(call.Args[1], 0) {
				findings = append(findings, funcFinding{node: call, message: "Content-Disposition is built with %s or concatenation from text the server does not choose — a quote or a semicolon in it breaks the header"})
			}
			return true
		})
		return findings
	}
	return r
}

// setsContentDisposition reports header.Set or header.Add of
// Content-Disposition.
func setsContentDisposition(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Set" && sel.Sel.Name != "Add") || len(call.Args) != 2 {
		return false
	}
	if types.TypeString(info.TypeOf(sel.X), nil) != "net/http.Header" {
		return false
	}
	tv, ok := info.Types[call.Args[0]]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String &&
		strings.EqualFold(constant.StringVal(tv.Value), "Content-Disposition")
}

// nameText follows the value of a header through the local variables of a
// function.
type nameText struct {
	info *types.Info
	fn   *ast.FuncDecl
}

// maxNameDepth bounds how many local assignments a value is followed through.
const maxNameDepth = 3

// unescaped reports a header value that puts text the server does not choose
// in with %s, %v or +.
func (t *nameText) unescaped(expr ast.Expr, depth int) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		return isPkgFunc(t.info, e, "fmt", "Sprintf") && t.sprintfCarries(e, depth)
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (t.carries(e.X, depth) || t.carries(e.Y, depth))
	case *ast.Ident:
		if value := t.local(e); value != nil && depth < maxNameDepth {
			return t.unescaped(value, depth+1)
		}
	}
	return false
}

// sprintfCarries reports a Sprintf whose %s or %v argument carries text.
func (t *nameText) sprintfCarries(call *ast.CallExpr, depth int) bool {
	if len(call.Args) == 0 {
		return false
	}
	tv, ok := t.info.Types[call.Args[0]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	for i, verb := range formatVerbs(constant.StringVal(tv.Value)) {
		if (verb == 's' || verb == 'v') && 1+i < len(call.Args) && t.carries(call.Args[1+i], depth) {
			return true
		}
	}
	return false
}

// carries reports a string value that may hold any text: a field, a
// parameter, what a call returns. A constant, a formatted time or number, and
// a String of a non-string value hold no quote.
func (t *nameText) carries(expr ast.Expr, depth int) bool {
	tv, ok := t.info.Types[expr]
	if !ok || tv.Value != nil {
		return false
	}
	if basic, ok := tv.Type.Underlying().(*types.Basic); !ok || basic.Kind() != types.String {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if isPkgFunc(t.info, e, "fmt", "Sprintf") {
			return t.sprintfCarries(e, depth)
		}
		if fn := staticFunc(t.info, e); fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "strconv" {
			return false
		}
		if sel, ok := ast.Unparen(e.Fun).(*ast.SelectorExpr); ok && (sel.Sel.Name == "Format" || sel.Sel.Name == "String") {
			return false
		}
	case *ast.BinaryExpr:
		return t.carries(e.X, depth) || t.carries(e.Y, depth)
	case *ast.Ident:
		if value := t.local(e); value != nil && depth < maxNameDepth {
			return t.carries(value, depth+1)
		}
	}
	return true
}

// local returns the value a local variable is assigned once.
func (t *nameText) local(ident *ast.Ident) ast.Expr {
	v, ok := t.info.ObjectOf(ident).(*types.Var)
	if !ok {
		return nil
	}
	return singleAssignment(t.info, t.fn, v)
}

// WebStorageHoldsTokenRule detects a session token written into
// localStorage or sessionStorage:
//
//	localStorage.setItem('console_jwt', token)
//
// Any script on the page reads web storage, and a token kept there outlives
// the session the httpOnly cookie ends: one injected script takes the
// session with it.
type WebStorageHoldsTokenRule struct {
	*rules.BaseRule
}

// NewWebStorageHoldsTokenRule creates web-storage-holds-token.
func NewWebStorageHoldsTokenRule() *WebStorageHoldsTokenRule {
	return &WebStorageHoldsTokenRule{BaseRule: rules.NewBaseRule(
		"web-storage-holds-token",
		"security",
		"Detects a token, JWT or secret written into localStorage or sessionStorage — any script on the page reads it, and it outlives the session",
		core.SeverityMedium,
	)}
}

// webStorageSet is a setItem call with two plain arguments.
var webStorageSet = regexp.MustCompile(`\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*([^,()]+?)\s*,\s*([^,()]+?)\s*\)`)

// nonAlphanumeric separates the words of a storage key ('app_jwt').
var nonAlphanumeric = regexp.MustCompile(`[^A-Za-z0-9]+`)

// credentialWords name a value that opens a session or an account.
var credentialWords = wordSet("jwt", "token", "bearer", "password", "passwd", "secret", "apikey")

// AnalyzeFile reports the storage writes of a credential.
func (r *WebStorageHoldsTokenRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || skipFrontendPath(ctx) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range helpers.FileJSText(ctx) {
		m := webStorageSet.FindStringSubmatch(line)
		if m == nil || (!namesCredential(m[1]) && !namesCredential(m[2])) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "A token or secret is written into web storage — any script on the page reads it, and it outlives the session")
		v.WithCode(strings.TrimSpace(ctx.Lines[i]))
		v.WithSuggestion("Keep the session in an httpOnly cookie, or the token in memory only")
		violations = append(violations, v)
	}
	return violations
}

// namesCredential reports a storage key or value named after a credential:
// 'app_jwt', ACCESS_TOKEN_KEY, refreshToken. A CSRF token is meant to be
// read by the page's own script.
func namesCredential(arg string) bool {
	text := strings.Trim(arg, "'\"`")
	if i := strings.LastIndexByte(text, '.'); i >= 0 {
		text = text[i+1:]
	}
	var words []string
	for _, part := range nonAlphanumeric.Split(text, -1) {
		words = append(words, helpers.IdentifierWords(part)...)
	}
	credential := false
	for i, word := range words {
		switch {
		case word == "csrf" || word == "xsrf":
			return false
		case credentialWords[word], word == "key" && i > 0 && words[i-1] == "api":
			credential = true
		}
	}
	return credential
}

// NewRoleClaimTrustedWithoutRecheckRule creates
// role-claim-trusted-without-recheck: the login hands a role out only to an
// email on an allowlist, and the middleware trusts the role from the token
// on every request without asking the allowlist again:
//
//	if isOwnerEmail(email) { return identity{role: "owner"} }  // login
//	ctx = context.WithValue(ctx, roleKey, claims.Role)          // every request
//
// Taking the email off the list revokes nothing until the token expires.
func NewRoleClaimTrustedWithoutRecheckRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"role-claim-trusted-without-recheck",
			"security",
			"Detects a role the login grants only to an allowlisted email that the request middleware trusts from the token without asking the allowlist again — removing the email revokes nothing until the token expires",
			core.SeverityMedium,
		),
		suggestion: "Recheck the allowlist (or the stored grant) for the role in the middleware on each request",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(funcScope, *ast.FuncDecl) []funcFinding {
		grants := allowlistRoleGrants(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			obj, ok := scope.info.Defs[fn.Name].(*types.Func)
			if !ok || len(grants) == 0 {
				return nil
			}
			var predicates []*types.Func
			for p := range grants {
				if p.Pkg() == obj.Pkg() {
					predicates = append(predicates, p)
				}
			}
			slices.SortFunc(predicates, func(a, b *types.Func) int { return strings.Compare(a.Name(), b.Name()) })
			if len(predicates) == 0 || callsAnyOf(scope, fn.Body, predicates, 1) {
				return nil
			}
			var findings []funcFinding
			for _, body := range handlerBodies(scope.info, fn) {
				inspectOwnBody(body, func(n ast.Node) {
					call, ok := n.(*ast.CallExpr)
					if !ok || !isPkgFunc(scope.info, call, "context", "WithValue") || len(call.Args) != 3 {
						return
					}
					if sel, ok := ast.Unparen(call.Args[2]).(*ast.SelectorExpr); ok && hasTokenIn(sel.Sel.Name, wordSet("role")) {
						findings = append(findings, funcFinding{node: call, message: "The role from the token is trusted on every request, while the login grants it only to emails " +
							predicates[0].Name() + " allows — removing an email from the list revokes nothing until the token expires"})
					}
				})
			}
			return findings
		}
	}
	return r
}

// allowlistRoleGrants returns the allowlist predicates a branch that hands
// out a role is conditioned on: if isOwnerEmail(e) { ... role: "owner" ... }.
func allowlistRoleGrants(decls map[*types.Func]typedFuncDecl) map[*types.Func]bool {
	grants := make(map[*types.Func]bool)
	for _, d := range decls {
		ast.Inspect(d.decl.Body, func(n ast.Node) bool {
			check, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			call, ok := ast.Unparen(check.Cond).(*ast.CallExpr)
			if !ok {
				return true
			}
			if p := allowlistPredicate(d.info, call); p != nil && grantsRole(check.Body) {
				grants[p] = true
			}
			return true
		})
	}
	return grants
}

// grantsRole reports a block that sets a role to a string: role: "owner",
// identity.Role = "owner".
func grantsRole(body *ast.BlockStmt) bool {
	isRole := func(expr ast.Expr) bool {
		switch e := ast.Unparen(expr).(type) {
		case *ast.Ident:
			return hasTokenIn(e.Name, wordSet("role"))
		case *ast.SelectorExpr:
			return hasTokenIn(e.Sel.Name, wordSet("role"))
		}
		return false
	}
	isString := func(expr ast.Expr) bool {
		basic, ok := ast.Unparen(expr).(*ast.BasicLit)
		return ok && basic.Kind == token.STRING
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.KeyValueExpr:
			found = found || (isRole(e.Key) && isString(e.Value))
		case *ast.AssignStmt:
			for i, lhs := range e.Lhs {
				found = found || (i < len(e.Rhs) && isRole(lhs) && isString(e.Rhs[i]))
			}
		}
		return !found
	})
	return found
}

// allowlistWords name a predicate that checks a list of allowed accounts.
var allowlistWords = wordSet("email", "allowed", "allowlist", "allowlisted", "whitelist", "whitelisted")

// allowlistPredicate returns the function a call checks an allowlist with: a
// package function of a string answering a bool, named after an email or an
// allowlist (isOwnerEmail, isAllowedUser).
func allowlistPredicate(info *types.Info, call *ast.CallExpr) *types.Func {
	fn := staticFunc(info, call)
	if fn == nil || !hasTokenIn(fn.Name(), allowlistWords) {
		return nil
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() != nil || sig.Params().Len() == 0 || sig.Results().Len() != 1 {
		return nil
	}
	if !isBasicKind(sig.Params().At(0).Type(), types.String) || !isBasicKind(sig.Results().At(0).Type(), types.Bool) {
		return nil
	}
	return fn
}

// isBasicKind reports a type whose underlying type is the basic kind.
func isBasicKind(t types.Type, kind types.BasicKind) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == kind
}

// callsAnyOf reports a body that calls one of the functions, directly or in
// a loaded callee up to depth calls down.
func callsAnyOf(scope funcScope, body *ast.BlockStmt, fns []*types.Func, depth int) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if callee := staticFunc(scope.info, call); callee != nil {
			for _, fn := range fns {
				found = found || callee.Origin() == fn
			}
		}
		if !found && depth > 0 {
			if decl, ok := scope.callee(call); ok {
				found = callsAnyOf(funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}, decl.decl.Body, fns, depth-1)
			}
		}
		return !found
	})
	return found
}

// WritePermissionIsReadRule detects a route permission entry whose write
// permission is a read permission:
//
//	{prefix: "/rates", read: "reports:read", write: "reports:read"}
//
// A role that may only read the section changes its data. An entry with a
// flag set (selfScoped: true) says the handler narrows the write itself and
// is left out.
type WritePermissionIsReadRule struct {
	*rules.BaseRule
}

// NewWritePermissionIsReadRule creates write-permission-is-read.
func NewWritePermissionIsReadRule() *WritePermissionIsReadRule {
	return &WritePermissionIsReadRule{BaseRule: rules.NewBaseRule(
		"write-permission-is-read",
		"security",
		"Detects a permission entry whose write permission is a read permission — a read-only role changes the data",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the entries of the file's permission tables.
func (r *WritePermissionIsReadRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if write := readWrite(lit); write != nil {
			line := ctx.LineFor(write)
			if !ctx.IsSuppressed(line, r.Name()) {
				v := r.CreateViolation(ctx.RelPath, line, "The write permission of this entry is a read permission — a role that may only read the section changes its data")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Require a write permission for changes, or mark the entry as scoped to the caller's own data")
				violations = append(violations, v)
			}
		}
		return true
	})
	return violations
}

var (
	readKeyWords  = wordSet("read", "view", "get")
	writeKeyWords = wordSet("write", "mutate", "update", "edit", "modify", "change")
)

// readWrite returns the write entry of a literal {read: "x:read", write:
// "x:read"} whose write permission equals the read one or names reading.
func readWrite(lit *ast.CompositeLit) *ast.KeyValueExpr {
	var read, write *ast.KeyValueExpr
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			return nil
		}
		if value, ok := kv.Value.(*ast.Ident); ok && value.Name == "true" {
			return nil
		}
		words := helpers.IdentifierWords(key.Name)
		switch {
		case len(words) == 0:
		case readKeyWords[words[0]]:
			read = kv
		case writeKeyWords[words[0]]:
			write = kv
		}
	}
	if read == nil || write == nil {
		return nil
	}
	readValue, ok1 := stringLiteral(read.Value)
	writeValue, ok2 := stringLiteral(write.Value)
	if !ok1 || !ok2 || writeValue == "" {
		return nil
	}
	if writeValue == readValue {
		return write
	}
	words := nonAlphanumeric.Split(strings.ToLower(writeValue), -1)
	reads, writes := false, false
	for _, word := range words {
		reads = reads || readKeyWords[word]
		writes = writes || writeKeyWords[word] || word == "manage"
	}
	if reads && !writes {
		return write
	}
	return nil
}

// roleGrantCall is a call that gives a principal a role: EnsureDefaultRole,
// GrantRole.
var roleGrantCall = regexp.MustCompile(`^(?:Ensure|Grant|Assign|Add|Restore)\w*Role$`)

// NewAllowlistRegrantsRevokedRoleRule creates allowlist-regrants-revoked-role:
// an allowlisted account gets its role back on every access, or the
// allowlist alone authorizes it next to the stored roles:
//
//	if isSeedEmail(email) { store.EnsureDefaultRole(ctx, staff.ID, "super_admin") }
//	return isSeedEmail(email) || len(access.Roles) > 0, nil
//
// A role removed in the admin screen comes back with the next request: the
// list meant to seed the first administrator overrides every later decision.
func NewAllowlistRegrantsRevokedRoleRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"allowlist-regrants-revoked-role",
			"security",
			"Detects an allowlisted account that gets its role back on every access, or that the allowlist alone authorizes next to the stored roles — a role removed in the admin screen does not hold",
			core.SeverityMedium,
		),
		suggestion: "Grant the seed role only when the account is created, and authorize by the stored roles alone",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.IfStmt:
				call, ok := ast.Unparen(node.Cond).(*ast.CallExpr)
				if !ok || allowlistPredicate(scope.info, call) == nil {
					return true
				}
				ast.Inspect(node.Body, func(m ast.Node) bool {
					if grant, ok := m.(*ast.CallExpr); ok && roleGrantCall.MatchString(calledName(grant)) {
						findings = append(findings, funcFinding{node: grant, message: "The allowlisted account gets its role back on every access — a role removed in the admin screen comes back with the next request"})
					}
					return true
				})
			case *ast.ReturnStmt:
				if len(node.Results) > 0 && authorizesByAllowlist(scope.info, node.Results[0]) && isAuthorizer(scope.info, fn) {
					findings = append(findings, funcFinding{node: node, message: "The allowlist alone authorizes the account next to its stored roles — removing every role in the admin screen leaves it in"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// authorizesByAllowlist reports `isSeedEmail(e) || <stored check>`.
func authorizesByAllowlist(info *types.Info, expr ast.Expr) bool {
	or, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || or.Op != token.LOR {
		return false
	}
	for _, side := range []ast.Expr{or.X, or.Y} {
		if call, ok := ast.Unparen(side).(*ast.CallExpr); ok && allowlistPredicate(info, call) != nil {
			return true
		}
	}
	return false
}

// isAuthorizer reports a function that answers whether an account is let in:
// Authorized, IsAllowed, CanAccess, with a bool first result.
func isAuthorizer(info *types.Info, fn *ast.FuncDecl) bool {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Results().Len() == 0 || !isBasicKind(sig.Results().At(0).Type(), types.Bool) {
		return false
	}
	return hasTokenIn(fn.Name.Name, wordSet("authorized", "authorize", "allowed", "permitted", "access"))
}
