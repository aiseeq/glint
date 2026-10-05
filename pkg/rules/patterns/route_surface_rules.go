package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewUnauthenticatedRouteOutsideRateLimitRule())
	rules.Register(NewAuthenticatedPagesWithoutNoStoreRule())
	rules.Register(NewCDNAssetWithoutIntegrityRule())
	rules.Register(NewPrivilegedSurfaceEnabledByDefaultRule())
	rules.Register(NewTestDataPathUngatedInProductionRule())
	rules.Register(NewNilSliceAsUnrestrictedScopeRule())
}

// routeScope is one level of a router built in a function body: the router
// itself or a Group/Route of it, with its middleware and its routes.
type routeScope struct {
	parent   *routeScope
	uses     []routeUse
	routes   []*ast.CallExpr // r.Get(pattern, handler) and the like
	children []*routeScope
}

// routeUse is the middleware one statement applies: r.Use(...) itself, or a
// call of a helper that applies it to the router it is given
// (a.useCommonMiddleware(r, limit)); at is the statement's call, info types
// the middleware expressions.
type routeUse struct {
	at   *ast.CallExpr
	args []ast.Expr
	info *types.Info
}

// routeMethods register a handler for a pattern.
var routeMethods = map[string]bool{"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true, "Head": true,
	"Options": true, "Connect": true, "Trace": true, "Handle": true, "HandleFunc": true, "Method": true, "MethodFunc": true}

// routerScope builds the router tree of the statements of a block whose
// calls go to a router: a value with Use and Get or Handle methods.
func routerScope(scope funcScope, block *ast.BlockStmt, parent *routeScope) *routeScope {
	info := scope.info
	rs := &routeScope{parent: parent}
	for _, stmt := range block.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !isRouter(info.TypeOf(sel.X)) {
			rs.uses = append(rs.uses, helperUses(scope, call)...)
			continue
		}
		switch name := sel.Sel.Name; {
		case name == "Use":
			rs.uses = append(rs.uses, routeUse{at: call, args: call.Args, info: info})
		case name == "Group" && len(call.Args) == 1:
			if lit, ok := call.Args[0].(*ast.FuncLit); ok {
				rs.children = append(rs.children, routerScope(scope, lit.Body, rs))
			}
		case name == "Route" && len(call.Args) == 2:
			if lit, ok := call.Args[1].(*ast.FuncLit); ok {
				rs.children = append(rs.children, routerScope(scope, lit.Body, rs))
			}
		case routeMethods[name] && len(call.Args) >= 2:
			rs.routes = append(rs.routes, call)
		}
	}
	return rs
}

// helperUses returns the middleware a loaded helper applies to the router
// the call passes it: the Use calls of its body on that parameter.
func helperUses(scope funcScope, call *ast.CallExpr) []routeUse {
	helper, ok := scope.callee(call)
	if !ok {
		return nil
	}
	params := paramObjects(helper)
	var uses []routeUse
	for i, arg := range call.Args {
		if i >= len(params) || params[i] == nil || !isRouter(scope.info.TypeOf(arg)) {
			continue
		}
		for _, stmt := range helper.decl.Body.List {
			expr, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			inner, ok := expr.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := inner.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Use" && identObject(helper.info, sel.X) == params[i] {
				uses = append(uses, routeUse{at: call, args: inner.Args, info: helper.info})
			}
		}
	}
	return uses
}

// isRouter reports a type with a Use method and a Get or Handle method.
func isRouter(t types.Type) bool {
	if t == nil {
		return false
	}
	has := func(name string) bool {
		obj, _, _ := types.LookupFieldOrMethod(t, true, nil, name)
		_, ok := obj.(*types.Func)
		return ok
	}
	return has("Use") && (has("Get") || has("Handle"))
}

// walk calls visit on the scope and its descendants.
func (s *routeScope) walk(visit func(*routeScope)) {
	visit(s)
	for _, child := range s.children {
		child.walk(visit)
	}
}

// chainUses reports a middleware of the scope or its ancestors match accepts.
func (s *routeScope) chainUses(match func(info *types.Info, expr ast.Expr) bool) bool {
	for scope := s; scope != nil; scope = scope.parent {
		if firstUse(scope, match) != nil {
			return true
		}
	}
	return false
}

// namesMiddleware reports a middleware expression whose text holds one of the
// words: limiter.middleware(), a.basicAuth, requirePermission(...).
func namesMiddleware(expr ast.Expr, words ...string) bool {
	text := strings.ToLower(middlewareName(expr))
	for _, word := range words {
		if strings.Contains(text, word) {
			return true
		}
	}
	return false
}

// middlewareName spells a middleware expression, the factory for a call:
// limiter.middleware for limiter.middleware().
func middlewareName(expr ast.Expr) string {
	if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok {
		expr = call.Fun
	}
	return helpers.ExprText(expr)
}

// isLimiter matches a rate-limit middleware.
func isLimiter(_ *types.Info, expr ast.Expr) bool { return namesMiddleware(expr, "limit", "throttl") }

// isAuthMiddleware matches a middleware that authenticates the request.
func isAuthMiddleware(_ *types.Info, expr ast.Expr) bool {
	return namesMiddleware(expr, "auth", "session", "permission", "login", "requireuser")
}

// funcOfExpr returns the loaded declaration a handler or middleware
// expression names: a function, a method value, or the function a call of a
// factory returns from.
func funcOfExpr(scope funcScope, info *types.Info, expr ast.Expr) (typedFuncDecl, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		fn := staticFunc(info, e)
		if fn == nil {
			return typedFuncDecl{}, false
		}
		decl, ok := scope.decls[fn.Origin()]
		return decl, ok
	case *ast.Ident:
		fn, ok := info.Uses[e].(*types.Func)
		if !ok {
			return typedFuncDecl{}, false
		}
		decl, ok := scope.decls[fn.Origin()]
		return decl, ok
	case *ast.SelectorExpr:
		fn, ok := info.Uses[e.Sel].(*types.Func)
		if !ok {
			return typedFuncDecl{}, false
		}
		decl, ok := scope.decls[fn.Origin()]
		return decl, ok
	}
	return typedFuncDecl{}, false
}

// reaches reports a body that, itself or through the loaded functions it
// calls up to depth levels down, makes a call match accepts.
func reaches(scope funcScope, decl typedFuncDecl, depth int, match func(info *types.Info, call *ast.CallExpr) bool) bool {
	seen := make(map[*ast.FuncDecl]bool)
	var visit func(d typedFuncDecl, level int) bool
	visit = func(d typedFuncDecl, level int) bool {
		if seen[d.decl] || d.decl.Body == nil {
			return false
		}
		seen[d.decl] = true
		found := false
		ast.Inspect(d.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			if match(d.info, call) {
				found = true
				return false
			}
			if level < depth {
				if fn := staticFunc(d.info, call); fn != nil {
					if next, ok := scope.decls[fn.Origin()]; ok && visit(next, level+1) {
						found = true
					}
				}
			}
			return !found
		})
		return found
	}
	return visit(decl, 0)
}

// reachesStorage matches a call of a database handle's method: a query, an
// exec or a ping.
func reachesStorage(_ *types.Info, call *ast.CallExpr) bool {
	name := callName(call)
	return slices.Contains(helpers.SQLMethods, name) || slices.Contains(helpers.SQLPingMethods, name)
}

// NewUnauthenticatedRouteOutsideRateLimitRule creates unauthenticated-route-outside-rate-limit:
// a router limits the rate of some groups, and a route registered outside
// them reaches the database or checks a shared secret - a flood of it loads
// the database, or guesses the secret, with no limit:
//
//	r.Get("/ready", s.readiness)             // pings the database
//	r.Route("/api", func(r chi.Router) {
//		r.Use(limiter.middleware())
func NewUnauthenticatedRouteOutsideRateLimitRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"unauthenticated-route-outside-rate-limit",
			"patterns",
			"Detects a route registered outside the rate-limited groups of its router whose handler reaches the database or checks a shared secret — a flood or a guessing run goes unthrottled",
			core.SeverityMedium,
		),
		suggestion: "Register the route in a group with a limiter of its own (a separate instance, so a flood there does not spend the API's budget)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		root := routerScope(scope, fn.Body, nil)
		limited := false
		root.walk(func(s *routeScope) { limited = limited || s.chainUses(isLimiter) })
		if !limited {
			return nil
		}
		var findings []funcFinding
		root.walk(func(s *routeScope) {
			if s.chainUses(isLimiter) || s.chainUses(isAuthMiddleware) {
				return
			}
			for _, route := range s.routes {
				handler, ok := funcOfExpr(scope, scope.info, route.Args[len(route.Args)-1])
				if !ok {
					continue
				}
				switch {
				case reaches(scope, handler, 2, reachesStorage):
					findings = append(findings, funcFinding{node: route, message: "The route reaches the database but is registered outside the rate-limited groups of its router — a flood of it loads the database unthrottled"})
				case reaches(scope, handler, 2, func(info *types.Info, call *ast.CallExpr) bool {
					return isPkgFunc(info, call, "crypto/subtle", "ConstantTimeCompare") || isPkgFunc(info, call, "crypto/hmac", "Equal")
				}):
					findings = append(findings, funcFinding{node: route, message: "The route checks a shared secret but is registered outside the rate-limited groups of its router — guesses at the secret go unthrottled"})
				}
			}
		})
		return findings
	}
	return r
}

// NewAuthenticatedPagesWithoutNoStoreRule creates authenticated-pages-without-no-store:
// a group of server-rendered pages behind a login where nothing sets
// Cache-Control - a browser or a proxy keeps an operator's page and shows it
// after logout or to the next user:
//
//	r.Group(func(r chi.Router) {
//		r.Use(a.basicAuth)            // and no middleware sets Cache-Control: no-store
func NewAuthenticatedPagesWithoutNoStoreRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"authenticated-pages-without-no-store",
			"patterns",
			"Detects a router group of HTML pages behind an auth middleware where no middleware or handler sets Cache-Control — the pages stay in browser and proxy caches",
			core.SeverityMedium,
		),
		suggestion: "Add a middleware to the group that sets Cache-Control: private, no-store",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		obj, ok := scope.info.Defs[fn.Name].(*types.Func)
		if fn.Body == nil || !ok || obj.Pkg() == nil || !importsPath(obj.Pkg(), "html/template") {
			return nil
		}
		setsCacheControl := func(info *types.Info, expr ast.Expr) bool {
			decl, ok := funcOfExpr(scope, info, expr)
			return ok && reaches(scope, decl, 2, writesCacheControl)
		}
		var findings []funcFinding
		routerScope(scope, fn.Body, nil).walk(func(s *routeScope) {
			auth := firstUse(s, isAuthMiddleware)
			if auth == nil || (s.parent != nil && s.parent.chainUses(isAuthMiddleware)) || s.chainUses(setsCacheControl) {
				return
			}
			handled, routes := false, 0
			s.walk(func(inner *routeScope) {
				for _, route := range inner.routes {
					routes++
					handled = handled || setsCacheControl(scope.info, route.Args[len(route.Args)-1])
				}
			})
			if routes > 0 && !handled {
				findings = append(findings, funcFinding{node: auth.at, message: "Pages behind " + middlewareName(auth.expr) + " are served without Cache-Control: no-store — a browser or a proxy keeps them after logout"})
			}
		})
		return findings
	}
	return r
}

// usedMiddleware is one middleware expression of a Use and where it is
// applied.
type usedMiddleware struct {
	at   *ast.CallExpr
	expr ast.Expr
}

// firstUse returns the first middleware of the scope match accepts.
func firstUse(s *routeScope, match func(info *types.Info, expr ast.Expr) bool) *usedMiddleware {
	for _, use := range s.uses {
		for _, arg := range use.args {
			if match(use.info, arg) {
				return &usedMiddleware{at: use.at, expr: arg}
			}
		}
	}
	return nil
}

// importsPath reports a package importing path.
func importsPath(pkg *types.Package, path string) bool {
	for _, imported := range pkg.Imports() {
		if imported.Path() == path {
			return true
		}
	}
	return false
}

// writesCacheControl matches header.Set("Cache-Control", ...) or Add.
func writesCacheControl(_ *types.Info, call *ast.CallExpr) bool {
	name := callName(call)
	if (name != "Set" && name != "Add") || len(call.Args) != 2 {
		return false
	}
	key, ok := stringLiteral(call.Args[0])
	return ok && strings.EqualFold(key, "Cache-Control")
}

// CDNAssetWithoutIntegrityRule detects a template that loads a script or a
// stylesheet from a third-party origin without an integrity hash: whatever
// the CDN serves runs inside the page's origin.
type CDNAssetWithoutIntegrityRule struct {
	*rules.BaseRule
}

// NewCDNAssetWithoutIntegrityRule creates cdn-asset-without-integrity.
func NewCDNAssetWithoutIntegrityRule() *CDNAssetWithoutIntegrityRule {
	return &CDNAssetWithoutIntegrityRule{BaseRule: rules.NewBaseRule(
		"cdn-asset-without-integrity",
		"patterns",
		"Detects a <script src> or a stylesheet <link> in a template pointing at a third-party origin without an integrity attribute — a changed or hijacked CDN file runs in the page",
		core.SeverityMedium,
	)}
}

var (
	assetTag      = regexp.MustCompile(`(?is)<(script|link)\b[^>]*>`)
	externalAsset = regexp.MustCompile(`(?i)\b(?:src|href)\s*=\s*["']?(?:https?:)?//`)
	stylesheetRel = regexp.MustCompile(`(?i)\brel\s*=\s*["']?(?:stylesheet|modulepreload)\b`)
	integrityAttr = regexp.MustCompile(`(?i)\bintegrity\s*=`)
)

// AnalyzeFile reports the external assets of a template that carry no
// integrity hash.
func (r *CDNAssetWithoutIntegrityRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTemplate() {
		return nil
	}
	// Pages kept with the documentation (mockups, prototypes, reports) are
	// not served by the application.
	if slices.Contains(strings.Split(filepath.ToSlash(ctx.RelPath), "/"), "docs") {
		return nil
	}
	text := string(ctx.Content)
	var violations []*core.Violation
	for _, loc := range assetTag.FindAllStringSubmatchIndex(text, -1) {
		tag := text[loc[0]:loc[1]]
		kind := strings.ToLower(text[loc[2]:loc[3]])
		if !externalAsset.MatchString(tag) || integrityAttr.MatchString(tag) || (kind != "script" && !stylesheetRel.MatchString(tag)) {
			continue
		}
		line := strings.Count(text[:loc[0]], "\n") + 1
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, "A third-party "+kind+" is loaded without an integrity hash — whatever the CDN serves runs in the page")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Pin the file with integrity=\"sha384-...\" crossorigin=\"anonymous\", or serve it from the application")
		violations = append(violations, v)
	}
	return violations
}

// privilegedWords name a surface that must stay off unless asked for.
var privilegedWords = map[string]bool{"admin": true, "debug": true, "mock": true, "insecure": true, "pprof": true,
	"swagger": true, "playground": true, "fake": true, "stub": true}

// NewPrivilegedSurfaceEnabledByDefaultRule creates privileged-surface-enabled-by-default:
// an admin panel, a debug endpoint or a mock provider switched on unless an
// environment variable turns it off - a deployment that forgets the variable
// exposes it:
//
//	adminEnabled := true
//	if v := os.Getenv("ADMIN_ENABLED"); v != "" { adminEnabled = v == "true" }
func NewPrivilegedSurfaceEnabledByDefaultRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"privileged-surface-enabled-by-default",
			"patterns",
			"Detects an admin, debug or mock switch that is on unless an environment variable turns it off — a deployment without the variable exposes it",
			core.SeverityHigh,
		),
		suggestion: "Default the switch to off and turn it on explicitly where it is wanted",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if node.Tok != token.DEFINE || len(node.Lhs) != 1 || len(node.Rhs) != 1 || !isIdentNamed(node.Rhs[0], "true") {
					return true
				}
				v := identObject(scope.info, node.Lhs[0])
				if v != nil && namesPrivileged(v.Name()) && overriddenFromEnv(scope.info, fn.Body, v) {
					findings = append(findings, funcFinding{node: node, message: v.Name() + " is on unless an environment variable turns it off — a deployment without the variable exposes it"})
				}
			case *ast.CallExpr:
				if key, ok := privilegedEnvDefaultTrue(node); ok {
					findings = append(findings, funcFinding{node: node, message: key + " defaults to true — a deployment without the variable exposes what it switches on"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// namesPrivileged reports a name holding a privileged word.
func namesPrivileged(name string) bool {
	for _, word := range helpers.IdentifierWords(name) {
		if privilegedWords[word] {
			return true
		}
	}
	return false
}

// overriddenFromEnv reports a body assigning v inside an if that reads the
// environment.
func overriddenFromEnv(info *types.Info, body *ast.BlockStmt, v *types.Var) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || found {
			return !found
		}
		readsEnv := false
		for _, part := range []ast.Node{ifStmt.Init, ifStmt.Cond} {
			if part == nil {
				continue
			}
			ast.Inspect(part, func(m ast.Node) bool {
				if call, ok := m.(*ast.CallExpr); ok && (isPkgFunc(info, call, "os", "Getenv") || isPkgFunc(info, call, "os", "LookupEnv")) {
					readsEnv = true
				}
				return !readsEnv
			})
		}
		if !readsEnv {
			return true
		}
		ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
			if assign, ok := m.(*ast.AssignStmt); ok {
				for _, lhs := range assign.Lhs {
					if identObject(info, lhs) == v {
						found = true
					}
				}
			}
			return !found
		})
		return !found
	})
	return found
}

// envKey matches the name of an environment variable.
var envKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// privilegedEnvDefaultTrue matches envBool("ADMIN_ENABLED", true): a call
// reading a privileged environment key with a true default.
func privilegedEnvDefaultTrue(call *ast.CallExpr) (string, bool) {
	if len(call.Args) < 2 {
		return "", false
	}
	key, ok := stringLiteral(call.Args[0])
	if !ok || !envKey.MatchString(key) || !namesPrivileged(key) {
		return "", false
	}
	for _, arg := range call.Args[1:] {
		if isIdentNamed(arg, "true") {
			return key, true
		}
		if s, ok := stringLiteral(arg); ok && (s == "true" || s == "1") {
			return key, true
		}
	}
	return "", false
}

// testGateWords name what a handler checks to keep test tooling off in
// production.
var testGateWords = map[string]bool{"cfg": true, "config": true, "conf": true, "env": true, "test": true, "tests": true, "debug": true,
	"dev": true, "sandbox": true, "demo": true, "enabled": true, "feature": true, "flag": true, "flags": true, "tools": true}

// NewTestDataPathUngatedInProductionRule creates test-data-path-ungated-in-production:
// an HTTP handler fills an entity from a helper of hardcoded test data and
// stores it, with no configuration check on the way - in production it
// creates real records from fake people:
//
//	order := input.newTestOrder()
//	err := a.createOrder(ctx, order)
func NewTestDataPathUngatedInProductionRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"test-data-path-ungated-in-production",
			"patterns",
			"Detects an HTTP handler that stores an entity filled by a test-data helper with no configuration check — production gets real records made of test data",
			core.SeverityHigh,
		),
		suggestion: "Refuse the request unless a test-tools switch is on, and keep that switch off in production",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || requestParam(scope.info, fn) == nil || checksGate(scope.info, fn.Body) {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !namesTestData(callName(call)) {
				return true
			}
			if _, loaded := scope.callee(call); !loaded {
				return true
			}
			entity := testDataEntity(scope.info, fn.Body, call)
			if entity != nil && storedIn(scope, fn.Body, entity) {
				findings = append(findings, funcFinding{node: call, message: callName(call) + " fills " + entity.Name() + " with test data and the handler stores it with no configuration check — production gets real records made of test data"})
			}
			return true
		})
		return findings
	}
	return r
}

// namesTestData reports a function named for test data: newTestOrder,
// applyTestCustomer.
func namesTestData(name string) bool {
	words := helpers.IdentifierWords(name)
	for i, word := range words {
		if word == "test" && i > 0 {
			return true
		}
	}
	return false
}

// checksGate reports a body with an if whose condition reads a configuration
// or a test switch.
func checksGate(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || found {
			return !found
		}
		ast.Inspect(ifStmt.Cond, func(m ast.Node) bool {
			if id, ok := m.(*ast.Ident); ok {
				for _, word := range helpers.IdentifierWords(id.Name) {
					found = found || testGateWords[word]
				}
			}
			if call, ok := m.(*ast.CallExpr); ok && (isPkgFunc(info, call, "os", "Getenv") || isPkgFunc(info, call, "os", "LookupEnv")) {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}

// testDataEntity returns the variable a test-data call fills: the one it is
// assigned to, or its first argument.
func testDataEntity(info *types.Info, body *ast.BlockStmt, call *ast.CallExpr) *types.Var {
	var entity *types.Var
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 && ast.Unparen(assign.Rhs[0]) == call {
			entity = identObject(info, assign.Lhs[0])
		}
		return entity == nil
	})
	if entity == nil && len(call.Args) > 0 {
		entity = identObject(info, call.Args[0])
	}
	return entity
}

// storedIn reports a body passing the entity to a write: a call named for one
// or a loaded function that makes one.
func storedIn(scope funcScope, body *ast.BlockStmt, entity *types.Var) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		passes := false
		for _, arg := range call.Args {
			passes = passes || identObject(scope.info, arg) == entity
		}
		if !passes {
			return true
		}
		if helpers.IsWriteName(callName(call)) {
			found = true
		} else if decl, ok := scope.callee(call); ok && reaches(scope, decl, 1, func(_ *types.Info, inner *ast.CallExpr) bool { return helpers.IsWriteName(callName(inner)) }) {
			found = true
		}
		return !found
	})
	return found
}

// NewNilSliceAsUnrestrictedScopeRule creates nil-slice-as-unrestricted-scope:
// a field read as "nil means everything" (if u.TeamIDs == nil { return
// true }) filled from a loader that builds its slice with var s []T and
// append - for a user with no rows the loader returns nil, and the user with
// nothing assigned is given everything:
//
//	pids, err := repo.TeamIDsForUser(ctx, id)   // var ids []int; ids = append(ids, ...)
//	uc.TeamIDs = pids
func NewNilSliceAsUnrestrictedScopeRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"nil-slice-as-unrestricted-scope",
			"patterns",
			"Detects a field treated as unrestricted when nil, filled from a loader that returns nil for zero rows — an account with nothing assigned gets everything",
			core.SeverityHigh,
		),
		suggestion: "Return an empty non-nil slice from the loader (ids := []T{}), or keep \"all\" as an explicit flag instead of nil",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		nilScoped := nilComparedSliceFields(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			if fn.Body == nil || len(nilScoped) == 0 {
				return nil
			}
			defs := loaderResults(scope.info, fn.Body)
			var findings []funcFinding
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
					return true
				}
				_, field, ok := fieldSelection(scope.info, assign.Lhs[0])
				if !ok || !nilScoped[field] {
					return true
				}
				call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
				if !ok {
					if v := identObject(scope.info, assign.Rhs[0]); v != nil {
						call = defs[v]
					}
				}
				if call == nil {
					return true
				}
				if loader, ok := scope.callee(call); ok && returnsAppendedNil(loader) {
					findings = append(findings, funcFinding{node: assign, message: field.Name() + " is read as unrestricted when nil, and " + callName(call) + " returns nil for zero rows — an account with nothing assigned gets everything"})
				}
				return true
			})
			return findings
		}
	}
	return r
}

// nilComparedSliceFields returns the slice fields some body compares with
// nil.
func nilComparedSliceFields(decls map[*types.Func]typedFuncDecl) map[*types.Var]bool {
	fields := make(map[*types.Var]bool)
	for _, decl := range decls {
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
				return true
			}
			for _, pair := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
				if !isNilIdent(pair[1]) {
					continue
				}
				if _, field, ok := fieldSelection(decl.info, pair[0]); ok {
					if _, isSlice := field.Type().Underlying().(*types.Slice); isSlice {
						fields[field] = true
					}
				}
			}
			return true
		})
	}
	return fields
}

// loaderResults maps the variables a body defines as the first result of a
// call to that call: pids, err := repo.TeamIDs(ctx, id).
func loaderResults(info *types.Info, body *ast.BlockStmt) map[*types.Var]*ast.CallExpr {
	results := make(map[*types.Var]*ast.CallExpr)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		if call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); ok {
			if v := identObject(info, assign.Lhs[0]); v != nil {
				results[v] = call
			}
		}
		return true
	})
	return results
}

// returnsAppendedNil reports a function returning a slice declared with
// var s []T and grown only by append: nil when nothing was appended.
func returnsAppendedNil(fn typedFuncDecl) bool {
	declared := make(map[*types.Var]bool)
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Values) != 0 {
			return true
		}
		for _, name := range spec.Names {
			if v, ok := fn.info.Defs[name].(*types.Var); ok {
				if _, isSlice := v.Type().Underlying().(*types.Slice); isSlice {
					declared[v] = true
				}
			}
		}
		return true
	})
	if len(declared) == 0 {
		return false
	}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			v := identObject(fn.info, lhs)
			if v == nil || !declared[v] || i >= len(assign.Rhs) {
				continue
			}
			if call, ok := ast.Unparen(assign.Rhs[i]).(*ast.CallExpr); !ok || !isIdentNamed(call.Fun, "append") {
				delete(declared, v)
			}
		}
		return true
	})
	found := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) > 0 {
			if v := identObject(fn.info, ret.Results[0]); v != nil && declared[v] {
				found = true
			}
		}
		return !found
	})
	return found
}
