package patterns

import (
	"cmp"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewWebhookProcessingErrorAcknowledgedRule())
	rules.Register(NewWebhookEvidenceNotPersistedBefore4xxRule())
	rules.Register(NewCachedTokenNotInvalidatedRule())
}

// webhookWords name an entry point that receives another system's events.
var webhookWords = wordSet("webhook", "callback", "hook", "notification", "notify", "ipn")

// isWebhookFunc reports a function or a method of a type named like a
// webhook receiver.
func isWebhookFunc(fn *ast.FuncDecl) bool {
	if hasTokenIn(fn.Name.Name, webhookWords) {
		return true
	}
	return hasTokenIn(receiverTypeName(fn.Recv), webhookWords)
}

// responseWriterParam returns the http.ResponseWriter parameter of a function.
func responseWriterParam(info *types.Info, fn *ast.FuncDecl) types.Object {
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			obj := info.Defs[name]
			if obj != nil && isNamedType(obj.Type(), "net/http", "ResponseWriter") {
				return obj
			}
		}
	}
	return nil
}

// writtenStatus returns the status a statement answers through the writer:
// w.WriteHeader(code), http.Error(w, msg, code), or 200 for w.Write.
func writtenStatus(info *types.Info, stmt ast.Stmt, writer types.Object) (int64, bool) {
	exprStmt, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return 0, false
	}
	call, ok := ast.Unparen(exprStmt.X).(*ast.CallExpr)
	if !ok {
		return 0, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, false
	}
	if base, ok := sel.X.(*ast.Ident); ok && info.Uses[base] == writer {
		switch sel.Sel.Name {
		case "WriteHeader":
			if len(call.Args) == 1 {
				return constInt(info, call.Args[0])
			}
		case "Write":
			return 200, true
		}
		return 0, false
	}
	if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" && sel.Sel.Name == "Error" && len(call.Args) == 3 {
		if arg, ok := call.Args[0].(*ast.Ident); ok && info.Uses[arg] == writer {
			return constInt(info, call.Args[2])
		}
	}
	return 0, false
}

func constInt(info *types.Info, expr ast.Expr) (int64, bool) {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(tv.Value)
}

// onlyLogs reports a non-empty block made of logger calls alone.
func onlyLogs(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	for _, stmt := range body.List {
		if !isLoggerStmt(stmt) {
			return false
		}
	}
	return true
}

// NewWebhookProcessingErrorAcknowledgedRule creates
// webhook-processing-error-acknowledged: a webhook handler whose processing
// error is only logged before the success status, and a webhook processing
// function that logs a status it does not know and returns nil. The sender
// takes the 2xx as delivered and never sends the update again.
func NewWebhookProcessingErrorAcknowledgedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"webhook-processing-error-acknowledged",
			"patterns",
			"Detects a webhook whose processing failure is answered with success: an error only logged before the 2xx, or an unknown status logged and returned as nil — the sender never delivers the update again",
			core.SeverityHigh,
		),
		suggestion: "Answer a failed or unrecognized webhook with an error status, or persist it for a retry before acknowledging",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if !isWebhookFunc(fn) {
			return nil
		}
		info := scope.info
		if writer := responseWriterParam(info, fn); writer != nil {
			return acknowledgedFailures(info, fn.Body, writer)
		}
		if signature, ok := info.TypeOf(fn.Name).(*types.Signature); ok && lastResultIsError(signature) {
			return unknownStatusAccepted(fn.Body)
		}
		return nil
	}
	return r
}

// acknowledgedFailures returns the error checks of a handler that only log
// and are followed by a 2xx answer.
func acknowledgedFailures(info *types.Info, body *ast.BlockStmt, writer types.Object) []funcFinding {
	var findings []funcFinding
	for i, stmt := range body.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok || ifStmt.Else != nil || errNotNilIdent(info, ifStmt.Cond) == nil || !onlyLogs(ifStmt.Body) {
			continue
		}
		for _, later := range body.List[i+1:] {
			if status, ok := writtenStatus(info, later, writer); ok {
				if status >= 200 && status < 300 {
					findings = append(findings, funcFinding{node: ifStmt, message: "The webhook's processing error is only logged and the handler answers success — the sender takes the update as delivered and never sends it again"})
				}
				break
			}
		}
	}
	return findings
}

// unknownStatusAccepted returns the branches of a webhook processing function
// that log an empty mapped value (`if status == "" { log; return nil }`) or a
// switch default, and return nil.
func unknownStatusAccepted(body *ast.BlockStmt) []funcFinding {
	var findings []funcFinding
	report := func(node ast.Node, stmts []ast.Stmt) {
		if len(stmts) < 2 {
			return
		}
		ret, ok := stmts[len(stmts)-1].(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 || !isNilIdent(ret.Results[len(ret.Results)-1]) {
			return
		}
		for _, stmt := range stmts[:len(stmts)-1] {
			if !isLoggerStmt(stmt) {
				return
			}
		}
		findings = append(findings, funcFinding{node: node, message: "The webhook processing logs a status it does not recognize and returns nil — the sender is told the update was applied and never delivers it again"})
	}
	inspectFuncBody(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			if node.Else == nil && comparesToEmptyLiteral(node.Cond) {
				report(node, node.Body.List)
			}
		case *ast.SwitchStmt:
			for _, clause := range node.Body.List {
				if cc, ok := clause.(*ast.CaseClause); ok && cc.List == nil {
					report(cc, cc.Body)
				}
			}
		}
		return true
	})
	return findings
}

// comparesToEmptyLiteral reports `x == ""`.
func comparesToEmptyLiteral(cond ast.Expr) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	for _, side := range []ast.Expr{bin.X, bin.Y} {
		if lit, ok := ast.Unparen(side).(*ast.BasicLit); ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``") {
			return true
		}
	}
	return false
}

// NewWebhookEvidenceNotPersistedBefore4xxRule creates
// webhook-evidence-not-persisted-before-4xx: inside one failure branch of a
// webhook handler, a nested branch answers 4xx and returns before the call
// that stores the raw body. A sender does not retry a 4xx, and the update it
// carried is gone without a trace.
func NewWebhookEvidenceNotPersistedBefore4xxRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"webhook-evidence-not-persisted-before-4xx",
			"patterns",
			"Detects a webhook failure branch that stores the raw body after a nested branch has answered 4xx and returned — the sender does not retry a 4xx and that update is lost without a trace",
			core.SeverityMedium,
		),
		suggestion: "Store the raw body before any branch of the failure answers and returns",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		info := scope.info
		writer := responseWriterParam(info, fn)
		if writer == nil || !isWebhookFunc(fn) {
			return nil
		}
		raw := rawBodies(info, fn.Body)
		if len(raw) == 0 {
			return nil
		}
		var findings []funcFinding
		inspectFuncBody(fn.Body, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			early := false
			for _, stmt := range block.List {
				if ifStmt, ok := stmt.(*ast.IfStmt); ok && answersClientErrorAndReturns(info, ifStmt.Body, writer) {
					early = true
					continue
				}
				if call := storesRawBody(info, stmt, raw); early && call != nil {
					findings = append(findings, funcFinding{node: call, message: "The raw webhook body is stored only after a branch above has answered 4xx and returned — the sender does not retry a 4xx, and that update is lost without a trace"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// rawBodies returns the variables a body reads a request body into with
// io.ReadAll.
func rawBodies(info *types.Info, body *ast.BlockStmt) []types.Object {
	var raw []types.Object
	inspectFuncBody(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn := staticFunc(info, call); fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "io" || fn.Name() != "ReadAll" {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok && info.ObjectOf(ident) != nil {
			raw = append(raw, info.ObjectOf(ident))
		}
		return true
	})
	return raw
}

func answersClientErrorAndReturns(info *types.Info, body *ast.BlockStmt, writer types.Object) bool {
	if len(body.List) < 2 {
		return false
	}
	if _, ok := body.List[len(body.List)-1].(*ast.ReturnStmt); !ok {
		return false
	}
	for _, stmt := range body.List {
		if status, ok := writtenStatus(info, stmt, writer); ok && status >= 400 && status < 500 {
			return true
		}
	}
	return false
}

// storesRawBody returns a statement's call that passes a raw body on.
func storesRawBody(info *types.Info, stmt ast.Stmt, raw []types.Object) *ast.CallExpr {
	exprStmt, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil
	}
	call, ok := ast.Unparen(exprStmt.X).(*ast.CallExpr)
	if !ok || helpers.IsLoggerCall(call) {
		return nil
	}
	for _, arg := range call.Args {
		if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && containsObject(raw, info.Uses[ident]) {
			return call
		}
	}
	return nil
}

// tokenWords and expiryWords name the fields of a cached credential.
var (
	tokenWords  = wordSet("token")
	expiryWords = wordSet("exp", "expiry", "expires", "expiration", "expire", "until", "deadline")
)

// tokenCache is a type that caches a token with its expiry.
type tokenCache struct {
	named        *types.Named
	token, until *types.Var
}

// NewCachedTokenNotInvalidatedRule creates
// cached-token-not-invalidated-on-auth-failure: a type that caches a token
// with its expiry and has no way, other than its own getter, to drop it,
// while a caller of the getter reads the response status. When the server
// revokes the token early, every call fails with 401/403 until the local
// clock runs out.
func NewCachedTokenNotInvalidatedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"cached-token-not-invalidated-on-auth-failure",
			"patterns",
			"Detects a token cached with its expiry that callers cannot drop when the server answers 401/403 — a token revoked early fails every call until the local clock runs out",
			core.SeverityMedium,
		),
		suggestion: "Give the cache a method that drops the token, and call it and retry once when the server answers 401 or 403",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		caches := tokenCaches(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			if len(caches) == 0 || !readsResponseStatus(scope.info, fn.Body) {
				return nil
			}
			var findings []funcFinding
			inspectFuncBody(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if ok && gets(scope.info, call, caches) {
					findings = append(findings, funcFinding{node: call, message: "The token comes from a cache with an expiry that nothing can drop — when the server revokes it early, every call fails with 401/403 until the local clock runs out"})
				}
				return true
			})
			return findings
		}
	}
	return r
}

// tokenCaches returns the types with a token getter (Token() (string, error)),
// a token field and an expiry field, where no method but the getter clears
// either field.
func tokenCaches(decls map[*types.Func]typedFuncDecl) []tokenCache {
	var caches []tokenCache
	for fn := range decls {
		named := getterReceiver(fn)
		if named == nil {
			continue
		}
		cache, ok := cachedFields(named)
		if !ok || clearedOutsideGetter(decls, cache) {
			continue
		}
		caches = append(caches, cache)
	}
	slices.SortFunc(caches, func(a, b tokenCache) int { return cmp.Compare(a.named.Obj().Pos(), b.named.Obj().Pos()) })
	return caches
}

// getterReceiver returns the receiver type of a method named Token that
// returns (string, error).
func getterReceiver(fn *types.Func) *types.Named {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || fn.Name() != "Token" || sig.Results().Len() != 2 {
		return nil
	}
	if !types.Identical(sig.Results().At(0).Type(), types.Typ[types.String]) || !isErrorType(sig.Results().At(1).Type()) {
		return nil
	}
	recv := sig.Recv().Type()
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, _ := recv.(*types.Named)
	return named
}

func cachedFields(named *types.Named) (tokenCache, bool) {
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return tokenCache{}, false
	}
	cache := tokenCache{named: named}
	for field := range st.Fields() {
		switch {
		case hasTokenIn(field.Name(), tokenWords) && types.Identical(field.Type(), types.Typ[types.String]):
			cache.token = field
		case hasTokenIn(field.Name(), expiryWords) && isNamedType(field.Type(), "time", "Time"):
			cache.until = field
		}
	}
	return cache, cache.token != nil && cache.until != nil
}

// clearedOutsideGetter reports a method of the cache, other than its getter,
// that sets the token to "" or the expiry to the zero time.
func clearedOutsideGetter(decls map[*types.Func]typedFuncDecl, cache tokenCache) bool {
	for fn, decl := range decls {
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() == nil || fn.Name() == "Token" {
			continue
		}
		recv := sig.Recv().Type()
		if ptr, ok := recv.(*types.Pointer); ok {
			recv = ptr.Elem()
		}
		if recv != cache.named || decl.decl.Body == nil {
			continue
		}
		if clearsField(decl.info, decl.decl.Body, cache) {
			return true
		}
	}
	return false
}

func clearsField(info *types.Info, body *ast.BlockStmt, cache tokenCache) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return !found
		}
		for i, lhs := range assign.Lhs {
			sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
			if !ok {
				continue
			}
			field := info.Uses[sel.Sel]
			if (field == cache.token || field == cache.until) && isZeroValueExpr(assign.Rhs[i]) {
				found = true
			}
		}
		return !found
	})
	return found
}

// gets reports a call of a cache's token getter, directly or through an
// interface the cache implements.
func gets(info *types.Info, call *ast.CallExpr, caches []tokenCache) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Token" {
		return false
	}
	method, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	recv := sig.Recv().Type()
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	for _, cache := range caches {
		if recv == cache.named {
			return true
		}
		if iface, ok := recv.Underlying().(*types.Interface); ok && types.Implements(types.NewPointer(cache.named), iface) {
			return true
		}
	}
	return false
}

// readsResponseStatus reports a body reading StatusCode of an *http.Response.
func readsResponseStatus(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	inspectFuncBody(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "StatusCode" {
			t := info.TypeOf(sel.X)
			if ptr, isPtr := t.(*types.Pointer); isPtr {
				t = ptr.Elem()
			}
			if isNamedType(t, "net/http", "Response") {
				found = true
			}
		}
		return !found
	})
	return found
}
