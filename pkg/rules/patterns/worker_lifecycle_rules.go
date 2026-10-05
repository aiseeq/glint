package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewStatefulClientConstructedTwiceRule())
	rules.Register(NewDroppedEnqueueReliesOnStartupOnlyRescanRule())
	rules.Register(NewPostSideEffectWriteUsesRequestContextRule())
	rules.Register(NewWorkersCancelledBeforeHTTPDrainRule())
	rules.Register(NewGlobalRequestTimeoutCutsUploadHandlerRule())
	rules.Register(NewExpiryIssuedNeverEnforcedRule())
}

// NewStatefulClientConstructedTwiceRule creates stateful-client-constructed-twice:
// a constructor of a type that keeps state under a lock (a cache map, a
// token) called twice with the same arguments in one function builds two
// instances, each warming its own cache - one part of the program never sees
// what the other learned:
//
//	client = rates.NewClient(cfg.Account, cfg.Key)    // for the admin
//	...
//	client := rates.NewClient(cfg.Account, cfg.Key)   // for the refresher
func NewStatefulClientConstructedTwiceRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"stateful-client-constructed-twice",
			"patterns",
			"Detects a constructor of a type holding a lock or a cache called twice with the same arguments in one function — two instances keep two caches, and one never sees what the other learned",
			core.SeverityMedium,
		),
		suggestion: "Build the instance once and pass it to both users",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		type site struct {
			call *ast.CallExpr
			path []ast.Node
		}
		first := make(map[string]site)
		var findings []funcFinding
		var stack []ast.Node
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := staticFunc(scope.info, call)
			if callee == nil || !helpers.HasLeadingWord(callee.Name(), "New") || !buildsStatefulValue(callee) {
				return true
			}
			key := callee.FullName() + "(" + argsText(call) + ")"
			here := site{call: call, path: slices.Clone(stack)}
			prev, seen := first[key]
			if !seen {
				first[key] = here
				return true
			}
			if !exclusiveBranches(prev.path, here.path) {
				findings = append(findings, funcFinding{node: call, message: callee.Name() + " is called again with the same arguments in this function; the type keeps state under a lock, so the two instances keep two caches — build it once and share it"})
			}
			return true
		})
		return findings
	}
	return r
}

// sharedStateWords name a type whose state is meant to be shared by every
// user: a client of a remote service and its cache. A limiter or a counter
// is per user on purpose.
var sharedStateWords = []string{"client", "cache", "provider", "gateway", "api", "fetcher", "source"}

// buildsStatefulValue reports a function whose first result is a pointer to
// a client-like struct with a mutex and a map field: an instance that keeps
// state its users should share.
func buildsStatefulValue(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Results().Len() == 0 {
		return false
	}
	ptr, ok := types.Unalias(sig.Results().At(0).Type()).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || !slices.ContainsFunc(helpers.IdentifierWords(named.Obj().Name()), func(w string) bool { return slices.Contains(sharedStateWords, w) }) {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	locked, cached := false, false
	for field := range st.Fields() {
		if isNamedType(field.Type(), "sync", "Mutex") || isNamedType(field.Type(), "sync", "RWMutex") {
			locked = true
		}
		if _, ok := field.Type().Underlying().(*types.Map); ok {
			cached = true
		}
	}
	return locked && cached
}

// argsText returns the source spelling of a call's arguments.
func argsText(call *ast.CallExpr) string {
	parts := make([]string, 0, len(call.Args))
	for _, arg := range call.Args {
		parts = append(parts, types.ExprString(arg))
	}
	return strings.Join(parts, ", ")
}

// exclusiveBranches reports two nodes, given by their ancestor paths, that
// sit in different branches of one if or switch: never both run.
func exclusiveBranches(a, b []ast.Node) bool {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	if i == 0 || i >= len(a) || i >= len(b) {
		return false
	}
	switch fork := a[i-1].(type) {
	case *ast.IfStmt:
		return (a[i] == fork.Body && b[i] == fork.Else) || (a[i] == fork.Else && b[i] == fork.Body)
	case *ast.BlockStmt:
		_, left := a[i].(*ast.CaseClause)
		_, right := b[i].(*ast.CaseClause)
		return left && right
	}
	return false
}

// NewDroppedEnqueueReliesOnStartupOnlyRescanRule creates
// dropped-enqueue-relies-on-startup-only-rescan: an enqueue that drops the
// item when the queue is full (select with default) counts on a rescan of
// stored work, but the worker reading the queue rescans only once, before its
// loop - the dropped item waits for a restart:
//
//	select {
//	case w.queue <- id:
//	default:
//		w.logger.Warn("queue full; deferred to the resume scan")
//	}
//	...
//	for { select { case id := <-w.queue: ... } }   // no ticker case
func NewDroppedEnqueueReliesOnStartupOnlyRescanRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"dropped-enqueue-relies-on-startup-only-rescan",
			"patterns",
			"Detects an enqueue that drops the item when the queue is full while the worker reading the queue never rescans stored work on a timer — the dropped item waits for a restart",
			core.SeverityMedium,
		),
		suggestion: "Rescan the stored work on a ticker in the worker's loop, or block (with a timeout) instead of dropping",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectStmt)
			if !ok {
				return true
			}
			queue, drop := droppingSend(scope.info, sel)
			if queue == nil {
				return true
			}
			if consumer := queueConsumer(scope, queue); consumer != "" {
				findings = append(findings, funcFinding{node: drop, message: "The item is dropped when the queue " + queue.Name() + " is full, but " + consumer + ", which reads the queue, never rescans stored work on a timer — the dropped item waits for a restart"})
			}
			return true
		})
		return findings
	}
	return r
}

// droppingSend returns the queue field a select sends an item to, with a
// default clause that only logs, and that clause; nil for none. A send of an
// empty struct or a bool is a wake-up signal that coalesces, not an item.
func droppingSend(info *types.Info, sel *ast.SelectStmt) (*types.Var, *ast.CommClause) {
	var queue *types.Var
	var drop *ast.CommClause
	for _, stmt := range sel.Body.List {
		clause, ok := stmt.(*ast.CommClause)
		if !ok {
			continue
		}
		if clause.Comm == nil {
			drop = clause
			continue
		}
		send, ok := clause.Comm.(*ast.SendStmt)
		if !ok {
			continue
		}
		field, ok := ast.Unparen(send.Chan).(*ast.SelectorExpr)
		if !ok {
			continue
		}
		v, ok := info.Uses[field.Sel].(*types.Var)
		if !ok || !v.IsField() || signalValue(info.TypeOf(send.Value)) {
			continue
		}
		queue = v
	}
	if queue == nil || drop == nil || (len(drop.Body) > 0 && !onlyLogs(&ast.BlockStmt{List: drop.Body})) {
		return nil, nil
	}
	return queue, drop
}

// signalValue reports a value that carries no item: struct{} or bool.
func signalValue(t types.Type) bool {
	if t == nil {
		return true
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		return u.NumFields() == 0
	case *types.Basic:
		return u.Kind() == types.Bool
	}
	return false
}

// queueConsumer returns the name of a loaded function that receives from
// the queue field in a loop with no timer case; "" when none does, or when a
// reader rescans on a timer.
func queueConsumer(scope funcScope, queue *types.Var) string {
	consumer := ""
	for _, decl := range scope.decls {
		receives, timed := false, false
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectStmt:
				reads, ticks := selectReads(decl.info, node, queue)
				receives = receives || reads
				timed = timed || (reads && ticks)
			case *ast.RangeStmt:
				receives = receives || isQueueField(decl.info, node.X, queue)
			}
			return true
		})
		if timed {
			return ""
		}
		if receives && (consumer == "" || decl.decl.Name.Name < consumer) {
			consumer = decl.decl.Name.Name
		}
	}
	return consumer
}

// selectReads reports whether a select receives from the queue field, and
// whether it also has a timer case (a ticker, time.After).
func selectReads(info *types.Info, sel *ast.SelectStmt, queue *types.Var) (reads, ticks bool) {
	for _, stmt := range sel.Body.List {
		clause, ok := stmt.(*ast.CommClause)
		if !ok || clause.Comm == nil {
			continue
		}
		if tickReceive(clause.Comm) || timerReceive(clause.Comm) {
			ticks = true
		}
		ast.Inspect(clause.Comm, func(n ast.Node) bool {
			if unary, ok := n.(*ast.UnaryExpr); ok && unary.Op == token.ARROW && isQueueField(info, unary.X, queue) {
				reads = true
			}
			return true
		})
	}
	return reads, ticks
}

// timerReceive reports a select case receiving from time.After or a timer's C.
func timerReceive(comm ast.Stmt) bool {
	found := false
	ast.Inspect(comm, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isSelectorCall(call, "time", "After") {
			found = true
		}
		return !found
	})
	return found
}

// isQueueField reports an expression that is the queue field.
func isQueueField(info *types.Info, expr ast.Expr, queue *types.Var) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	return ok && info.Uses[sel.Sel] == queue
}

// sendVerbs lead the names of calls that send a command out: once it went,
// it cannot be taken back.
var sendVerbs = []string{"Send", "Deliver", "Transfer", "Charge", "Submit", "Payout", "Refund", "Capture", "Dispatch", "Publish"}

// recordVerbs lead the names of calls that record an outcome besides the
// write verbs: finalize a lease, complete a job, acknowledge a message.
var recordVerbs = []string{"Finalize", "Complete", "Ack", "Acknowledge", "Settle"}

// NewPostSideEffectWriteUsesRequestContextRule creates
// post-side-effect-write-uses-request-context: the write that records the
// success of an outbound command made with the caller's cancellable context
// fails when the caller goes away right after the send - the command went
// out, its record did not, and the next attempt sends it again:
//
//	resp, err := s.gateway.SendTransfer(req)
//	if err != nil { ... }
//	if err := s.repo.UpdateSent(ctx, id, resp.Ref); err != nil {   // ctx of the request
func NewPostSideEffectWriteUsesRequestContextRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"post-side-effect-write-uses-request-context",
			"patterns",
			"Detects the write recording an outbound command's success made with the caller's cancellable context — when the caller goes away after the send the record is lost and the command is sent again",
			core.SeverityMedium,
		),
		suggestion: "Record the outcome on a detached context with its own timeout: context.WithTimeout(context.WithoutCancel(ctx), d)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		cancellable := cancellableContexts(scope.info, fn)
		if len(cancellable) == 0 || mentionsNotice(fn.Name.Name) || mentionsNotice(receiverTypeName(fn.Recv)) || mentionsNotice(packagePath(scope.info, fn)) {
			return nil
		}
		var findings []funcFinding
		reported := make(map[*ast.CallExpr]bool)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, stmt := range block.List {
				send := outboundSend(scope.info, stmt)
				if send == "" {
					continue
				}
				var after []ast.Stmt
				if check, ok := stmt.(*ast.IfStmt); ok && check.Else != nil {
					after = append(after, check.Else)
				}
				after = append(after, block.List[i+1:]...)
				if write := successRecord(scope.info, after, cancellable); write != nil && !reported[write] {
					reported[write] = true
					findings = append(findings, funcFinding{node: write, message: callName(write) + " records the outcome of " + send + " with the caller's cancellable context — when the caller goes away after the send the record is lost and the command is sent again"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// cancellableDerivations are the context functions whose result is
// cancelled with its parent.
var cancellableDerivations = []string{"WithTimeout", "WithCancel", "WithDeadline"}

// cancellableContexts returns the context parameters of fn and the contexts
// derived from them by WithTimeout, WithCancel or WithDeadline in its body.
func cancellableContexts(info *types.Info, fn *ast.FuncDecl) map[types.Object]bool {
	ctxs := make(map[types.Object]bool)
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if obj := info.ObjectOf(name); obj != nil && isNamedType(obj.Type(), "context", "Context") {
				ctxs[obj] = true
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || len(call.Args) == 0 || !slices.ContainsFunc(cancellableDerivations, func(name string) bool { return isSelectorCall(call, "context", name) }) {
			return true
		}
		parent, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
		if !ok || !ctxs[info.ObjectOf(parent)] {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
			if obj := info.ObjectOf(ident); obj != nil {
				ctxs[obj] = true
			}
		}
		return true
	})
	return ctxs
}

// outboundSend returns the name of the send call a statement makes outside a
// func literal: in its init, its assignment or itself; "" for none.
func outboundSend(info *types.Info, stmt ast.Stmt) string {
	var scan ast.Node = stmt
	if check, ok := stmt.(*ast.IfStmt); ok {
		if check.Init == nil {
			return ""
		}
		scan = check.Init
	}
	found := ""
	ast.Inspect(scan, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit, *ast.BlockStmt:
			return false
		case *ast.CallExpr:
			if commandSent(info, node) {
				found = callName(node)
			}
		}
		return found == ""
	})
	return found
}

// noticeWords name a notification: sending one twice after a restart is a
// duplicate message, not a repeated command.
var noticeWords = []string{"alert", "notif", "email", "mail", "message", "telegram", "slack", "sms"}

// commandSent reports a method call that sends a command out: led by a send
// verb, failing with an error, not a call of a storage driver and not a
// notification.
func commandSent(info *types.Info, call *ast.CallExpr) bool {
	name := callName(call)
	if !slices.ContainsFunc(sendVerbs, func(verb string) bool { return helpers.HasLeadingWord(name, verb) }) {
		return false
	}
	fn := staticFunc(info, call)
	if fn == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || sig.Results().Len() == 0 || !isErrorType(sig.Results().At(sig.Results().Len()-1).Type()) {
		return false
	}
	if fn.Pkg() != nil && storageDriver(fn.Pkg().Path()) {
		return false
	}
	return !mentionsNotice(name) && !mentionsNotice(types.TypeString(sig.Recv().Type(), nil))
}

// mentionsNotice reports a name that speaks of a notification.
func mentionsNotice(name string) bool {
	lower := strings.ToLower(name)
	return slices.ContainsFunc(noticeWords, func(w string) bool { return strings.Contains(lower, w) })
}

// successRecord returns the first write call in stmts handed one of the
// cancellable contexts, outside the bodies of error branches.
func successRecord(info *types.Info, stmts []ast.Stmt, cancellable map[types.Object]bool) *ast.CallExpr {
	var found *ast.CallExpr
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			if found != nil {
				return false
			}
			switch node := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.IfStmt:
				if isErrNotNil(node.Cond) {
					if node.Init != nil {
						ast.Inspect(node.Init, func(m ast.Node) bool {
							if call, ok := m.(*ast.CallExpr); ok && found == nil && recordsOn(info, call, cancellable) {
								found = call
							}
							return found == nil
						})
					}
					if node.Else != nil {
						if write := successRecord(info, []ast.Stmt{node.Else}, cancellable); write != nil {
							found = write
						}
					}
					return false
				}
			case *ast.CallExpr:
				if recordsOn(info, node, cancellable) {
					found = node
				}
			}
			return found == nil
		})
		if found != nil {
			return found
		}
	}
	return nil
}

// recordsOn reports a write call handed one of the cancellable contexts.
func recordsOn(info *types.Info, call *ast.CallExpr, cancellable map[types.Object]bool) bool {
	name := callName(call)
	if !helpers.IsWriteName(name) && !slices.ContainsFunc(recordVerbs, func(verb string) bool { return helpers.HasLeadingWord(name, verb) }) {
		return false
	}
	for _, arg := range call.Args {
		if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && cancellable[info.ObjectOf(ident)] {
			return true
		}
	}
	return false
}

// NewWorkersCancelledBeforeHTTPDrainRule creates workers-cancelled-before-http-drain:
// cancelling the context of the background workers before the HTTP server
// drains takes the workers away from the requests still being served:
//
//	workerCancel()
//	return shutdownHTTPServer(server)    // server.Shutdown drains requests
func NewWorkersCancelledBeforeHTTPDrainRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"workers-cancelled-before-http-drain",
			"patterns",
			"Detects the background workers' context cancelled before the HTTP server drains — requests still being served lose the workers they depend on",
			core.SeverityMedium,
		),
		suggestion: "Shut the HTTP server down first (Shutdown waits for in-flight requests), then cancel the workers",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		stmts := fn.Body.List
		for i, stmt := range stmts {
			cancel := workerCancelOf(scope.info, stmts[:i], stmt)
			if cancel == nil {
				continue
			}
			for _, later := range stmts[i+1:] {
				if reachesServerShutdown(scope, later, 2) {
					findings = append(findings, funcFinding{node: stmt, message: cancel.Name() + " cancels the workers' context before the HTTP server drains — requests still being served lose the workers they depend on"})
					break
				}
			}
		}
		return findings
	}
	return r
}

// workerCancelOf returns the cancel function stmt calls (not deferred) when
// an earlier statement made it with context.WithCancel and handed its
// context to a call.
func workerCancelOf(info *types.Info, before []ast.Stmt, stmt ast.Stmt) types.Object {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return nil
	}
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return nil
	}
	cancel := info.ObjectOf(ident)
	for _, prev := range before {
		assign, ok := prev.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
			continue
		}
		made, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !isSelectorCall(made, "context", "WithCancel") {
			continue
		}
		ctxIdent, ok1 := assign.Lhs[0].(*ast.Ident)
		cancelIdent, ok2 := assign.Lhs[1].(*ast.Ident)
		if !ok1 || !ok2 || info.ObjectOf(cancelIdent) != cancel {
			continue
		}
		if handsContext(info, before, info.ObjectOf(ctxIdent)) {
			return cancel
		}
	}
	return nil
}

// handsContext reports a call in stmts handed ctx: the workers it starts.
func handsContext(info *types.Info, stmts []ast.Stmt, ctx types.Object) bool {
	found := false
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				for _, arg := range call.Args {
					if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && info.ObjectOf(ident) == ctx {
						found = true
					}
				}
			}
			return !found
		})
	}
	return found
}

// reachesServerShutdown reports a node that calls (*http.Server).Shutdown,
// directly or through loaded functions within depth calls.
func reachesServerShutdown(scope funcScope, node ast.Node, depth int) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if fn := staticFunc(scope.info, call); fn != nil && fn.Name() == "Shutdown" {
			if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil && isPointerToNamedType(sig.Recv().Type(), "net/http", "Server") {
				found = true
				return false
			}
		}
		if decl, ok := scope.callee(call); ok && depth > 1 {
			inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
			found = reachesServerShutdown(inner, decl.decl.Body, depth-1)
		}
		return !found
	})
	return found
}

// multipartReads are the *http.Request methods that read an uploaded file.
var multipartReads = []string{"ParseMultipartForm", "FormFile", "MultipartReader"}

// NewGlobalRequestTimeoutCutsUploadHandlerRule creates
// global-request-timeout-cuts-upload-handler: a router-wide request timeout
// sized for pages also covers a handler that receives and parses an uploaded
// file; a large file takes longer, and the import dies halfway with a
// deadline error:
//
//	r.Use(middleware.Timeout(30 * time.Second))
//	...
//	func (a *Admin) handleImport(w http.ResponseWriter, r *http.Request) {
//		reader, err := r.MultipartReader()     // no deadline of its own
func NewGlobalRequestTimeoutCutsUploadHandlerRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"global-request-timeout-cuts-upload-handler",
			"patterns",
			"Detects an upload handler reading a multipart file under a router-wide request timeout without a deadline of its own — a large file is cut halfway with a deadline error",
			core.SeverityMedium,
		),
		suggestion: "Give the upload handler its own deadline: r = r.WithContext(context.WithTimeout(context.WithoutCancel(r.Context()), d)), and extend the connection deadlines with http.ResponseController",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if !hasRouterTimeout(decls) {
			return func(funcScope, *ast.FuncDecl) []funcFinding { return nil }
		}
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			request := requestParam(scope.info, fn)
			if request == nil || fn.Body == nil || setsOwnDeadline(scope.info, fn.Body, request) {
				return nil
			}
			if !readsMultipart(scope, fn.Body, request, 2) {
				return nil
			}
			return []funcFinding{{node: fn.Name, message: fn.Name.Name + " reads an uploaded file under the router-wide request timeout with no deadline of its own — a large file is cut halfway with a deadline error"}}
		}
	}
	return r
}

// hasRouterTimeout reports a Use(...) of a middleware Timeout, or an
// http.TimeoutHandler, in the loaded bodies.
func hasRouterTimeout(decls map[*types.Func]typedFuncDecl) bool {
	for _, decl := range decls {
		found := false
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			fn := staticFunc(decl.info, call)
			if fn == nil || fn.Pkg() == nil {
				return true
			}
			path := fn.Pkg().Path()
			if fn.Name() == "TimeoutHandler" && path == "net/http" {
				found = true
			}
			if fn.Name() == "Use" {
				for _, arg := range call.Args {
					if inner, ok := ast.Unparen(arg).(*ast.CallExpr); ok {
						if mw := staticFunc(decl.info, inner); mw != nil && mw.Pkg() != nil && mw.Name() == "Timeout" && strings.HasSuffix(mw.Pkg().Path(), "middleware") {
							found = true
						}
					}
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// requestParam returns the *http.Request parameter of a handler
// (http.ResponseWriter, *http.Request); nil for another function.
func requestParam(info *types.Info, fn *ast.FuncDecl) types.Object {
	var writer bool
	var request types.Object
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			obj := info.ObjectOf(name)
			if obj == nil {
				continue
			}
			if isNamedType(obj.Type(), "net/http", "ResponseWriter") {
				writer = true
			}
			if isPointerToNamedType(obj.Type(), "net/http", "Request") {
				request = obj
			}
		}
	}
	if !writer {
		return nil
	}
	return request
}

// setsOwnDeadline reports a handler that replaces its request (r = ...) or
// detaches a context from it.
func setsOwnDeadline(info *types.Info, body *ast.BlockStmt, request types.Object) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && node.Tok == token.ASSIGN && info.ObjectOf(ident) == request {
					found = true
				}
			}
		case *ast.CallExpr:
			if isSelectorCall(node, "context", "WithoutCancel") {
				found = true
			}
		}
		return !found
	})
	return found
}

// readsMultipart reports a body that reads an uploaded file from the
// request, directly or in a loaded function handed the request within depth
// calls.
func readsMultipart(scope funcScope, body *ast.BlockStmt, request types.Object, depth int) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && slices.Contains(multipartReads, sel.Sel.Name) {
			if ident, ok := ast.Unparen(sel.X).(*ast.Ident); ok && scope.info.ObjectOf(ident) == request {
				found = true
				return false
			}
		}
		if depth <= 1 {
			return true
		}
		decl, ok := scope.callee(call)
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			ident, ok := ast.Unparen(arg).(*ast.Ident)
			if !ok || scope.info.ObjectOf(ident) != request {
				continue
			}
			if param := paramAt(decl, i); param != nil {
				inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
				found = found || readsMultipart(inner, decl.decl.Body, param, depth-1)
			}
		}
		return !found
	})
	return found
}

// paramAt returns the object of the i-th parameter of a declaration.
func paramAt(decl typedFuncDecl, i int) types.Object {
	n := 0
	for _, field := range decl.decl.Type.Params.List {
		for _, name := range field.Names {
			if n == i {
				return decl.info.ObjectOf(name)
			}
			n++
		}
	}
	return nil
}

// expiryFieldWords name a response field that tells the client until when a
// value holds.
var expiryFieldWords = [][]string{{"expires", "at"}, {"expire", "at"}, {"expiry"}, {"expiration"}, {"valid", "until"}, {"expires"}}

// NewExpiryIssuedNeverEnforcedRule creates expiry-issued-never-enforced: an
// expiry put into a response (expires_at = now + 15 minutes) whose duration
// is spelled only there - no code compares the entity's age with it, so the
// server accepts what it told the client had expired:
//
//	expiresAt := time.Now().Add(15 * time.Minute)
//	writeJSON(w, QuoteResponse{ExpiresAt: expiresAt.Format(time.RFC3339)})
func NewExpiryIssuedNeverEnforcedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"expiry-issued-never-enforced",
			"patterns",
			"Detects an expiry sent in a response whose duration is spelled only there — no code compares the entity's age with it, so what the client was told has expired is still accepted",
			core.SeverityMedium,
		),
		suggestion: "Name the duration once (a constant) and check it where the entity is used: refuse it when time.Since(created) exceeds the duration",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		uses := objectUses(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			if fn.Body == nil || requestParam(scope.info, fn) == nil {
				return nil
			}
			defs := singleDefinitions(scope.info, fn.Body)
			var findings []funcFinding
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !jsonTagged(scope.info.TypeOf(lit)) {
					return true
				}
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || !namesExpiry(key.Name) {
						continue
					}
					if add := clockAdd(scope.info, defs, kv.Value); add != nil && spelledOnce(scope.info, add.Args[0], uses) && !expiryHandedOn(scope.info, fn.Body, kv.Value) {
						findings = append(findings, funcFinding{node: add, message: "The expiry sent as " + key.Name + " is computed from a duration spelled only here — no code compares the entity's age with it, so what the client was told has expired is still accepted"})
					}
				}
				return true
			})
			return findings
		}
	}
	return r
}

// objectUses counts the uses of every object in the loaded packages.
func objectUses(decls map[*types.Func]typedFuncDecl) map[types.Object]int {
	seen := make(map[*types.Info]bool)
	uses := make(map[types.Object]int)
	for _, decl := range decls {
		if seen[decl.info] {
			continue
		}
		seen[decl.info] = true
		for _, obj := range decl.info.Uses {
			uses[obj]++
		}
	}
	return uses
}

// jsonTagged reports a struct type with a json tag on a field.
func jsonTagged(t types.Type) bool {
	if t == nil {
		return false
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := range st.NumFields() {
		if _, ok := reflect.StructTag(st.Tag(i)).Lookup("json"); ok {
			return true
		}
	}
	return false
}

// namesExpiry reports a field name such as ExpiresAt or ValidUntil.
func namesExpiry(name string) bool {
	words := helpers.IdentifierWords(name)
	for _, want := range expiryFieldWords {
		if slices.Equal(words, want) {
			return true
		}
	}
	return false
}

// clockAdd returns the time.Now().Add(d) call an expression is (through
// Format, UTC or a local variable's only definition); nil for none.
func clockAdd(info *types.Info, defs map[types.Object]ast.Expr, expr ast.Expr) *ast.CallExpr {
	for range 4 {
		switch e := ast.Unparen(expr).(type) {
		case *ast.Ident:
			def, ok := defs[info.ObjectOf(e)]
			if !ok {
				return nil
			}
			expr = def
		case *ast.CallExpr:
			sel, ok := ast.Unparen(e.Fun).(*ast.SelectorExpr)
			if !ok {
				return nil
			}
			if sel.Sel.Name == "Add" && len(e.Args) == 1 && fromClock(info, sel.X) {
				return e
			}
			if sel.Sel.Name != "Format" && sel.Sel.Name != "UTC" && sel.Sel.Name != "Unix" {
				return nil
			}
			expr = sel.X
		default:
			return nil
		}
	}
	return nil
}

// spelledOnce reports a duration whose every named part outside package
// time is used once in the project: a literal, or a constant nothing else
// reads.
func spelledOnce(info *types.Info, expr ast.Expr, uses map[types.Object]int) bool {
	once := true
	ast.Inspect(expr, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		obj := info.Uses[ident]
		if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() == "time" {
			return true
		}
		if _, isPkg := obj.(*types.PkgName); isPkg {
			return true
		}
		if uses[obj] > 1 {
			once = false
		}
		return once
	})
	return once
}

// packagePath returns the import path of the package fn is declared in.
func packagePath(info *types.Info, fn *ast.FuncDecl) string {
	if obj, ok := info.Defs[fn.Name].(*types.Func); ok && obj.Pkg() != nil {
		return obj.Pkg().Path()
	}
	return ""
}

// expiryHandedOn reports an expiry variable handed to a call other than a
// format or a log: stored with the entity, its check lives with the store.
func expiryHandedOn(info *types.Info, body *ast.BlockStmt, value ast.Expr) bool {
	var root *ast.Ident
	ast.Inspect(value, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && root == nil {
			if _, isVar := info.ObjectOf(ident).(*types.Var); isVar {
				root = ident
			}
		}
		return root == nil
	})
	if root == nil {
		return false
	}
	obj := info.ObjectOf(root)
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if helpers.IsLoggerCall(call) {
			return false
		}
		for _, arg := range call.Args {
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && info.ObjectOf(ident) == obj {
				found = true
			}
		}
		return !found
	})
	return found
}

// storageDriver reports a package of a database or cache client: its Send
// is a round trip to our own storage. "net" of storagePackages stands for any
// networked client and is left out.
func storageDriver(path string) bool {
	return slices.ContainsFunc(storagePackages, func(root string) bool {
		return root != "net" && (path == root || strings.HasPrefix(path, root+"/"))
	})
}
