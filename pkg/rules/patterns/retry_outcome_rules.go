package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewRetryKeyMintedPerAttemptRule())
	rules.Register(NewStaleBatchRowActedWithoutStatusRecheckRule())
	rules.Register(NewIdempotencyKeyNotScopedToCallerRule())
	rules.Register(NewOutboundDeliveryRetriesPermanent4xxRule())
	rules.Register(NewValidationAfterCommittedInsertRule())
}

// referenceWords name a value that identifies an operation to the party that
// executes it: a transaction reference, an idempotency or dedup key.
var referenceWords = []string{"ref", "reference", "idempotency", "dedup", "dedupe"}

// namesReference reports an identifier spelled with a reference word:
// txnRef, PartnerReference, IdempotencyKey.
func namesReference(name string) bool {
	return slices.ContainsFunc(helpers.IdentifierWords(name), func(w string) bool { return slices.Contains(referenceWords, w) })
}

// NewRetryKeyMintedPerAttemptRule creates retry-key-minted-per-attempt: a
// reference or idempotency key minted from a random value (uuid.New, rand)
// for every item of a batch is new on every attempt - a batch run again
// after a crash or a retry sends the items already sent under new
// references, and the receiver executes them twice:
//
//	for _, row := range batch.Rows {
//		Mutate(row, uuid.New().String(), year)    // txnRef
//
// A reference derived from the batch and the item (batch id, row number)
// stays the same across attempts.
func NewRetryKeyMintedPerAttemptRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"retry-key-minted-per-attempt",
			"patterns",
			"Detects a reference or idempotency key minted from a random value for each item of a batch — a batch run again sends the items already sent under new references",
			core.SeverityHigh,
		),
		suggestion: "Derive the reference from what survives a retry: the persisted batch id and the item's index or its own key",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		perItem := calledPerItem(scope, fn, 2)
		var findings []funcFinding
		var stack []ast.Node
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok || !mintsRandom(scope.info, call) {
				return true
			}
			slot, target := referenceSlot(scope.info, stack)
			repeated := perItem || insideItemLoop(scope.info, stack) || takesItem(scope.info, target)
			if slot == "" || !repeated || statusGuardedBefore(fn.Body, call) {
				return true
			}
			findings = append(findings, funcFinding{node: call, message: "The reference " + slot + " is minted from a random value for each item — a batch run again sends the items already sent under new references, and the receiver executes them twice"})
			return true
		})
		return findings
	}
	return r
}

// mintsRandom reports a call that returns a new random value: uuid.New,
// uuid.NewString, a math/rand function.
func mintsRandom(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	switch fn.Pkg().Path() {
	case "github.com/google/uuid", "github.com/gofrs/uuid":
		return fn.Name() == "New" || fn.Name() == "NewString" || fn.Name() == "NewRandom" || fn.Name() == "NewV4" || fn.Name() == "NewV7"
	case "math/rand", "math/rand/v2":
		return true
	}
	return false
}

// referenceSlot returns the name of the reference a value built by the
// innermost node of stack goes to: the parameter of a call (with the call),
// the variable or the field it is assigned to; "" when it goes to none.
func referenceSlot(info *types.Info, stack []ast.Node) (string, *ast.CallExpr) {
	for i := len(stack) - 2; i >= 0; i-- {
		child := stack[i+1]
		switch node := stack[i].(type) {
		case *ast.CallExpr:
			if node.Fun == child || formatsValue(info, node) {
				continue
			}
			if name := paramNameAt(info, node, child); name != "" {
				if namesReference(name) {
					return name, node
				}
				return "", nil
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok && node.Value == child {
				if namesReference(key.Name) {
					return key.Name, nil
				}
				return "", nil
			}
		case *ast.AssignStmt:
			for j, rhs := range node.Rhs {
				if rhs != child || j >= len(node.Lhs) {
					continue
				}
				if name := assignedName(node.Lhs[j]); namesReference(name) {
					return name, nil
				}
			}
			return "", nil
		case ast.Stmt, *ast.FuncLit:
			return "", nil
		}
	}
	return "", nil
}

// takesItem reports a call also handed a batch item: Mutate(row, ref).
func takesItem(info *types.Info, call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	for _, arg := range call.Args {
		t := info.TypeOf(arg)
		if t == nil {
			continue
		}
		if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
			t = ptr.Elem()
		}
		if named, ok := types.Unalias(t).(*types.Named); ok && slices.ContainsFunc(helpers.IdentifierWords(named.Obj().Name()), func(w string) bool { return slices.Contains(itemWords, w) }) {
			return true
		}
	}
	return false
}

// statusGuardedBefore reports a body that, before node, leaves unless a
// status holds: the operation runs once per state, a repeat stops there.
func statusGuardedBefore(body *ast.BlockStmt, node ast.Node) bool {
	for _, stmt := range body.List {
		if stmt.End() > node.Pos() {
			return false
		}
		check, ok := stmt.(*ast.IfStmt)
		if !ok || !blockLeaves(check.Body) {
			continue
		}
		found := false
		ast.Inspect(check.Cond, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				words := helpers.IdentifierWords(sel.Sel.Name)
				if slices.Contains(words, "status") || slices.Contains(words, "state") {
					found = true
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

// formatsValue reports a call that only puts its arguments into text
// (fmt.Sprintf, strings.Join): the value goes on to where its result goes.
func formatsValue(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	switch fn.Pkg().Path() {
	case "fmt":
		return strings.HasPrefix(fn.Name(), "Sprint")
	case "strings":
		return fn.Name() == "Join" || fn.Name() == "ToUpper" || fn.Name() == "ToLower"
	}
	return false
}

// paramNameAt returns the name of the parameter of a static call that arg
// is passed to; "" for a call whose signature is unknown or a builtin.
func paramNameAt(info *types.Info, call *ast.CallExpr, arg ast.Node) string {
	fn := staticFunc(info, call)
	if fn == nil {
		return ""
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return ""
	}
	for i, a := range call.Args {
		if a != arg {
			continue
		}
		if i >= sig.Params().Len() {
			if sig.Variadic() && sig.Params().Len() > 0 {
				return sig.Params().At(sig.Params().Len() - 1).Name()
			}
			return ""
		}
		return sig.Params().At(i).Name()
	}
	return ""
}

// itemWords name the element of a batch: a row of an upload, an item of a
// stored job. A loop over them repeats work that a retry repeats too.
var itemWords = []string{"row", "rows", "item", "items", "record", "records", "line", "lines", "entry", "entries"}

// itemLoop reports a range over batch items: elements of a type named for a
// row, an item or a record.
func itemLoop(info *types.Info, loop *ast.RangeStmt) bool {
	t := info.TypeOf(loop.X)
	if t == nil {
		return false
	}
	var elem types.Type
	switch u := t.Underlying().(type) {
	case *types.Slice:
		elem = u.Elem()
	case *types.Array:
		elem = u.Elem()
	case *types.Map:
		elem = u.Elem()
	default:
		return false
	}
	if ptr, ok := types.Unalias(elem).(*types.Pointer); ok {
		elem = ptr.Elem()
	}
	named, ok := types.Unalias(elem).(*types.Named)
	return ok && slices.ContainsFunc(helpers.IdentifierWords(named.Obj().Name()), func(w string) bool { return slices.Contains(itemWords, w) })
}

// insideItemLoop reports a node path that runs through the body of a loop
// over batch items.
func insideItemLoop(info *types.Info, stack []ast.Node) bool {
	for i := len(stack) - 2; i >= 0; i-- {
		switch node := stack[i].(type) {
		case *ast.RangeStmt:
			if node.Body == stack[i+1] && itemLoop(info, node) {
				return true
			}
		case *ast.FuncLit:
			return false
		}
	}
	return false
}

// calledPerItem reports a function called from the body of a loop, directly
// or through callers within depth calls.
func calledPerItem(scope funcScope, fn *ast.FuncDecl, depth int) bool {
	obj, ok := scope.info.Defs[fn.Name].(*types.Func)
	return ok && calledInLoop(scope, obj, depth, map[*types.Func]bool{})
}

func calledInLoop(scope funcScope, fn *types.Func, depth int, seen map[*types.Func]bool) bool {
	if seen[fn] {
		return false
	}
	seen[fn] = true
	for _, site := range scope.callers[fn.Origin()] {
		if nodeInItemLoop(site.caller.info, site.caller.decl.Body, site.call) {
			return true
		}
		if depth > 1 {
			if caller, ok := site.caller.info.Defs[site.caller.decl.Name].(*types.Func); ok && calledInLoop(scope, caller, depth-1, seen) {
				return true
			}
		}
	}
	return false
}

// nodeInItemLoop reports a node inside the body of a loop over batch items
// of body.
func nodeInItemLoop(info *types.Info, body *ast.BlockStmt, node ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch l := n.(type) {
		case *ast.RangeStmt:
			if itemLoop(info, l) && l.Body.Pos() <= node.Pos() && node.End() <= l.Body.End() {
				found = true
			}
		case *ast.FuncLit:
			return false
		}
		return !found
	})
	return found
}

// selectionStatusWords name a list of rows picked by their status.
var selectionStatusWords = []string{"pending", "sent", "stuck", "timed", "expired", "processing", "confirmed", "waiting", "unfinished", "queued", "submitted", "approved", "overdue", "stale", "inflight"}

// stateChangeVerbs lead the names of calls that move an entity to another
// state.
var stateChangeVerbs = []string{"Cancel", "Expire", "Complete", "Fail", "Approve", "Reject", "Refund", "Resend", "Close", "Void", "Reverse", "Settle"}

// NewStaleBatchRowActedWithoutStatusRecheckRule creates
// stale-batch-row-acted-without-status-recheck: a job that picks rows by
// their status and then changes each one by its id alone acts on rows that
// moved on since the pick - a payout completed meanwhile is cancelled:
//
//	txs, _ := repo.GetTimedOutSent(ctx, age)
//	for _, tx := range txs {
//		canceller.CancelExpired(ctx, tx.ID)    // no "while still SENT"
//
// Passing the selected status (or the row's version) lets the change refuse
// a row that is no longer in it.
func NewStaleBatchRowActedWithoutStatusRecheckRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"stale-batch-row-acted-without-status-recheck",
			"patterns",
			"Detects a job that picks rows by status and changes each one by id alone — a row that moved on since the pick (completed, cancelled) is changed anyway",
			core.SeverityHigh,
		),
		suggestion: "Pass the status the row was picked in (or its version) and change it only while it still holds: UPDATE ... WHERE id = $1 AND status = $2",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok || loop.Value == nil {
				return true
			}
			rows, ok := ast.Unparen(loop.X).(*ast.Ident)
			if !ok || !pickedByStatus(scope.info, fn.Body, scope.info.ObjectOf(rows)) {
				return true
			}
			value, ok := loop.Value.(*ast.Ident)
			if !ok {
				return true
			}
			for _, call := range changesByIDOnly(scope, loop.Body, scope.info.ObjectOf(value), 2) {
				findings = append(findings, funcFinding{node: call, message: callName(call) + " changes a row picked by its status by id alone — a row that moved on since the pick is changed anyway; pass the picked status or the row's version"})
			}
			return true
		})
		return findings
	}
	return r
}

// pickedByStatus reports a variable assigned from a call whose name says it
// lists rows in a status (GetTimedOutSent, ListPending) without claiming
// them.
func pickedByStatus(info *types.Info, body *ast.BlockStmt, rows types.Object) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || found || len(assign.Rhs) != 1 {
			return !found
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || info.ObjectOf(ident) != rows {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		words := helpers.IdentifierWords(callName(call))
		has := func(set []string) bool {
			return slices.ContainsFunc(words, func(w string) bool { return slices.Contains(set, w) })
		}
		claims := slices.ContainsFunc(words, func(w string) bool { return claimWords[w] })
		found = has(selectionStatusWords) && !claims
		return !found
	})
	return found
}

// changesByIDOnly returns the state changes in body handed the id of row and
// nothing that pins its state; a loaded function handed the whole row is
// followed within depth calls.
func changesByIDOnly(scope funcScope, body *ast.BlockStmt, row types.Object, depth int) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callName(call)
		if slices.ContainsFunc(stateChangeVerbs, func(verb string) bool { return helpers.HasLeadingWord(name, verb) }) {
			if passesRowID(scope.info, call, row) && !pinsRowState(scope.info, call, row) {
				calls = append(calls, call)
			}
			return true
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
			if !ok || scope.info.ObjectOf(ident) != row {
				continue
			}
			if param := paramAt(decl, i); param != nil {
				inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
				calls = append(calls, changesByIDOnly(inner, decl.decl.Body, param, depth-1)...)
			}
		}
		return true
	})
	return calls
}

// passesRowID reports a call handed row.ID (a field of the row whose name
// ends in ID).
func passesRowID(info *types.Info, call *ast.CallExpr, row types.Object) bool {
	for _, arg := range call.Args {
		sel, ok := ast.Unparen(arg).(*ast.SelectorExpr)
		if !ok {
			continue
		}
		base, ok := ast.Unparen(sel.X).(*ast.Ident)
		if !ok || info.ObjectOf(base) != row {
			continue
		}
		words := helpers.IdentifierWords(sel.Sel.Name)
		if len(words) > 0 && words[len(words)-1] == "id" {
			return true
		}
	}
	return false
}

// pinsRowState reports a call also handed what pins the row's state: the
// row itself, its status or version, or a status value.
func pinsRowState(info *types.Info, call *ast.CallExpr, row types.Object) bool {
	for _, arg := range call.Args {
		arg = ast.Unparen(arg)
		if ident, ok := arg.(*ast.Ident); ok && info.ObjectOf(ident) == row {
			return true
		}
		if sel, ok := arg.(*ast.SelectorExpr); ok {
			words := helpers.IdentifierWords(sel.Sel.Name)
			if slices.Contains(words, "status") || slices.Contains(words, "version") || slices.Contains(words, "state") {
				return true
			}
		}
		if named, ok := types.Unalias(info.TypeOf(arg)).(*types.Named); ok {
			words := helpers.IdentifierWords(named.Obj().Name())
			if slices.Contains(words, "status") || slices.Contains(words, "state") {
				return true
			}
		}
	}
	return false
}

// principalNouns name who calls: the authenticated partner, user, account.
var principalNouns = []string{"partner", "user", "account", "tenant", "merchant", "client", "caller", "principal", "customer", "owner", "member"}

// NewIdempotencyKeyNotScopedToCallerRule creates
// idempotency-key-not-scoped-to-caller: an idempotency key built from the
// request alone where an authenticated caller is known - two callers sending
// the same payment id share one key, and the second gets the first one's
// result back (or blocks it):
//
//	partner, _ := authenticatedPartner(r.Context())
//	...
//	IdempotencyKey: fmt.Sprintf("ext:%d:%s", req.ProjectID, req.PaymentID),
func NewIdempotencyKeyNotScopedToCallerRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"idempotency-key-not-scoped-to-caller",
			"patterns",
			"Detects an idempotency key built from request values alone while an authenticated caller is known — two callers sending the same id share one key and get each other's result",
			core.SeverityHigh,
		),
		suggestion: "Put the caller's identity (partner, user, API client id) into the idempotency key or its scope",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		callerParam := principalParams(scope.info, fn)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			var name string
			var value ast.Expr
			switch node := n.(type) {
			case *ast.KeyValueExpr:
				if key, ok := node.Key.(*ast.Ident); ok {
					name, value = key.Name, node.Value
				}
			case *ast.AssignStmt:
				if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
					name, value = assignedName(node.Lhs[0]), node.Rhs[0]
				}
			}
			if value == nil || !namesIdempotencyKey(name) || !builtKey(value) {
				return true
			}
			if len(callerParam) > 0 {
				if !slices.ContainsFunc(callerParam, func(obj types.Object) bool { return mentionsObject(scope.info, value, obj) }) {
					findings = append(findings, funcFinding{node: value, message: "The idempotency key " + name + " leaves out the authenticated caller this function has — two callers sending the same id share one key"})
				}
				return true
			}
			local := principalLocals(scope.info, fn.Body)
			if len(local) > 0 && !slices.ContainsFunc(local, func(obj types.Object) bool { return mentionsObject(scope.info, value, obj) }) {
				findings = append(findings, funcFinding{node: value, message: "The idempotency key " + name + " leaves out the authenticated caller this function has — two callers sending the same id share one key"})
				return true
			}
			if len(local) == 0 && callerKnownUpstream(scope, fn, 2) {
				findings = append(findings, funcFinding{node: value, message: "The idempotency key " + name + " is built from request values alone while the handler calling this knows the authenticated caller — two callers sending the same id share one key"})
			}
			return true
		})
		return findings
	}
	return r
}

// namesIdempotencyKey reports IdempotencyKey, idemKey, dedupKey.
func namesIdempotencyKey(name string) bool {
	words := helpers.IdentifierWords(name)
	if len(words) < 2 || words[len(words)-1] != "key" {
		return false
	}
	return slices.ContainsFunc(words, func(w string) bool { return w == "idempotency" || w == "idem" || w == "dedup" || w == "dedupe" })
}

// builtKey reports a key put together here: a format call, a join, a
// concatenation.
func builtKey(value ast.Expr) bool {
	switch v := ast.Unparen(value).(type) {
	case *ast.CallExpr:
		name := callName(v)
		return name == "Sprintf" || name == "Join" || name == "Sprint"
	case *ast.BinaryExpr:
		return v.Op == token.ADD
	}
	return false
}

// principalParams returns the parameters of fn named for a caller
// (partnerID, user).
func principalParams(info *types.Info, fn *ast.FuncDecl) []types.Object {
	var params []types.Object
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if slices.ContainsFunc(helpers.IdentifierWords(name.Name), func(w string) bool { return slices.Contains(principalNouns, w) }) {
				params = append(params, info.ObjectOf(name))
			}
		}
	}
	return params
}

// principalLocals returns the variables of body assigned the authenticated
// caller: partner, err := authenticatedPartner(r.Context()).
func principalLocals(info *types.Info, body *ast.BlockStmt) []types.Object {
	var locals []types.Object
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !resolvesPrincipal(callName(call)) {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
			locals = append(locals, info.ObjectOf(ident))
		}
		return true
	})
	return locals
}

// resolvesPrincipal reports a call that names the authenticated caller:
// authenticatedPartner, currentUser, UserFromContext.
func resolvesPrincipal(name string) bool {
	words := helpers.IdentifierWords(name)
	if !slices.ContainsFunc(words, func(w string) bool { return slices.Contains(principalNouns, w) }) {
		return false
	}
	return slices.Contains(words, "authenticated") || slices.Contains(words, "current") || slices.Contains(words, "principal") ||
		(slices.Contains(words, "from") && (slices.Contains(words, "context") || slices.Contains(words, "ctx") || slices.Contains(words, "request")))
}

// callerKnownUpstream reports a function called, within depth calls, from a
// function that resolved the authenticated caller.
func callerKnownUpstream(scope funcScope, fn *ast.FuncDecl, depth int) bool {
	obj, ok := scope.info.Defs[fn.Name].(*types.Func)
	return ok && principalAbove(scope, obj, depth, map[*types.Func]bool{})
}

func principalAbove(scope funcScope, fn *types.Func, depth int, seen map[*types.Func]bool) bool {
	if seen[fn] {
		return false
	}
	seen[fn] = true
	for _, site := range scope.callers[fn.Origin()] {
		if len(principalLocals(site.caller.info, site.caller.decl.Body)) > 0 {
			return true
		}
		if depth > 1 {
			if caller, ok := site.caller.info.Defs[site.caller.decl.Name].(*types.Func); ok && principalAbove(scope, caller, depth-1, seen) {
				return true
			}
		}
	}
	return false
}

// NewOutboundDeliveryRetriesPermanent4xxRule creates
// outbound-delivery-retries-permanent-4xx: a delivery that answers every
// non-2xx status with one error, whose caller schedules a retry on it,
// retries a 404 or a 403 like a 503 - the recipient refused the request
// itself, the same bytes to the same URL get the same answer for the whole
// schedule:
//
//	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
//		return nil
//	}
//	return fmt.Errorf("http status %d", resp.StatusCode)    // caller: markRetry
func NewOutboundDeliveryRetriesPermanent4xxRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"outbound-delivery-retries-permanent-4xx",
			"patterns",
			"Detects a delivery that answers every non-2xx status with one error that its caller retries — a 4xx refusal is resent for the whole schedule like an outage",
			core.SeverityMedium,
		),
		suggestion: "Tell a 4xx refusal (other than 408, 425, 429) apart from 5xx and transport failures, and dead-letter it instead of scheduling a retry",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		ret := unclassifiedStatusFailure(scope.info, fn.Body)
		if ret == nil {
			return nil
		}
		obj, ok := scope.info.Defs[fn.Name].(*types.Func)
		if !ok || !retriedByCaller(scope, obj) {
			return nil
		}
		return []funcFinding{{node: ret, message: "Every non-2xx answer becomes one error that the caller retries — a 4xx refusal is resent for the whole schedule; tell 4xx apart from 5xx and transport failures"}}
	}
	return r
}

// unclassifiedStatusFailure returns the return of an error mentioning a
// response's StatusCode in a body that tests the status only for 2xx: no
// 4xx or 5xx bound, no switch, no classifier. nil for none.
func unclassifiedStatusFailure(info *types.Info, body *ast.BlockStmt) *ast.ReturnStmt {
	reads := false
	classified := false
	var failure *ast.ReturnStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.SelectorExpr:
			if responseStatus(info, node) {
				reads = true
			}
		case *ast.BinaryExpr:
			if responseStatus(info, ast.Unparen(node.X)) || responseStatus(info, ast.Unparen(node.Y)) {
				for _, side := range []ast.Expr{node.X, node.Y} {
					if v, ok := intConstant(info, side); ok && (v < 200 || v > 300) {
						classified = true
					}
				}
			}
		case *ast.SwitchStmt:
			if node.Tag != nil && responseStatus(info, ast.Unparen(node.Tag)) {
				classified = true
			}
		case *ast.CallExpr:
			if classifiesStatus(info, node) {
				classified = true
			}
		case *ast.ReturnStmt:
			if failure == nil && len(node.Results) > 0 && statusError(info, node.Results[len(node.Results)-1]) {
				failure = node
			}
		}
		return true
	})
	if !reads || classified {
		return nil
	}
	return failure
}

// responseStatus reports resp.StatusCode of an *http.Response.
func responseStatus(info *types.Info, expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "StatusCode" && isPointerToNamedType(info.TypeOf(sel.X), "net/http", "Response")
}

// statusClassWords name a classifier of a status: permanent, retryable.
var statusClassWords = []string{"permanent", "retryable", "retriable", "retry", "transient", "temporary", "classify", "rejection", "rejected", "client"}

// classifiesStatus reports a call handed a response's StatusCode whose name
// speaks of a class of failure: isPermanentRejection(resp.StatusCode).
func classifiesStatus(info *types.Info, call *ast.CallExpr) bool {
	words := helpers.IdentifierWords(callName(call))
	if !slices.ContainsFunc(words, func(w string) bool { return slices.Contains(statusClassWords, w) }) {
		return false
	}
	for _, arg := range call.Args {
		if responseStatus(info, ast.Unparen(arg)) {
			return true
		}
	}
	return false
}

// statusError reports fmt.Errorf or errors.New built with a response's
// StatusCode.
func statusError(info *types.Info, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	if !isSelectorCall(call, "fmt", "Errorf") && !isSelectorCall(call, "errors", "New") {
		return false
	}
	found := false
	ast.Inspect(call, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && responseStatus(info, e) {
			found = true
		}
		return !found
	})
	return found
}

// retriedByCaller reports a function whose caller, in the branch of its
// error, reaches a call that schedules a retry within two calls.
func retriedByCaller(scope funcScope, fn *types.Func) bool {
	for _, site := range scope.callers[fn.Origin()] {
		branch := errorBranchOf(site.caller.decl.Body, site.call)
		if branch == nil {
			continue
		}
		inner := funcScope{info: site.caller.info, decls: scope.decls, callers: scope.callers}
		if schedulesRetry(inner, branch, 2) {
			return true
		}
	}
	return false
}

// errorBranchOf returns the body of `if err := call(); err != nil`, or of
// the `if err != nil` right after `err := call()`.
func errorBranchOf(body *ast.BlockStmt, call *ast.CallExpr) *ast.BlockStmt {
	var branch *ast.BlockStmt
	ast.Inspect(body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok || branch != nil {
			return branch == nil
		}
		for i, stmt := range block.List {
			if check, ok := stmt.(*ast.IfStmt); ok && check.Init != nil && containsNode(check.Init, call) && isErrNotNil(check.Cond) {
				branch = check.Body
				return false
			}
			if containsNode(stmt, call) && i+1 < len(block.List) {
				if check, ok := block.List[i+1].(*ast.IfStmt); ok && check.Init == nil && isErrNotNil(check.Cond) {
					branch = check.Body
					return false
				}
			}
		}
		return true
	})
	return branch
}

// retryWords name a call that schedules another attempt.
var retryWords = []string{"retry", "retries", "backoff", "reschedule", "requeue"}

// schedulesRetry reports a body that calls something named for a retry,
// directly or in a loaded function within depth calls.
func schedulesRetry(scope funcScope, body ast.Node, depth int) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if slices.ContainsFunc(helpers.IdentifierWords(callName(call)), func(w string) bool { return slices.Contains(retryWords, w) }) {
			found = true
			return false
		}
		if depth > 1 {
			if decl, ok := scope.callee(call); ok {
				inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
				found = schedulesRetry(inner, decl.decl.Body, depth-1)
			}
		}
		return !found
	})
	return found
}

// checkVerbs lead the names of calls that validate an entity.
var checkVerbs = []string{"ensure", "validate", "check", "verify", "require", "assert"}

// compensationVerbs lead the names of calls that take a write back.
var compensationVerbs = []string{"Delete", "Remove", "Rollback", "Cancel", "Void", "Undo", "Compensate", "Revert", "Purge"}

// transactionCalls are calls that run a function's writes in a database
// transaction: then the insert is not committed before the check.
var transactionCalls = []string{"Begin", "BeginTx", "WithTx", "InTx", "RunInTx", "WithTransaction", "Transaction", "InTransaction"}

// NewValidationAfterCommittedInsertRule creates validation-after-committed-insert:
// a check that refuses an entity run after the insert that committed it,
// with nothing taking the row back on refusal - the caller gets a conflict,
// the table keeps the refused row:
//
//	if _, err := repo.CreateOrGet(ctx, tx); err != nil { ... }
//	if err := ensureReferenceIsFree(ctx, repo, tx); err != nil {
//		return err                     // the row stays
//	}
func NewValidationAfterCommittedInsertRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"validation-after-committed-insert",
			"patterns",
			"Detects a check that refuses an entity after the insert that committed it, with nothing removing the row on refusal — the refused row stays in the table",
			core.SeverityHigh,
		),
		suggestion: "Validate before the insert, or run the check inside the insert's transaction so a refusal rolls the row back",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || runsInTransaction(fn.Body) {
			return nil
		}
		var findings []funcFinding
		stmts := fn.Body.List
		for i, stmt := range stmts {
			entity := insertedEntity(scope.info, stmt)
			if entity == nil {
				continue
			}
			for _, later := range stmts[i+1:] {
				check, ok := later.(*ast.IfStmt)
				if !ok || check.Init == nil || !isErrNotNil(check.Cond) || !endsWithReturn(check.Body) || compensates(check.Body) {
					continue
				}
				validation := validatesEntity(scope.info, check.Init, entity)
				if validation == "" {
					continue
				}
				findings = append(findings, funcFinding{node: check, message: validation + " refuses the entity after the insert committed it, and nothing removes the row on refusal — the refused row stays in the table"})
			}
		}
		return findings
	}
	return r
}

// runsInTransaction reports a body that opens or runs in a transaction.
func runsInTransaction(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && slices.Contains(transactionCalls, callName(call)) {
			found = true
		}
		return !found
	})
	return found
}

// insertedEntity returns the variable a statement hands to a Create or
// Insert call outside a func literal; nil for none.
func insertedEntity(info *types.Info, stmt ast.Stmt) types.Object {
	var entity types.Object
	ast.Inspect(stmt, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit, *ast.BlockStmt:
			return false
		case *ast.CallExpr:
			name := callName(node)
			if !helpers.HasLeadingWord(name, "Create") && !helpers.HasLeadingWord(name, "Insert") {
				return true
			}
			for _, arg := range node.Args {
				ident, ok := ast.Unparen(arg).(*ast.Ident)
				if !ok {
					continue
				}
				obj := info.ObjectOf(ident)
				if obj == nil || isNamedType(obj.Type(), "context", "Context") {
					continue
				}
				if _, isPtr := types.Unalias(obj.Type()).(*types.Pointer); isPtr {
					entity = obj
				}
			}
		}
		return entity == nil
	})
	return entity
}

// validatesEntity returns the name of a check call in node handed entity;
// "" for none.
func validatesEntity(info *types.Info, node ast.Node, entity types.Object) string {
	found := ""
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != "" {
			return found == ""
		}
		name := callName(call)
		lower := strings.ToLower(name)
		if !slices.ContainsFunc(checkVerbs, func(verb string) bool { return strings.HasPrefix(lower, verb) && helpers.WordEndsAt(name, len(verb)) }) {
			return true
		}
		for _, arg := range call.Args {
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && info.ObjectOf(ident) == entity {
				found = name
			}
		}
		return found == ""
	})
	return found
}

// compensates reports a block that takes a write back.
func compensates(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			name := callName(call)
			if slices.ContainsFunc(compensationVerbs, func(verb string) bool { return helpers.HasLeadingWord(name, verb) }) {
				found = true
			}
		}
		return !found
	})
	return found
}
