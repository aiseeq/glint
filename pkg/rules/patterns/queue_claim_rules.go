package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewLeaseReclaimWithoutAttemptLimitRule())
	rules.Register(NewRepeatableClaimRule())
	rules.Register(NewForUpdateOutsideTransactionRule())
	rules.Register(NewPoisonRowLeftClaimedRule())
	rules.Register(NewRemoteCancelFailureIgnoredRule())
}

// returningClause is the RETURNING tail of a statement: what it reads back
// does not count as what it does.
var returningClause = regexp.MustCompile(`(?is)\breturning\b.*$`)

// claimedStatus captures the status a claim UPDATE sets: SET status = 'X'.
var claimedStatus = regexp.MustCompile(`(?is)\bset\s+(?:\w+\.)?status\s*=\s*'(\w+)'`)

// NewLeaseReclaimWithoutAttemptLimitRule creates
// lease-reclaim-without-attempt-limit: a queue claim that also re-takes rows
// left in its own processing status once their lease expired, without
// counting the attempt or checking a limit - a row the worker crashes on is
// claimed, crashes it and is claimed again every lease period, forever:
//
//	WHERE (status = 'PENDING' AND next_retry_at <= NOW())
//	   OR (status = 'PROCESSING' AND updated_at <= NOW() - $2 * interval '1 second')
//	...
//	UPDATE outbox SET status = 'PROCESSING'      -- attempts untouched
func NewLeaseReclaimWithoutAttemptLimitRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"lease-reclaim-without-attempt-limit",
			"patterns",
			"Detects a queue claim that re-takes rows whose lease expired without counting the attempt or checking a limit — a row the worker crashes on is reclaimed and crashes it forever",
			core.SeverityMedium,
		),
		suggestion: "Count a reclaim as an attempt (attempts = attempts + 1 for a row taken from the processing status) and dead-letter a row with no attempts left",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		for _, lit := range sqlLiterals(fn.Body) {
			text := lit.text
			match := claimedStatus.FindStringSubmatch(text)
			if match == nil || strings.Contains(strings.ToLower(returningClause.ReplaceAllString(text, "")), "attempt") {
				continue
			}
			reclaim := regexp.MustCompile(`(?is)status\s*=\s*'` + regexp.QuoteMeta(match[1]) + `'\s+and\s+[\w.]+\s*<=?\s*(?:now\(\)|current_timestamp)`)
			if reclaim.MatchString(text) {
				findings = append(findings, funcFinding{node: lit.expr, message: "The claim re-takes rows left in '" + match[1] + "' after their lease expired without counting the attempt — a row the worker crashes on is reclaimed every lease period, forever"})
			}
		}
		return findings
	}
	return r
}

// claimVerbs lead the names of functions and calls that take work for one
// worker.
var claimVerbs = []string{"Claim", "Lease", "Acquire", "Reserve", "Dequeue", "Lock"}

// leadsWithAny reports a name led by one of the camelCase words.
func leadsWithAny(name string, words []string) bool {
	return slices.ContainsFunc(words, func(w string) bool { return helpers.HasLeadingWord(name, w) })
}

// setClause and whereClause split an UPDATE into what it sets and what it
// tests.
var (
	setClause    = regexp.MustCompile(`(?is)\bset\b(.*?)\bwhere\b(.*)$`)
	setColumn    = regexp.MustCompile(`(?:^|,)\s*(?:\w+\.)?(\w+)\s*=`)
	statusFilter = regexp.MustCompile(`(?i)\b(?:status|state)\s*(?:=|in\b)`)
)

// claimBookkeeping are the columns a claim bumps whatever it claims.
var claimBookkeeping = []string{"version", "updated_at", "updated", "modified_at"}

// NewRepeatableClaimRule creates repeatable-claim: a claim UPDATE guarded by
// the row's status that leaves the status as it was and tests none of the
// columns it sets - a second caller passes the same guard and claims the row
// again, and both go on to act on it:
//
//	UPDATE payments SET approved_by = $1, version = version + 1
//	WHERE id = $2 AND version = $3 AND status = 'WAITING_APPROVAL'   -- no approved_by IS NULL
func NewRepeatableClaimRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"repeatable-claim",
			"patterns",
			"Detects a claim UPDATE that keeps the row in its claimable status and tests none of the columns it sets — a second caller claims the same row again",
			core.SeverityHigh,
		),
		suggestion: "Make the claim exclusive: move the row out of the claimable status, or require the claimed column to be empty (AND approved_by IS NULL)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || !leadsWithAny(fn.Name.Name, claimVerbs) {
			return nil
		}
		var findings []funcFinding
		for _, lit := range sqlLiterals(fn.Body) {
			if column := repeatableClaim(lit.text); column != "" {
				findings = append(findings, funcFinding{node: lit.expr, message: "The claim sets " + column + " but keeps the row in its claimable status and does not test " + column + " — a second caller claims the same row again"})
			}
		}
		return findings
	}
	return r
}

// repeatableClaim returns the first column an UPDATE sets when it keeps the
// status, filters by it and tests none of the columns it sets; "" otherwise.
func repeatableClaim(text string) string {
	if !regexp.MustCompile(`(?i)^\s*update\b`).MatchString(text) {
		return ""
	}
	parts := setClause.FindStringSubmatch(text)
	if parts == nil || !statusFilter.MatchString(parts[2]) {
		return ""
	}
	where := strings.ToLower(parts[2])
	claimed := ""
	for _, m := range setColumn.FindAllStringSubmatch(parts[1], -1) {
		column := strings.ToLower(m[1])
		if column == "status" || column == "state" {
			return ""
		}
		if slices.Contains(claimBookkeeping, column) {
			continue
		}
		if regexp.MustCompile(`\b` + column + `\b`).MatchString(where) {
			return ""
		}
		if claimed == "" {
			claimed = column
		}
	}
	return claimed
}

// poolTypes are the handles that run each statement on its own connection,
// outside any transaction.
var poolTypes = []string{"Pool", "DB"}

// modifyingStatement finds an UPDATE ... SET, an INSERT or a DELETE: a
// statement that acts on the rows it locks.
var modifyingStatement = regexp.MustCompile(`(?is)\bupdate\s+[\w.]+(?:\s+\w+)?\s+set\b|\binsert\s+into\b|\bdelete\s+from\b`)

// NewForUpdateOutsideTransactionRule creates for-update-outside-transaction:
// SELECT ... FOR UPDATE run through a connection pool locks the rows only for
// that one statement - the lock is released before the caller acts on them,
// and two workers take the same rows:
//
//	rows, err := r.db.Pool.Query(ctx, `SELECT ... FOR UPDATE SKIP LOCKED`)
func NewForUpdateOutsideTransactionRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"for-update-outside-transaction",
			"patterns",
			"Detects SELECT ... FOR UPDATE run through a connection pool, outside a transaction — the lock ends with the statement, before the rows are acted on",
			core.SeverityHigh,
		),
		suggestion: "Run the SELECT and the writes in one transaction, or claim the rows in one statement (UPDATE ... FROM (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		defs := singleDefinitions(scope.info, fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !queryMethods[callName(call)] || !onPool(scope.info, call) {
				return true
			}
			text := queryText(scope.info, defs, call)
			if strings.Contains(strings.ToLower(text), "for update") && !modifyingStatement.MatchString(text) {
				findings = append(findings, funcFinding{node: call, message: "SELECT ... FOR UPDATE runs through the pool, outside a transaction — the lock ends with this statement, before the rows are acted on, and two workers take the same rows"})
			}
			return true
		})
		return findings
	}
	return r
}

// onPool reports a method call on a pool or a database handle.
func onPool(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	if fn == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	t := sig.Recv().Type()
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && slices.Contains(poolTypes, named.Obj().Name())
}

// queryText returns the text of the first string argument of a call: a
// literal, or a local variable's only definition.
func queryText(info *types.Info, defs map[types.Object]ast.Expr, call *ast.CallExpr) string {
	for _, arg := range call.Args {
		expr := ast.Unparen(arg)
		if ident, ok := expr.(*ast.Ident); ok {
			if def, ok := defs[info.ObjectOf(ident)]; ok {
				expr = ast.Unparen(def)
			}
		}
		if text, ok := stringLiteral(expr); ok {
			return text
		}
	}
	return ""
}

// finalizeVerbs lead the names of calls that settle a claimed item: mark it
// sent or failed, release it, schedule a retry.
var finalizeVerbs = []string{"Finalize", "Release", "Fail", "Retry", "Requeue", "Reschedule", "Handle", "Complete", "Ack", "Nack", "Unlock", "Dead", "Abandon", "Return"}

// settlesItem reports a call that writes or settles a claimed item.
func settlesItem(call *ast.CallExpr) bool {
	name := callName(call)
	return helpers.IsWriteName(name) || leadsWithAny(name, finalizeVerbs)
}

// NewPoisonRowLeftClaimedRule creates poison-row-left-claimed: in a queue
// worker (a function that leases a batch and settles items on some path), an
// error branch after the claim that returns or skips the item
// without settling it leaves the row leased; the lease expires, the row is
// claimed again and fails the same way - a poison row loops forever:
//
//	items, err := w.repo.ClaimPending(ctx, 1)
//	...
//	if err := validate(item); err != nil {
//		w.logger.Error("invalid item", ...)
//		return                                  // the row stays PROCESSING
//	}
func NewPoisonRowLeftClaimedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"poison-row-left-claimed",
			"patterns",
			"Detects an error branch after a queue claim that leaves without settling the claimed item — the lease expires and the row is reclaimed and fails the same way, forever",
			core.SeverityMedium,
		),
		suggestion: "Settle the item on every error path: mark it failed (dead-letter), schedule a retry or release the lease",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		claim, own := queueClaim(scope.info, fn.Body)
		if claim == nil || !callsAny(fn.Body, func(call *ast.CallExpr) bool { return leadsWithAny(callName(call), finalizeVerbs) }) {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			check, ok := n.(*ast.IfStmt)
			if !ok || check.Pos() < claim.End() || check == own || !isErrNotNil(check.Cond) || !blockLeaves(check.Body) {
				return true
			}
			if check.Init != nil && callsAny(check.Init, settlesItem) || callsAny(check.Body, settlesItem) {
				return true
			}
			findings = append(findings, funcFinding{node: check, message: "This error branch leaves the item claimed by " + callName(claim) + " without settling it — the lease expires, the row is claimed again and fails the same way, forever"})
			return true
		})
		return findings
	}
	return r
}

// leaseVerbs lead the names of calls that lease a batch of queue items.
var leaseVerbs = []string{"Claim", "Lease", "Reserve", "Dequeue"}

// queueClaim returns the claim call of `items, err := x.ClaimPending(...)`
// in a body - a method leasing a batch, a slice of items - and the if that
// checks its own error.
func queueClaim(info *types.Info, body *ast.BlockStmt) (*ast.CallExpr, *ast.IfStmt) {
	var claim *ast.CallExpr
	var own *ast.IfStmt
	ast.Inspect(body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok || claim != nil {
			return claim == nil
		}
		for i, stmt := range block.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
				continue
			}
			call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
			if !ok || !leadsWithAny(callName(call), leaseVerbs) {
				continue
			}
			if _, isSel := call.Fun.(*ast.SelectorExpr); !isSel {
				continue
			}
			if _, isSlice := typeUnderlying(info.TypeOf(assign.Lhs[0])).(*types.Slice); !isSlice {
				continue
			}
			claim = call
			if i+1 < len(block.List) {
				own, _ = block.List[i+1].(*ast.IfStmt)
			}
			return false
		}
		return true
	})
	return claim, own
}

// callsAny reports a call under node that pass accepts, outside func literals.
func callsAny(node ast.Node, pass func(*ast.CallExpr) bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && pass(call) {
			found = true
		}
		return !found
	})
	return found
}

// remoteCancelVerbs lead the names of calls that stop an operation at the
// provider.
var remoteCancelVerbs = []string{"Cancel", "Void", "Revoke", "Reverse", "Abort"}

// completionWords are message words of a finished operation, not a
// cancelled one.
var completionWords = []string{"complet", "paid", "settled", "success", "executed", "processed"}

// NewRemoteCancelFailureIgnoredRule creates remote-cancel-failure-ignored: a
// cancel at the provider that fails and is only logged, followed by the
// local cancellation - or a classifier that reads the provider's "completed"
// as "already cancelled" - records a stopped payout the provider still
// executes:
//
//	if err := s.client.CancelTransaction(ref); err != nil {
//		s.logger.Error("failed to cancel at provider", "error", err)   // and on
//	}
//	return s.repo.UpdateStatus(ctx, id, "CANCELLED")
func NewRemoteCancelFailureIgnoredRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"remote-cancel-failure-ignored",
			"patterns",
			"Detects a failed cancel at the provider that is only logged before the local record is written, and a classifier that takes a provider's \"completed\" for \"already cancelled\" — the record says stopped while the provider executes",
			core.SeverityHigh,
		),
		suggestion: "Stop on a failed remote cancel unless the provider confirms the cancellation itself; never read a completed state as cancelled",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		findings := completedTakenAsCancelled(fn)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			check, ok := n.(*ast.IfStmt)
			if !ok || check.Init == nil || !isErrNotNil(check.Cond) || leavesAnywhere(check.Body) {
				return true
			}
			cancel := remoteCancelCall(check.Init)
			if cancel == nil {
				return true
			}
			if writesAfter(fn.Body, check.End()) {
				findings = append(findings, funcFinding{node: check, message: "A failed " + callName(cancel) + " is only logged and the local record is written after it — the record says stopped while the provider may still execute"})
			}
			return true
		})
		return findings
	}
	return r
}

// remoteCancelCall returns the method call of an if's init that cancels at
// a provider; nil for none.
func remoteCancelCall(init ast.Stmt) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(init, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != nil {
			return found == nil
		}
		if _, isSel := call.Fun.(*ast.SelectorExpr); isSel && leadsWithAny(callName(call), remoteCancelVerbs) {
			found = call
		}
		return found == nil
	})
	return found
}

// leavesAnywhere reports a block with a return, a branch or a panic at any
// depth.
func leavesAnywhere(block *ast.BlockStmt) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt, *ast.BranchStmt:
			found = true
		case *ast.CallExpr:
			if isIdentNamed(node.Fun, "panic") {
				found = true
			}
		}
		return !found
	})
	return found
}

// writesAfter reports a write call in body after pos.
func writesAfter(body *ast.BlockStmt, pos token.Pos) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && call.Pos() > pos && (helpers.IsWriteName(callName(call)) || helpers.HasLeadingWord(callName(call), "Set")) {
			found = true
		}
		return !found
	})
	return found
}

// completedTakenAsCancelled reports, in a function returning a bool, the
// text checks of a || chain that tests for cancellation words and also for
// words of a completed operation: a completed payout is answered as
// "already cancelled".
func completedTakenAsCancelled(fn *ast.FuncDecl) []funcFinding {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 || !isIdentNamed(fn.Type.Results.List[0].Type, "bool") {
		return nil
	}
	var findings []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		var cancels bool
		var completed []*ast.CallExpr
		for _, operand := range flattenOr(ret.Results[0]) {
			call, ok := ast.Unparen(operand).(*ast.CallExpr)
			if !ok {
				continue
			}
			word := lastStringArg(call)
			switch {
			case strings.Contains(word, "cancel"):
				cancels = true
			case slices.ContainsFunc(completionWords, func(w string) bool { return strings.Contains(word, w) }):
				completed = append(completed, call)
			}
		}
		if cancels {
			for _, call := range completed {
				findings = append(findings, funcFinding{node: call, message: "A provider message of a completed operation is taken for \"already cancelled\" — a payout that went through is recorded as cancelled"})
			}
		}
		return false
	})
	return findings
}

// lastStringArg returns the lower-cased value of a call's last argument when
// it is a string literal; "" otherwise.
func lastStringArg(call *ast.CallExpr) string {
	if len(call.Args) == 0 {
		return ""
	}
	text, _ := stringLiteral(call.Args[len(call.Args)-1])
	return strings.ToLower(text)
}

// typeUnderlying returns the underlying type of t, nil for none.
func typeUnderlying(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return t.Underlying()
}
