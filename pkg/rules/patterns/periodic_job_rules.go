package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewPeriodicJobDoneCheckByAnyRowRule())
	rules.Register(NewPeriodAttemptMarkerIgnoresWorkSetRule())
	rules.Register(NewAttemptMarkerWrittenBeforeWorkRule())
}

// periodicWorkDepth bounds how deep the calls after a guard are followed to
// the loop that writes the keys of the period.
const periodicWorkDepth = 2

// guardLookahead is how many statements after a check its guard may follow.
const guardLookahead = 3

// NewPeriodicJobDoneCheckByAnyRowRule creates periodic-job-done-check-by-any-row:
// a job driven by a ticker that skips its whole run when any row of the
// period exists, while the run writes many keys of the period, stays skipped
// after a partial run or a lazy write of one key - the missing keys are never
// written that period:
//
//	exists, err := r.repo.HasRatesForDate(ctx, date)   // one row is enough
//	if exists {
//		return
//	}
//	r.fetchAll(ctx, date)                               // a loop of Upserts
func NewPeriodicJobDoneCheckByAnyRowRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"periodic-job-done-check-by-any-row",
			"patterns",
			"Detects a periodic job that skips its whole run when any row of the period exists, while the run writes many keys — after a partial run the missing keys are never written that period",
			core.SeverityMedium,
		),
		suggestion: "Check what is missing (the keys of the run without a row for the period) and fetch those, or mark the run done only when it completed",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || !tickDriven(scope, fn) {
			return nil
		}
		var findings []funcFinding
		for i, stmt := range fn.Body.List {
			check, result := periodCheck(scope.info, stmt, existenceCheck)
			if result == nil {
				continue
			}
			guard := guardAfter(fn.Body.List, i, func(cond ast.Expr) bool { return anyRowFound(scope.info, cond, result) })
			if guard < 0 || !writesKeysInLoop(scope, fn.Body.List[guard+1:], periodicWorkDepth) {
				continue
			}
			findings = append(findings, funcFinding{node: check, message: "The periodic job skips its whole run when " + callName(check) + " finds any row of the period, but the run writes many keys — after a partial run (or a lazy write of one key) the missing keys are never written that period"})
		}
		return findings
	}
	return r
}

// NewPeriodAttemptMarkerIgnoresWorkSetRule creates
// period-attempt-marker-ignores-work-set: a once-per-period attempt marker
// keyed by the period alone, guarding work whose list is computed at run
// time, covers only the list of the first run - an item added later that
// period finds the period attempted and waits for the next one:
//
//	pairs, _ := r.config.ActivePairs(ctx)
//	started, _ := r.repo.TryStartRefreshAttempt(ctx, date)   // pairs not in the key
//	if !started {
//		return
//	}
//	r.fetch(ctx, date, pairs)
func NewPeriodAttemptMarkerIgnoresWorkSetRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"period-attempt-marker-ignores-work-set",
			"patterns",
			"Detects a once-per-period attempt marker keyed without the work list it guards, which is computed at run time — an item added later in the period is skipped until the next one",
			core.SeverityMedium,
		),
		suggestion: "Key the marker by the work set too (a fingerprint of the list), or check which items of the list are still missing",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		forEachGuardedMarker(scope, fn, func(marker *ast.CallExpr, at int) {
			for _, work := range runTimeWorkSets(scope.info, fn.Body.List[:at]) {
				if mentionsObject(scope.info, marker, work) || !mentionsObjectIn(scope.info, fn.Body.List[at+1:], work) {
					continue
				}
				findings = append(findings, funcFinding{node: marker, message: "The once-per-period marker " + callName(marker) + " is keyed without " + work.Name() + ", the work list computed at run time — an item added to the list later in the period finds the period attempted and is skipped until the next one"})
				return
			}
		})
		return findings
	}
	return r
}

// NewAttemptMarkerWrittenBeforeWorkRule creates attempt-marker-written-before-work:
// a once-per-period marker written before the work it guards, and never
// taken back when the work fails, burns the period on a transient failure -
// every later run finds it attempted and does nothing until the next period:
//
//	started, _ := r.repo.TryStartRefreshAttempt(ctx, date)
//	if !started {
//		return
//	}
//	r.fetchAndStore(ctx, date)    // fails: no retry today
//
// An event marked processed by its duplicate check, before the processing,
// is the same trap per event: the sender's redelivery of an event whose
// processing failed is dropped as a duplicate.
//
//	if d.isDuplicate(key) { return true }
//	d.markProcessed(key)          // the processing comes after, in the caller
func NewAttemptMarkerWrittenBeforeWorkRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"attempt-marker-written-before-work",
			"patterns",
			"Detects a once-per-period marker written before the work it guards and never removed when the work fails — one transient failure skips the whole period",
			core.SeverityMedium,
		),
		suggestion: "Record the period after the work succeeded (check the marker first, write it last), or remove the marker on the failure path",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || takesBackMarker(fn.Body) {
			return nil
		}
		var findings []funcFinding
		forEachGuardedMarker(scope, fn, func(marker *ast.CallExpr, at int) {
			if !doesWork(fn.Body.List[at+1:]) {
				return
			}
			findings = append(findings, funcFinding{node: marker, message: "The once-per-period marker " + callName(marker) + " is written before the work it guards and never removed when the work fails — one transient failure skips the rest of the period"})
		})
		for _, marker := range dedupMarkersBeforeWork(scope, fn) {
			findings = append(findings, funcFinding{node: marker, message: "The event is marked by " + callName(marker) + " right after its duplicate check, before it is processed, and nothing removes the mark when the processing fails — the redelivery of a failed event is dropped as a duplicate"})
		}
		return findings
	}
	return r
}

// dedupStateWords name the state a duplicate check reads and a dedup marker
// writes.
var dedupStateWords = []string{"duplicate", "processed", "seen", "handled", "delivered"}

// dedupMarkVerbs lead the names of calls writing a dedup marker.
var dedupMarkVerbs = []string{"Mark", "Set", "Record", "Remember", "Add", "Save", "Store", "Put"}

// isDedupMarker reports markProcessed, MarkSeen, SetHandled.
func isDedupMarker(name string) bool {
	words := helpers.IdentifierWords(name)
	return slices.ContainsFunc(dedupMarkVerbs, func(verb string) bool { return helpers.HasLeadingWord(name, verb) }) &&
		slices.ContainsFunc(words, func(w string) bool { return w != "duplicate" && slices.Contains(dedupStateWords, w) })
}

// isDedupCheck reports isDuplicate, IsProcessed, alreadySeen.
func isDedupCheck(name string) bool {
	words := helpers.IdentifierWords(name)
	return !isDedupMarker(name) && !helpers.IsWriteName(name) &&
		slices.ContainsFunc(words, func(w string) bool { return slices.Contains(dedupStateWords, w) })
}

// dedupMarkersBeforeWork returns the dedup markers fn writes right after the
// guard that leaves on a duplicate, with the processing still ahead - later
// in fn, or in a caller of fn acting on its verdict - and nothing in fn or
// its callers removing the mark.
func dedupMarkersBeforeWork(scope funcScope, fn *ast.FuncDecl) []*ast.CallExpr {
	stmts := fn.Body.List
	var markers []*ast.CallExpr
	for i := range stmts {
		keys := dedupGuardKeys(scope.info, stmts, i)
		if len(keys) == 0 || i+1 >= len(stmts) {
			continue
		}
		marker := dedupMarkerIn(scope.info, stmts[i+1], keys)
		if marker == nil {
			continue
		}
		if !doesWork(stmts[i+2:]) && !callersTakeVerdict(scope, fn) {
			continue
		}
		markers = append(markers, marker)
	}
	return markers
}

// callersTakeVerdict reports a function whose callers exist and none of them
// takes a marker back: the work after its verdict runs with the mark set.
func callersTakeVerdict(scope funcScope, fn *ast.FuncDecl) bool {
	obj, ok := scope.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	sites := scope.callers[obj.Origin()]
	for _, site := range sites {
		if takesBackMarker(site.caller.decl.Body) {
			return false
		}
	}
	return len(sites) > 0
}

// dedupGuardKeys returns the keys of the duplicate check that the if at
// stmts[at] leaves on: a check call in its condition, or a variable a check
// call set before it.
func dedupGuardKeys(info *types.Info, stmts []ast.Stmt, at int) map[types.Object]bool {
	guard, ok := stmts[at].(*ast.IfStmt)
	if !ok || !blockLeaves(guard.Body) {
		return nil
	}
	keys := make(map[types.Object]bool)
	for _, operand := range flattenOr(guard.Cond) {
		ast.Inspect(operand, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if isDedupCheck(callName(node)) {
					addIdentArgs(info, node, keys)
				}
			case *ast.Ident:
				if check := dedupCheckSetting(info, stmts[:at], info.ObjectOf(node)); check != nil {
					addIdentArgs(info, check, keys)
				}
			}
			return true
		})
	}
	return keys
}

// dedupCheckSetting returns the duplicate check call whose result stmts
// assign to v.
func dedupCheckSetting(info *types.Info, stmts []ast.Stmt, v types.Object) *ast.CallExpr {
	if v == nil {
		return nil
	}
	for _, stmt := range stmts {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			continue
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !isDedupCheck(callName(call)) {
			continue
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && info.ObjectOf(id) == v {
			return call
		}
	}
	return nil
}

// addIdentArgs adds the variables call is handed as plain arguments.
func addIdentArgs(info *types.Info, call *ast.CallExpr, keys map[types.Object]bool) {
	for _, arg := range call.Args {
		if id, ok := ast.Unparen(arg).(*ast.Ident); ok {
			if v, isVar := info.ObjectOf(id).(*types.Var); isVar && !isNamedType(v.Type(), "context", "Context") {
				keys[v] = true
			}
		}
	}
}

// dedupMarkerIn returns the dedup marker stmt calls with one of keys: a bare
// call, an assignment of its result, or the init of an if.
func dedupMarkerIn(info *types.Info, stmt ast.Stmt, keys map[types.Object]bool) *ast.CallExpr {
	var expr ast.Expr
	switch node := stmt.(type) {
	case *ast.ExprStmt:
		expr = node.X
	case *ast.AssignStmt:
		if len(node.Rhs) == 1 {
			expr = node.Rhs[0]
		}
	case *ast.IfStmt:
		return dedupMarkerIn(info, node.Init, keys)
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || !isDedupMarker(callName(call)) {
		return nil
	}
	for _, arg := range call.Args {
		if id, ok := ast.Unparen(arg).(*ast.Ident); ok && keys[info.ObjectOf(id)] {
			return call
		}
	}
	return nil
}

// checkKind tells an existence check of the period's data from an attempt
// marker of the period's run.
type checkKind int

const (
	existenceCheck checkKind = iota
	attemptMarker
)

// runMarkerWords name the record of a run rather than the data it writes.
var runMarkerWords = []string{"attempt", "attempts", "run", "runs", "marker", "mark", "done", "complete", "completed", "finished", "processed", "job", "lock", "started"}

// existenceVerbs lead the names of checks whether rows exist.
var existenceVerbs = []string{"Has", "Exists", "Count", "Any"}

// periodCheck returns the call of `v, err := x.Check(..., period, ...)` - an
// existence check or an attempt marker taking a time.Time - and the object
// of v; nil when stmt is none.
func periodCheck(info *types.Info, stmt ast.Stmt, kind checkKind) (*ast.CallExpr, types.Object) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return nil, nil
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok || !takesTime(info, call) {
		return nil, nil
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || ident.Name == "_" {
		return nil, nil
	}
	name := callName(call)
	words := helpers.IdentifierWords(name)
	marks := slices.ContainsFunc(words, func(w string) bool { return slices.Contains(runMarkerWords, w) })
	switch kind {
	case existenceCheck:
		if marks || !slices.ContainsFunc(existenceVerbs, func(verb string) bool { return helpers.HasLeadingWord(name, verb) }) {
			return nil, nil
		}
	case attemptMarker:
		if !isAttemptMarker(name, words) {
			return nil, nil
		}
	}
	return call, info.ObjectOf(ident)
}

// isAttemptMarker reports a call that records the attempt of a run:
// TryStartRefreshAttempt, RecordAttempt, TryClaimDay.
func isAttemptMarker(name string, words []string) bool {
	if slices.Contains(words, "attempt") {
		return !helpers.HasLeadingWord(name, "Has") && !helpers.HasLeadingWord(name, "Get") && !helpers.HasLeadingWord(name, "Count") && !helpers.HasLeadingWord(name, "Delete")
	}
	return helpers.HasLeadingWord(name, "Try") && len(words) > 1 && slices.Contains([]string{"start", "begin", "claim"}, words[1])
}

// takesTime reports a call handed a time.Time: the period it is about.
func takesTime(info *types.Info, call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if isNamedType(info.TypeOf(arg), "time", "Time") {
			return true
		}
	}
	return false
}

// guardAfter returns the index of the if, among the few statements after
// stmts[at], whose condition (or one of its || operands) passes found and
// whose body leaves; -1 for none.
func guardAfter(stmts []ast.Stmt, at int, found func(ast.Expr) bool) int {
	for j := at + 1; j < len(stmts) && j <= at+guardLookahead; j++ {
		check, ok := stmts[j].(*ast.IfStmt)
		if !ok || check.Init != nil || !blockLeaves(check.Body) {
			continue
		}
		if slices.ContainsFunc(flattenOr(check.Cond), found) {
			return j
		}
	}
	return -1
}

// anyRowFound reports `v`, `v > 0`, `v != 0` or `v >= 1` for the result of
// an existence check: one row is taken for the whole period.
func anyRowFound(info *types.Info, cond ast.Expr, result types.Object) bool {
	cond = ast.Unparen(cond)
	if ident, ok := cond.(*ast.Ident); ok {
		return info.ObjectOf(ident) == result
	}
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	left, ok := ast.Unparen(bin.X).(*ast.Ident)
	if !ok || info.ObjectOf(left) != result {
		return false
	}
	lit, ok := ast.Unparen(bin.Y).(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	switch bin.Op {
	case token.GTR, token.NEQ:
		return lit.Value == "0"
	case token.GEQ:
		return lit.Value == "1"
	}
	return false
}

// notStarted reports `!v` for the result of an attempt marker.
func notStarted(info *types.Info, cond ast.Expr, result types.Object) bool {
	not, ok := ast.Unparen(cond).(*ast.UnaryExpr)
	if !ok || not.Op != token.NOT {
		return false
	}
	ident, ok := ast.Unparen(not.X).(*ast.Ident)
	return ok && info.ObjectOf(ident) == result
}

// forEachGuardedMarker calls visit with each attempt marker of a function
// driven by a ticker whose `!started` guard leaves, and the index of the
// guard.
func forEachGuardedMarker(scope funcScope, fn *ast.FuncDecl, visit func(marker *ast.CallExpr, guard int)) {
	if fn.Body == nil || !tickDriven(scope, fn) {
		return
	}
	for i, stmt := range fn.Body.List {
		marker, result := periodCheck(scope.info, stmt, attemptMarker)
		if marker == nil {
			continue
		}
		if guard := guardAfter(fn.Body.List, i, func(cond ast.Expr) bool { return notStarted(scope.info, cond, result) }); guard >= 0 {
			visit(marker, guard)
		}
	}
}

// tickDriven reports a function called from the tick of a polling loop,
// directly or through one caller.
func tickDriven(scope funcScope, fn *ast.FuncDecl) bool {
	obj, ok := scope.info.Defs[fn.Name].(*types.Func)
	return ok && calledFromTick(scope, obj, 2)
}

func calledFromTick(scope funcScope, fn *types.Func, depth int) bool {
	for _, site := range scope.callers[fn.Origin()] {
		if inTickBody(site.caller.decl.Body, site.call) {
			return true
		}
		if depth > 1 {
			if caller, ok := site.caller.info.Defs[site.caller.decl.Name].(*types.Func); ok && caller != fn && calledFromTick(scope, caller, depth-1) {
				return true
			}
		}
	}
	return false
}

// inTickBody reports a node inside the tick of a polling loop of body.
func inTickBody(body *ast.BlockStmt, node ast.Node) bool {
	found := false
	forEachTickBody(body, func(tick *ast.BlockStmt) {
		for _, stmt := range tick.List {
			if stmt.Pos() <= node.Pos() && node.End() <= stmt.End() {
				found = true
			}
		}
	})
	return found
}

// writesKeysInLoop reports statements that write in a loop - one key per
// iteration - directly or in a function they call, within depth calls.
func writesKeysInLoop(scope funcScope, stmts []ast.Stmt, depth int) bool {
	found := false
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			if found {
				return false
			}
			switch node := n.(type) {
			case *ast.RangeStmt:
				found = loopWrites(node.Body)
			case *ast.ForStmt:
				found = loopWrites(node.Body)
			case *ast.CallExpr:
				if decl, ok := scope.callee(node); ok && depth > 1 {
					inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
					found = writesKeysInLoop(inner, decl.decl.Body.List, depth-1)
				}
			}
			return !found
		})
	}
	return found
}

// loopWrites reports a write call in a loop body.
func loopWrites(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && helpers.IsWriteName(callName(call)) {
			found = true
		}
		return !found
	})
	return found
}

// runTimeWorkSets returns the slices and maps that stmts take from a call
// handed a context: a work list read from storage or configuration at run
// time.
func runTimeWorkSets(info *types.Info, stmts []ast.Stmt) []*types.Var {
	var sets []*types.Var
	for _, stmt := range stmts {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			continue
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !takesContext(info, call) {
			continue
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			continue
		}
		v, ok := info.ObjectOf(ident).(*types.Var)
		if !ok {
			continue
		}
		switch v.Type().Underlying().(type) {
		case *types.Slice, *types.Map:
			sets = append(sets, v)
		}
	}
	return sets
}

// takesContext reports a call handed a context.Context.
func takesContext(info *types.Info, call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if isNamedType(info.TypeOf(arg), "context", "Context") {
			return true
		}
	}
	return false
}

// mentionsObjectIn reports a use of obj in any of stmts.
func mentionsObjectIn(info *types.Info, stmts []ast.Stmt, obj types.Object) bool {
	for _, stmt := range stmts {
		found := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && info.ObjectOf(id) == obj {
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// markerRelease lead the names of calls that take a marker back.
var markerRelease = []string{"Delete", "Remove", "Clear", "Release", "Reset", "Unmark", "Forget", "Abandon", "Unlock", "Rollback"}

// takesBackMarker reports a function that calls something removing a
// marker: the failure path frees the period again.
func takesBackMarker(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			name := callName(call)
			found = slices.ContainsFunc(markerRelease, func(verb string) bool { return helpers.HasLeadingWord(name, verb) })
		}
		return !found
	})
	return found
}

// doesWork reports statements that call something other than a logger.
func doesWork(stmts []ast.Stmt) bool {
	found := false
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return !found
			}
			if helpers.IsLoggerCall(call) {
				return false
			}
			found = true
			return false
		})
	}
	return found
}
