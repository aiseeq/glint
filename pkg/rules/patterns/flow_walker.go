package patterns

import (
	"go/ast"
	"go/token"
)

// flowWalker is the shared path-sensitive control-flow walker behind the
// flow-based patterns rules. S is the rule state that travels along
// control-flow edges (a merged state, a path list, or a reachability flag);
// C is the rule's lexical-scope handle, opaque to the walker.
//
// Contract:
//
//   - Statements are visited in source order. A construct's outgoing states
//     are grouped into flowEdges: next (normal fallthrough), breaks and
//     continues (pending unlabeled break/continue for the nearest enclosing
//     loop, switch, or select). deadState marks a terminated branch: return
//     and any simpleStmt reporting termination produce dead edges. Hooks are
//     never invoked with a dead state, and dead code after a terminated
//     statement is not visited.
//   - Labeled branches keep their state: `break L` joins the state into the
//     exit of the statement labeled L, `continue L` into the iteration state
//     of the loop labeled L, `fallthrough` into the entry of the next case
//     clause body, and a forward `goto L` into the state reaching the label
//     (which revives a statement list after a return). A backward goto is
//     treated conservatively as a no-op: the state keeps flowing past it, as
//     if the jumped-over code ran once more. These states travel inside the
//     walker, so they skip the leaveScope and normalize calls of the
//     constructs they jump out of.
//   - joinStates is called with two live states whenever branches meet:
//     the if/else join, loop exits (zero-iteration clone, break states,
//     post-iteration state — in that order), and clause joins of
//     switch/select (clause exits in clause order; for switches without a
//     default clause a clone of the pre-clause state is appended last).
//     Loop exits include the zero-iteration and post-iteration states only
//     when the loop has a condition (or loopAlwaysExits is set); a `for {}`
//     loop otherwise exits through breaks alone. Clause break states fold
//     into next; continues propagate outward.
//   - At every fork each branch receives an independent state: the walker
//     clones via cloneState, except that exactly one continuation may receive
//     the incoming state itself. The incoming state of every hook is owned by
//     the callee and must not be retained by the caller.
//   - enterScope/leaveScope run in matched pairs per structural site (see
//     flowScopeKind); a rule that needs no scope at a site returns the parent
//     unchanged. Case and comm clauses create their scopes in the caseClause
//     and commClause hooks and are closed with leaveScope using the
//     flowScopeCaseClause/flowScopeCommClause kinds. normalize runs after a
//     composite construct joins its edges, before leaveScope of the
//     construct's header scope.
type flowWalker[S, C any] struct {
	rule flowRule[S, C]

	// branchTruncates reproduces the provider engine's legacy behaviour: any
	// branch statement (break/continue/goto/fallthrough, labeled or not) that
	// appears directly in a statement list terminates the list while keeping
	// the current state flowing out as next, instead of producing break or
	// continue edges.
	branchTruncates bool

	// loopAlwaysExits makes loop exits carry the zero-iteration and
	// post-iteration states even for loops without a condition.
	loopAlwaysExits bool

	// labels holds the pending labeled-branch states of the callable body
	// being walked; walk saves and restores it around every body.
	labels *flowLabels[S]
}

// flowLabels carries the states of labeled branches, goto and fallthrough
// until they reach their target. Go labels are scoped to the function body,
// so the label name identifies the target.
type flowLabels[S any] struct {
	breaks    map[string]S
	continues map[string]S
	gotos     map[string]S
	// seen marks labels already passed in source order: a goto to one of
	// them jumps backwards.
	seen map[string]bool
	// loopLabel is the label of the loop statement about to be walked.
	loopLabel string
	// fallState is the state of a fallthrough ending the current clause.
	fallState S
	carries   bool
}

func newFlowLabels[S any]() *flowLabels[S] {
	return &flowLabels[S]{
		breaks:    make(map[string]S),
		continues: make(map[string]S),
		gotos:     make(map[string]S),
		seen:      make(map[string]bool),
	}
}

func (w *flowWalker[S, C]) pendingLabels() *flowLabels[S] {
	if w.labels == nil {
		w.labels = newFlowLabels[S]()
	}
	return w.labels
}

// takeLabeled removes and returns the pending state of a label, or the dead
// state when nothing jumps there.
func (w *flowWalker[S, C]) takeLabeled(pending map[string]S, label string) S {
	state, ok := pending[label]
	if !ok {
		return w.rule.deadState()
	}
	delete(pending, label)
	return state
}

func (w *flowWalker[S, C]) addLabeled(pending map[string]S, label string, state S) {
	if existing, ok := pending[label]; ok {
		pending[label] = w.join(existing, state)
		return
	}
	pending[label] = state
}

// takeLoopLabel returns and clears the label of the loop being entered.
func (w *flowWalker[S, C]) takeLoopLabel() string {
	labels := w.pendingLabels()
	label := labels.loopLabel
	labels.loopLabel = ""
	return label
}

// takeFallthrough returns and clears the state a fallthrough carries into
// the next case clause.
func (w *flowWalker[S, C]) takeFallthrough() S {
	labels := w.pendingLabels()
	if !labels.carries {
		return w.rule.deadState()
	}
	state := labels.fallState
	labels.fallState = w.rule.deadState()
	labels.carries = false
	return state
}

// reachLabels marks the labels heading stmt as passed and joins the states of
// forward gotos to them into the incoming state.
func (w *flowWalker[S, C]) reachLabels(stmt ast.Stmt, state S) S {
	labels := w.pendingLabels()
	for {
		labeled, ok := stmt.(*ast.LabeledStmt)
		if !ok {
			return state
		}
		name := labeled.Label.Name
		labels.seen[name] = true
		state = w.join(state, w.takeLabeled(labels.gotos, name))
		stmt = labeled.Stmt
	}
}

// flowScopeKind identifies the structural site of an enterScope/leaveScope
// pair.
type flowScopeKind int

const (
	flowScopeBlock flowScopeKind = iota
	flowScopeIfHeader
	flowScopeIfBody
	flowScopeForHeader
	flowScopeForBody
	flowScopeRangeHeader
	flowScopeRangeBody
	flowScopeSwitchHeader
	flowScopeCaseClause
	flowScopeCommClause
)

// flowEdges carries the states leaving a statement or construct.
type flowEdges[S any] struct {
	next      S
	breaks    S
	continues S
}

// flowRule supplies the rule-specific pieces of a flow analysis.
type flowRule[S, C any] interface {
	cloneState(S) S
	joinStates(S, S) S
	liveState(S) bool
	deadState() S

	enterScope(kind flowScopeKind, node ast.Node, parent C, state S) (C, S)
	leaveScope(kind flowScopeKind, scope C, edges *flowEdges[S])

	// simpleStmt handles every non-control-flow statement (assignments,
	// declarations, expression statements, defer/go/send/incdec, return, …).
	// It reports terminated=true when the statement ends the branch.
	simpleStmt(stmt ast.Stmt, state S, scope C) (next S, terminated bool)
	// ifCondition splits the state for the two branches of an if statement.
	ifCondition(stmt *ast.IfStmt, state S, scope C) (thenState, elseState S)
	// flowExpr evaluates a bare expression position: for-condition, switch
	// tag, range operand.
	flowExpr(expr ast.Expr, state S, scope C) S
	// rangeVars declares/invalidates the key and value bindings of a range
	// statement inside the flowScopeRangeHeader scope.
	rangeVars(stmt *ast.RangeStmt, state S, scope C) S
	// typeSwitchGuard processes the Assign statement of a type switch.
	typeSwitchGuard(stmt ast.Stmt, state S, scope C) S
	// caseClause creates the clause scope and evaluates the clause guard
	// expressions of a switch or type switch (sw distinguishes the two).
	caseClause(sw ast.Stmt, clause *ast.CaseClause, state S, parent C) (S, C)
	// commClause creates the clause scope of a select clause; the walker then
	// runs clause.Comm as a statement inside that scope.
	commClause(clause *ast.CommClause, state S, parent C) (S, C)
	// normalize post-processes joined edges (deduplication/compaction).
	normalize(edges *flowEdges[S])
}

// walk runs the statement list of a callable body. The rule prepares the
// function-level scope itself; the walker does not open a scope for the body.
func (w *flowWalker[S, C]) walk(body *ast.BlockStmt, state S, scope C) flowEdges[S] {
	if body == nil {
		edges := w.deadEdges()
		edges.next = state
		return edges
	}
	outer := w.labels
	w.labels = newFlowLabels[S]()
	defer func() { w.labels = outer }()
	return w.stmtList(body.List, state, scope)
}

func (w *flowWalker[S, C]) deadEdges() flowEdges[S] {
	dead := w.rule.deadState()
	return flowEdges[S]{next: dead, breaks: dead, continues: dead}
}

func (w *flowWalker[S, C]) join(left, right S) S {
	if !w.rule.liveState(left) {
		return right
	}
	if !w.rule.liveState(right) {
		return left
	}
	return w.rule.joinStates(left, right)
}

func (w *flowWalker[S, C]) stmtList(stmts []ast.Stmt, state S, scope C) flowEdges[S] {
	edges := w.deadEdges()
	edges.next = state
	for _, stmt := range stmts {
		if w.branchTruncates {
			if !w.rule.liveState(edges.next) {
				break
			}
			if _, branch := stmt.(*ast.BranchStmt); branch {
				break
			}
		} else {
			// A forward goto revives the list at its label, so the list is
			// scanned past a terminated statement for labels.
			edges.next = w.reachLabels(stmt, edges.next)
			if !w.rule.liveState(edges.next) {
				continue
			}
		}
		stmtEdges := w.stmt(stmt, edges.next, scope)
		edges.breaks = w.join(edges.breaks, stmtEdges.breaks)
		edges.continues = w.join(edges.continues, stmtEdges.continues)
		edges.next = stmtEdges.next
	}
	return edges
}

func (w *flowWalker[S, C]) stmt(stmt ast.Stmt, state S, scope C) flowEdges[S] {
	switch node := stmt.(type) {
	case *ast.BlockStmt:
		return w.body(node, state, scope, flowScopeBlock)
	case *ast.IfStmt:
		return w.ifStmt(node, state, scope)
	case *ast.ForStmt:
		return w.forStmt(node, state, scope)
	case *ast.RangeStmt:
		return w.rangeStmt(node, state, scope)
	case *ast.SwitchStmt:
		return w.switchLike(node, node.Init, node.Tag, nil, node.Body, state, scope)
	case *ast.TypeSwitchStmt:
		return w.switchLike(node, node.Init, nil, node.Assign, node.Body, state, scope)
	case *ast.SelectStmt:
		return w.selectStmt(node, state, scope)
	case *ast.LabeledStmt:
		return w.labeledStmt(node, state, scope)
	case *ast.BranchStmt:
		return w.branchStmt(node, state)
	default:
		next, terminated := w.rule.simpleStmt(stmt, state, scope)
		edges := w.deadEdges()
		if !terminated {
			edges.next = next
		}
		return edges
	}
}

func (w *flowWalker[S, C]) labeledStmt(stmt *ast.LabeledStmt, state S, scope C) flowEdges[S] {
	if w.branchTruncates {
		return w.stmt(stmt.Stmt, state, scope)
	}
	name := stmt.Label.Name
	labels := w.pendingLabels()
	switch stmt.Stmt.(type) {
	case *ast.ForStmt, *ast.RangeStmt:
		labels.loopLabel = name
	}
	edges := w.stmt(stmt.Stmt, state, scope)
	labels.loopLabel = ""
	if broken := w.takeLabeled(labels.breaks, name); w.rule.liveState(broken) {
		edges.next = w.join(edges.next, broken)
		w.rule.normalize(&edges)
	}
	return edges
}

func (w *flowWalker[S, C]) branchStmt(stmt *ast.BranchStmt, state S) flowEdges[S] {
	edges := w.deadEdges()
	if w.branchTruncates {
		// Reached only through a labeled statement: the legacy provider
		// engine kept the state flowing without any break/continue edge.
		edges.next = state
		return edges
	}
	labels := w.pendingLabels()
	if stmt.Label != nil {
		name := stmt.Label.Name
		switch stmt.Tok {
		case token.BREAK:
			w.addLabeled(labels.breaks, name, state)
		case token.CONTINUE:
			w.addLabeled(labels.continues, name, state)
		case token.GOTO:
			if labels.seen[name] {
				// Backward jump: without iterating to a fixpoint the walker
				// lets the state flow on instead of losing the path.
				edges.next = state
				return edges
			}
			w.addLabeled(labels.gotos, name, state)
		}
		return edges
	}
	switch stmt.Tok {
	case token.BREAK:
		edges.breaks = state
	case token.CONTINUE:
		edges.continues = state
	case token.FALLTHROUGH:
		labels.fallState = state
		labels.carries = true
	}
	return edges
}

func (w *flowWalker[S, C]) body(block *ast.BlockStmt, state S, parent C, kind flowScopeKind) flowEdges[S] {
	if block == nil {
		edges := w.deadEdges()
		edges.next = state
		return edges
	}
	scope, entered := w.rule.enterScope(kind, block, parent, state)
	edges := w.stmtList(block.List, entered, scope)
	w.rule.leaveScope(kind, scope, &edges)
	return edges
}

func (w *flowWalker[S, C]) ifStmt(stmt *ast.IfStmt, state S, parent C) flowEdges[S] {
	scope, entered := w.rule.enterScope(flowScopeIfHeader, stmt, parent, state)
	if stmt.Init != nil {
		initEdges := w.stmt(stmt.Init, entered, scope)
		entered = initEdges.next
		if !w.rule.liveState(entered) {
			w.rule.leaveScope(flowScopeIfHeader, scope, &initEdges)
			return initEdges
		}
	}
	thenState, elseState := w.rule.ifCondition(stmt, entered, scope)

	edges := w.deadEdges()
	if w.rule.liveState(thenState) {
		edges = w.body(stmt.Body, thenState, scope, flowScopeIfBody)
	}
	elseEdges := w.deadEdges()
	if stmt.Else == nil {
		elseEdges.next = elseState
	} else if w.rule.liveState(elseState) {
		elseEdges = w.stmt(stmt.Else, elseState, scope)
	}
	edges.next = w.join(edges.next, elseEdges.next)
	edges.breaks = w.join(edges.breaks, elseEdges.breaks)
	edges.continues = w.join(edges.continues, elseEdges.continues)
	w.rule.normalize(&edges)
	w.rule.leaveScope(flowScopeIfHeader, scope, &edges)
	return edges
}

func (w *flowWalker[S, C]) forStmt(stmt *ast.ForStmt, state S, parent C) flowEdges[S] {
	label := w.takeLoopLabel()
	scope, entered := w.rule.enterScope(flowScopeForHeader, stmt, parent, state)
	if stmt.Init != nil {
		initEdges := w.stmt(stmt.Init, entered, scope)
		entered = initEdges.next
		if !w.rule.liveState(entered) {
			w.rule.leaveScope(flowScopeForHeader, scope, &initEdges)
			return initEdges
		}
	}
	if stmt.Cond != nil {
		entered = w.rule.flowExpr(stmt.Cond, entered, scope)
	}
	exits := stmt.Cond != nil || w.loopAlwaysExits
	zero := w.rule.deadState()
	if exits {
		zero = w.rule.cloneState(entered)
	}
	bodyEdges := w.deadEdges()
	if w.rule.liveState(entered) {
		bodyEdges = w.body(stmt.Body, entered, scope, flowScopeForBody)
	}
	iteration := w.join(bodyEdges.next, bodyEdges.continues)
	if label != "" {
		iteration = w.join(iteration, w.takeLabeled(w.pendingLabels().continues, label))
	}
	if stmt.Post != nil && w.rule.liveState(iteration) {
		iteration = w.stmt(stmt.Post, iteration, scope).next
	}
	edges := w.deadEdges()
	edges.next = zero
	edges.next = w.join(edges.next, bodyEdges.breaks)
	if exits {
		edges.next = w.join(edges.next, iteration)
	}
	w.rule.normalize(&edges)
	w.rule.leaveScope(flowScopeForHeader, scope, &edges)
	return edges
}

func (w *flowWalker[S, C]) rangeStmt(stmt *ast.RangeStmt, state S, parent C) flowEdges[S] {
	label := w.takeLoopLabel()
	state = w.rule.flowExpr(stmt.X, state, parent)
	scope, entered := w.rule.enterScope(flowScopeRangeHeader, stmt, parent, state)
	zero := w.rule.cloneState(entered)
	entered = w.rule.rangeVars(stmt, entered, scope)
	bodyEdges := w.deadEdges()
	if w.rule.liveState(entered) {
		bodyEdges = w.body(stmt.Body, entered, scope, flowScopeRangeBody)
	}
	edges := w.deadEdges()
	edges.next = zero
	edges.next = w.join(edges.next, bodyEdges.breaks)
	edges.next = w.join(edges.next, bodyEdges.next)
	edges.next = w.join(edges.next, bodyEdges.continues)
	if label != "" {
		edges.next = w.join(edges.next, w.takeLabeled(w.pendingLabels().continues, label))
	}
	w.rule.normalize(&edges)
	w.rule.leaveScope(flowScopeRangeHeader, scope, &edges)
	return edges
}

func (w *flowWalker[S, C]) switchLike(
	sw ast.Stmt,
	init ast.Stmt,
	tag ast.Expr,
	assign ast.Stmt,
	body *ast.BlockStmt,
	state S,
	parent C,
) flowEdges[S] {
	scope, entered := w.rule.enterScope(flowScopeSwitchHeader, sw, parent, state)
	if init != nil {
		entered = w.stmt(init, entered, scope).next
		if !w.rule.liveState(entered) {
			edges := w.deadEdges()
			w.rule.leaveScope(flowScopeSwitchHeader, scope, &edges)
			return edges
		}
	}
	if tag != nil {
		entered = w.rule.flowExpr(tag, entered, scope)
	}
	if assign != nil {
		entered = w.rule.typeSwitchGuard(assign, entered, scope)
	}
	edges := w.deadEdges()
	if !w.rule.liveState(entered) {
		w.rule.leaveScope(flowScopeSwitchHeader, scope, &edges)
		return edges
	}
	hasDefault := false
	carried := w.rule.deadState()
	for _, item := range body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			continue
		}
		hasDefault = hasDefault || len(clause.List) == 0
		clauseState, clauseScope := w.rule.caseClause(sw, clause, w.rule.cloneState(entered), scope)
		// A fallthrough from the previous clause enters this body without
		// evaluating its guard.
		clauseState = w.join(clauseState, carried)
		clauseEdges := w.deadEdges()
		if w.rule.liveState(clauseState) {
			clauseEdges = w.stmtList(clause.Body, clauseState, clauseScope)
		}
		carried = w.takeFallthrough()
		w.rule.leaveScope(flowScopeCaseClause, clauseScope, &clauseEdges)
		edges.next = w.join(edges.next, clauseEdges.next)
		edges.next = w.join(edges.next, clauseEdges.breaks)
		edges.continues = w.join(edges.continues, clauseEdges.continues)
	}
	if !hasDefault {
		edges.next = w.join(edges.next, w.rule.cloneState(entered))
	}
	w.rule.normalize(&edges)
	w.rule.leaveScope(flowScopeSwitchHeader, scope, &edges)
	return edges
}

func (w *flowWalker[S, C]) selectStmt(stmt *ast.SelectStmt, state S, parent C) flowEdges[S] {
	edges := w.deadEdges()
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok {
			continue
		}
		clauseState, clauseScope := w.rule.commClause(clause, w.rule.cloneState(state), parent)
		if clause.Comm != nil && w.rule.liveState(clauseState) {
			clauseState = w.stmt(clause.Comm, clauseState, clauseScope).next
		}
		clauseEdges := w.deadEdges()
		if w.rule.liveState(clauseState) {
			clauseEdges = w.stmtList(clause.Body, clauseState, clauseScope)
		}
		w.rule.leaveScope(flowScopeCommClause, clauseScope, &clauseEdges)
		edges.next = w.join(edges.next, clauseEdges.next)
		edges.next = w.join(edges.next, clauseEdges.breaks)
		edges.continues = w.join(edges.continues, clauseEdges.continues)
	}
	w.rule.normalize(&edges)
	return edges
}

// Compile-time assertions; they also tell the unused linter that the flowRule
// methods are reached through the generic walker.
var (
	_ flowRule[bool, struct{}]                                  = (*httpBodyReachRule)(nil)
	_ flowRule[[]idempotencyPath, *idempotencyScope]            = (*idempotencyFunctionAnalyzer)(nil)
	_ flowRule[[]checkpointFlow, *checkpointLexicalScope]       = (*checkpointFlowAnalyzer)(nil)
	_ flowRule[[]statusHistoryPath, *statusHistoryLexicalScope] = (*statusHistoryFlowAnalyzer)(nil)
	_ flowRule[[]providerFlowState, struct{}]                   = (*providerFlowAnalyzer)(nil)
	_ flowRule[*responseState, struct{}]                        = (*unboundedResponseAnalyzer)(nil)
	_ flowRule[*lenState, *lenScope]                            = (*lenDivisionAnalyzer)(nil)
)
