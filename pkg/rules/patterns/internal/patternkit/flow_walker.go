package patternkit

import (
	"go/ast"
	"go/token"
)

// FlowWalker is the shared path-sensitive control-flow walker behind the
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
//     when the loop has a condition; a `for {}` loop exits through breaks
//     alone. Clause break states fold
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
type FlowWalker[S, C any] struct {
	Rule FlowRule[S, C]

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

func (w *FlowWalker[S, C]) pendingLabels() *flowLabels[S] {
	if w.labels == nil {
		w.labels = newFlowLabels[S]()
	}
	return w.labels
}

// takeLabeled removes and returns the pending state of a label, or the dead
// state when nothing jumps there.
func (w *FlowWalker[S, C]) takeLabeled(pending map[string]S, label string) S {
	state, ok := pending[label]
	if !ok {
		return w.Rule.DeadState()
	}
	delete(pending, label)
	return state
}

func (w *FlowWalker[S, C]) addLabeled(pending map[string]S, label string, state S) {
	if existing, ok := pending[label]; ok {
		pending[label] = w.join(existing, state)
		return
	}
	pending[label] = state
}

// takeLoopLabel returns and clears the label of the loop being entered.
func (w *FlowWalker[S, C]) takeLoopLabel() string {
	labels := w.pendingLabels()
	label := labels.loopLabel
	labels.loopLabel = ""
	return label
}

// takeFallthrough returns and clears the state a fallthrough carries into
// the next case clause.
func (w *FlowWalker[S, C]) takeFallthrough() S {
	labels := w.pendingLabels()
	if !labels.carries {
		return w.Rule.DeadState()
	}
	state := labels.fallState
	labels.fallState = w.Rule.DeadState()
	labels.carries = false
	return state
}

// reachLabels marks the labels heading stmt as passed and joins the states of
// forward gotos to them into the incoming state.
func (w *FlowWalker[S, C]) reachLabels(stmt ast.Stmt, state S) S {
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

// FlowScopeKind identifies the structural site of an enterScope/leaveScope
// pair.
type FlowScopeKind int

const (
	FlowScopeBlock FlowScopeKind = iota
	flowScopeIfHeader
	FlowScopeIfBody
	FlowScopeForHeader
	FlowScopeForBody
	flowScopeRangeHeader
	FlowScopeRangeBody
	flowScopeSwitchHeader
	FlowScopeCaseClause
	FlowScopeCommClause
)

// FlowEdges carries the states leaving a statement or construct.
type FlowEdges[S any] struct {
	Next      S
	Breaks    S
	Continues S
}

// FlowRule supplies the rule-specific pieces of a flow analysis.
type FlowRule[S, C any] interface {
	CloneState(S) S
	JoinStates(S, S) S
	LiveState(S) bool
	DeadState() S

	EnterScope(kind FlowScopeKind, node ast.Node, parent C, state S) (C, S)
	LeaveScope(kind FlowScopeKind, scope C, edges *FlowEdges[S])

	// SimpleStmt handles every non-control-flow statement (assignments,
	// declarations, expression statements, defer/go/send/incdec, return, …).
	// It reports terminated=true when the statement ends the branch.
	SimpleStmt(stmt ast.Stmt, state S, scope C) (next S, terminated bool)
	// IfCondition splits the state for the two branches of an if statement.
	IfCondition(stmt *ast.IfStmt, state S, scope C) (thenState, elseState S)
	// FlowExpr evaluates a bare expression position: for-condition, switch
	// tag, range operand.
	FlowExpr(expr ast.Expr, state S, scope C) S
	// RangeVars declares/invalidates the key and value bindings of a range
	// statement inside the flowScopeRangeHeader scope.
	RangeVars(stmt *ast.RangeStmt, state S, scope C) S
	// TypeSwitchGuard processes the Assign statement of a type switch.
	TypeSwitchGuard(stmt ast.Stmt, state S, scope C) S
	// CaseClause creates the clause scope and evaluates the clause guard
	// expressions of a switch or type switch (sw distinguishes the two).
	CaseClause(sw ast.Stmt, clause *ast.CaseClause, state S, parent C) (S, C)
	// CommClause creates the clause scope of a select clause; the walker then
	// runs clause.Comm as a statement inside that scope.
	CommClause(clause *ast.CommClause, state S, parent C) (S, C)
	// Normalize post-processes joined edges (deduplication/compaction).
	Normalize(edges *FlowEdges[S])
}

// Walk runs the statement list of a callable body. The rule prepares the
// function-level scope itself; the walker does not open a scope for the body.
func (w *FlowWalker[S, C]) Walk(body *ast.BlockStmt, state S, scope C) FlowEdges[S] {
	if body == nil {
		edges := w.deadEdges()
		edges.Next = state
		return edges
	}
	outer := w.labels
	w.labels = newFlowLabels[S]()
	defer func() { w.labels = outer }()
	return w.stmtList(body.List, state, scope)
}

func (w *FlowWalker[S, C]) deadEdges() FlowEdges[S] {
	dead := w.Rule.DeadState()
	return FlowEdges[S]{Next: dead, Breaks: dead, Continues: dead}
}

func (w *FlowWalker[S, C]) join(left, right S) S {
	if !w.Rule.LiveState(left) {
		return right
	}
	if !w.Rule.LiveState(right) {
		return left
	}
	return w.Rule.JoinStates(left, right)
}

func (w *FlowWalker[S, C]) stmtList(stmts []ast.Stmt, state S, scope C) FlowEdges[S] {
	edges := w.deadEdges()
	edges.Next = state
	for _, stmt := range stmts {
		// A forward goto revives the list at its label, so the list is
		// scanned past a terminated statement for labels.
		edges.Next = w.reachLabels(stmt, edges.Next)
		if !w.Rule.LiveState(edges.Next) {
			continue
		}
		stmtEdges := w.Stmt(stmt, edges.Next, scope)
		edges.Breaks = w.join(edges.Breaks, stmtEdges.Breaks)
		edges.Continues = w.join(edges.Continues, stmtEdges.Continues)
		edges.Next = stmtEdges.Next
	}
	return edges
}

func (w *FlowWalker[S, C]) Stmt(stmt ast.Stmt, state S, scope C) FlowEdges[S] {
	switch node := stmt.(type) {
	case *ast.BlockStmt:
		return w.body(node, state, scope, FlowScopeBlock)
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
		next, terminated := w.Rule.SimpleStmt(stmt, state, scope)
		edges := w.deadEdges()
		if !terminated {
			edges.Next = next
		}
		return edges
	}
}

func (w *FlowWalker[S, C]) labeledStmt(stmt *ast.LabeledStmt, state S, scope C) FlowEdges[S] {
	name := stmt.Label.Name
	labels := w.pendingLabels()
	switch stmt.Stmt.(type) {
	case *ast.ForStmt, *ast.RangeStmt:
		labels.loopLabel = name
	}
	edges := w.Stmt(stmt.Stmt, state, scope)
	labels.loopLabel = ""
	if broken := w.takeLabeled(labels.breaks, name); w.Rule.LiveState(broken) {
		edges.Next = w.join(edges.Next, broken)
		w.Rule.Normalize(&edges)
	}
	return edges
}

func (w *FlowWalker[S, C]) branchStmt(stmt *ast.BranchStmt, state S) FlowEdges[S] {
	edges := w.deadEdges()
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
				edges.Next = state
				return edges
			}
			w.addLabeled(labels.gotos, name, state)
		}
		return edges
	}
	switch stmt.Tok {
	case token.BREAK:
		edges.Breaks = state
	case token.CONTINUE:
		edges.Continues = state
	case token.FALLTHROUGH:
		labels.fallState = state
		labels.carries = true
	}
	return edges
}

func (w *FlowWalker[S, C]) body(block *ast.BlockStmt, state S, parent C, kind FlowScopeKind) FlowEdges[S] {
	if block == nil {
		edges := w.deadEdges()
		edges.Next = state
		return edges
	}
	scope, entered := w.Rule.EnterScope(kind, block, parent, state)
	edges := w.stmtList(block.List, entered, scope)
	w.Rule.LeaveScope(kind, scope, &edges)
	return edges
}

func (w *FlowWalker[S, C]) ifStmt(stmt *ast.IfStmt, state S, parent C) FlowEdges[S] {
	scope, entered := w.Rule.EnterScope(flowScopeIfHeader, stmt, parent, state)
	if stmt.Init != nil {
		initEdges := w.Stmt(stmt.Init, entered, scope)
		entered = initEdges.Next
		if !w.Rule.LiveState(entered) {
			w.Rule.LeaveScope(flowScopeIfHeader, scope, &initEdges)
			return initEdges
		}
	}
	thenState, elseState := w.Rule.IfCondition(stmt, entered, scope)

	edges := w.deadEdges()
	if w.Rule.LiveState(thenState) {
		edges = w.body(stmt.Body, thenState, scope, FlowScopeIfBody)
	}
	elseEdges := w.deadEdges()
	if stmt.Else == nil {
		elseEdges.Next = elseState
	} else if w.Rule.LiveState(elseState) {
		elseEdges = w.Stmt(stmt.Else, elseState, scope)
	}
	edges.Next = w.join(edges.Next, elseEdges.Next)
	edges.Breaks = w.join(edges.Breaks, elseEdges.Breaks)
	edges.Continues = w.join(edges.Continues, elseEdges.Continues)
	w.Rule.Normalize(&edges)
	w.Rule.LeaveScope(flowScopeIfHeader, scope, &edges)
	return edges
}

func (w *FlowWalker[S, C]) forStmt(stmt *ast.ForStmt, state S, parent C) FlowEdges[S] {
	label := w.takeLoopLabel()
	scope, entered := w.Rule.EnterScope(FlowScopeForHeader, stmt, parent, state)
	if stmt.Init != nil {
		initEdges := w.Stmt(stmt.Init, entered, scope)
		entered = initEdges.Next
		if !w.Rule.LiveState(entered) {
			w.Rule.LeaveScope(FlowScopeForHeader, scope, &initEdges)
			return initEdges
		}
	}
	if stmt.Cond != nil {
		entered = w.Rule.FlowExpr(stmt.Cond, entered, scope)
	}
	exits := stmt.Cond != nil
	zero := w.Rule.DeadState()
	if exits {
		zero = w.Rule.CloneState(entered)
	}
	bodyEdges := w.deadEdges()
	if w.Rule.LiveState(entered) {
		bodyEdges = w.body(stmt.Body, entered, scope, FlowScopeForBody)
	}
	iteration := w.join(bodyEdges.Next, bodyEdges.Continues)
	if label != "" {
		iteration = w.join(iteration, w.takeLabeled(w.pendingLabels().continues, label))
	}
	if stmt.Post != nil && w.Rule.LiveState(iteration) {
		iteration = w.Stmt(stmt.Post, iteration, scope).Next
	}
	edges := w.deadEdges()
	edges.Next = zero
	edges.Next = w.join(edges.Next, bodyEdges.Breaks)
	if exits {
		edges.Next = w.join(edges.Next, iteration)
	}
	w.Rule.Normalize(&edges)
	w.Rule.LeaveScope(FlowScopeForHeader, scope, &edges)
	return edges
}

func (w *FlowWalker[S, C]) rangeStmt(stmt *ast.RangeStmt, state S, parent C) FlowEdges[S] {
	label := w.takeLoopLabel()
	state = w.Rule.FlowExpr(stmt.X, state, parent)
	scope, entered := w.Rule.EnterScope(flowScopeRangeHeader, stmt, parent, state)
	zero := w.Rule.CloneState(entered)
	entered = w.Rule.RangeVars(stmt, entered, scope)
	bodyEdges := w.deadEdges()
	if w.Rule.LiveState(entered) {
		bodyEdges = w.body(stmt.Body, entered, scope, FlowScopeRangeBody)
	}
	edges := w.deadEdges()
	edges.Next = zero
	edges.Next = w.join(edges.Next, bodyEdges.Breaks)
	edges.Next = w.join(edges.Next, bodyEdges.Next)
	edges.Next = w.join(edges.Next, bodyEdges.Continues)
	if label != "" {
		edges.Next = w.join(edges.Next, w.takeLabeled(w.pendingLabels().continues, label))
	}
	w.Rule.Normalize(&edges)
	w.Rule.LeaveScope(flowScopeRangeHeader, scope, &edges)
	return edges
}

func (w *FlowWalker[S, C]) switchLike(
	sw ast.Stmt,
	init ast.Stmt,
	tag ast.Expr,
	assign ast.Stmt,
	body *ast.BlockStmt,
	state S,
	parent C,
) FlowEdges[S] {
	scope, entered := w.Rule.EnterScope(flowScopeSwitchHeader, sw, parent, state)
	if init != nil {
		entered = w.Stmt(init, entered, scope).Next
		if !w.Rule.LiveState(entered) {
			edges := w.deadEdges()
			w.Rule.LeaveScope(flowScopeSwitchHeader, scope, &edges)
			return edges
		}
	}
	if tag != nil {
		entered = w.Rule.FlowExpr(tag, entered, scope)
	}
	if assign != nil {
		entered = w.Rule.TypeSwitchGuard(assign, entered, scope)
	}
	edges := w.deadEdges()
	if !w.Rule.LiveState(entered) {
		w.Rule.LeaveScope(flowScopeSwitchHeader, scope, &edges)
		return edges
	}
	hasDefault := false
	carried := w.Rule.DeadState()
	for _, item := range body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			continue
		}
		hasDefault = hasDefault || len(clause.List) == 0
		clauseState, clauseScope := w.Rule.CaseClause(sw, clause, w.Rule.CloneState(entered), scope)
		// A fallthrough from the previous clause enters this body without
		// evaluating its guard.
		clauseState = w.join(clauseState, carried)
		clauseEdges := w.deadEdges()
		if w.Rule.LiveState(clauseState) {
			clauseEdges = w.stmtList(clause.Body, clauseState, clauseScope)
		}
		carried = w.takeFallthrough()
		w.Rule.LeaveScope(FlowScopeCaseClause, clauseScope, &clauseEdges)
		edges.Next = w.join(edges.Next, clauseEdges.Next)
		edges.Next = w.join(edges.Next, clauseEdges.Breaks)
		edges.Continues = w.join(edges.Continues, clauseEdges.Continues)
	}
	if !hasDefault {
		edges.Next = w.join(edges.Next, w.Rule.CloneState(entered))
	}
	w.Rule.Normalize(&edges)
	w.Rule.LeaveScope(flowScopeSwitchHeader, scope, &edges)
	return edges
}

func (w *FlowWalker[S, C]) selectStmt(stmt *ast.SelectStmt, state S, parent C) FlowEdges[S] {
	edges := w.deadEdges()
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok {
			continue
		}
		clauseState, clauseScope := w.Rule.CommClause(clause, w.Rule.CloneState(state), parent)
		if clause.Comm != nil && w.Rule.LiveState(clauseState) {
			clauseState = w.Stmt(clause.Comm, clauseState, clauseScope).Next
		}
		clauseEdges := w.deadEdges()
		if w.Rule.LiveState(clauseState) {
			clauseEdges = w.stmtList(clause.Body, clauseState, clauseScope)
		}
		w.Rule.LeaveScope(FlowScopeCommClause, clauseScope, &clauseEdges)
		edges.Next = w.join(edges.Next, clauseEdges.Next)
		edges.Next = w.join(edges.Next, clauseEdges.Breaks)
		edges.Continues = w.join(edges.Continues, clauseEdges.Continues)
	}
	w.Rule.Normalize(&edges)
	return edges
}

// Compile-time assertions; they also tell the unused linter that the flowRule
// methods are reached through the generic walker.
var (
	_ FlowRule[bool, struct{}] = (*httpBodyReachRule)(nil)
)
