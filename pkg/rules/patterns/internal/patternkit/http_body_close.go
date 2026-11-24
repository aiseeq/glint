package patternkit

import (
	"go/ast"
	"go/types"
)

// httpBodyReachRule adapts the shared flow walker into a plain reachability
// walk: the state is a single "reachable" flag and every visited node is
// handed to the visit callback.
type httpBodyReachRule struct {
	info  *types.Info
	file  *ast.File
	visit func(ast.Node)
	// branch, when set, says which arms of an if statement a path can take
	// from its condition; an arm it rules out is not walked.
	branch func(cond ast.Expr) (then, els bool)
}

// walkReachableStatements hands visit every statement a path reaches; a call
// that never returns (panic, os.Exit, log.Fatal) ends the path. info and file
// may be nil.
func walkReachableStatements(statements []ast.Stmt, info *types.Info, file *ast.File, visit func(ast.Node)) {
	walker := &FlowWalker[bool, struct{}]{Rule: &httpBodyReachRule{info: info, file: file, visit: visit}}
	walker.stmtList(statements, true, struct{}{})
}

// WalkReachableStatementsWhere is walkReachableStatements where branch says
// which arms of an if statement a path can take from its condition: the
// statements of an arm it rules out are not handed to visit.
func WalkReachableStatementsWhere(statements []ast.Stmt, info *types.Info, file *ast.File, branch func(cond ast.Expr) (then, els bool), visit func(ast.Node)) {
	walker := &FlowWalker[bool, struct{}]{Rule: &httpBodyReachRule{info: info, file: file, visit: visit, branch: branch}}
	walker.stmtList(statements, true, struct{}{})
}

func (r *httpBodyReachRule) CloneState(state bool) bool { return state }

func (r *httpBodyReachRule) JoinStates(bool, bool) bool { return true }

func (r *httpBodyReachRule) LiveState(state bool) bool { return state }

func (r *httpBodyReachRule) DeadState() bool { return false }

func (r *httpBodyReachRule) EnterScope(_ FlowScopeKind, _ ast.Node, parent struct{}, state bool) (struct{}, bool) {
	return parent, state
}

func (r *httpBodyReachRule) LeaveScope(FlowScopeKind, struct{}, *FlowEdges[bool]) {}

func (r *httpBodyReachRule) SimpleStmt(stmt ast.Stmt, state bool, _ struct{}) (bool, bool) {
	r.visit(stmt)
	if _, isReturn := stmt.(*ast.ReturnStmt); isReturn {
		return false, true
	}
	return state, StmtNoReturn(stmt, r.info, r.file) != CallReturns
}

func (r *httpBodyReachRule) IfCondition(stmt *ast.IfStmt, state bool, _ struct{}) (bool, bool) {
	r.visit(stmt.Cond)
	if r.branch == nil {
		return state, state
	}
	then, els := r.branch(stmt.Cond)
	return state && then, state && els
}

func (r *httpBodyReachRule) FlowExpr(expr ast.Expr, state bool, _ struct{}) bool {
	r.visit(expr)
	return state
}

func (r *httpBodyReachRule) RangeVars(_ *ast.RangeStmt, state bool, _ struct{}) bool {
	return state
}

func (r *httpBodyReachRule) TypeSwitchGuard(stmt ast.Stmt, state bool, scope struct{}) bool {
	next, _ := r.SimpleStmt(stmt, state, scope)
	return next
}

func (r *httpBodyReachRule) CaseClause(_ ast.Stmt, clause *ast.CaseClause, state bool, parent struct{}) (bool, struct{}) {
	for _, expression := range clause.List {
		r.visit(expression)
	}
	return state, parent
}

func (r *httpBodyReachRule) CommClause(_ *ast.CommClause, state bool, parent struct{}) (bool, struct{}) {
	return state, parent
}

func (r *httpBodyReachRule) Normalize(*FlowEdges[bool]) {}
