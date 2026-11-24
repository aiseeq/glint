package gorules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strconv"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// slotOutcome is what the guard found on a path: the slot free or taken. Zero
// is a path the guard has not run on.
type slotOutcome uint8

const (
	slotFree slotOutcome = 1 + iota
	slotTaken
)

// slotPolarity is what a test of the slot says when it holds.
type slotPolarity uint8

const (
	// polarityNone: the test does not read the slot.
	polarityNone slotPolarity = iota
	polarityTaken
	polarityFree
	// polarityUnknown: the test reads the slot in a way that does not tell
	// free from taken (f(seen[slot]), ok && !ok, prev.size > limit).
	polarityUnknown
)

func (p slotPolarity) negated() slotPolarity {
	switch p {
	case polarityTaken:
		return polarityFree
	case polarityFree:
		return polarityTaken
	}
	return p
}

// outcomes returns what the guard found in its then and its else branch, by
// the polarity of its test: seen[slot], ok of _, ok := seen[slot], and a
// comparison of the value with its zero (count[slot] > 0, at[slot] != nil)
// say taken; ! and == with the zero say free. A condition beside the slot
// (seen[slot] && strict) leaves the decision to the slot: the claim holds on a
// run where it does. A test whose polarity is not known finds nothing.
func (g dedupGuard) outcomes(info *types.Info) (then, els slotOutcome) {
	t := slotTest{spelled: types.ExprString(g.slot), info: info}
	if assign, isAssign := g.test.Init.(*ast.AssignStmt); isAssign && len(assign.Rhs) == 1 &&
		types.ExprString(ast.Unparen(assign.Rhs[0])) == t.spelled {
		t.value = definedObject(assign.Lhs[0], info)
		if len(assign.Lhs) == 2 {
			t.present = definedObject(assign.Lhs[1], info)
		}
	}
	switch t.polarity(g.test.Cond) {
	case polarityTaken:
		return slotTaken, slotFree
	case polarityFree:
		return slotFree, slotTaken
	}
	return 0, 0
}

// definedObject returns the variable a target of := names, nil for _.
func definedObject(expr ast.Expr, info *types.Info) types.Object {
	if ident, ok := expr.(*ast.Ident); ok {
		return info.Defs[ident]
	}
	return nil
}

// slotTest reads the polarity of a guard's test.
type slotTest struct {
	spelled string
	// value and present are the variables the if init assigns the lookup and
	// its comma-ok to.
	value, present types.Object
	info           *types.Info
}

func (t slotTest) polarity(expr ast.Expr) slotPolarity {
	switch node := ast.Unparen(expr).(type) {
	case *ast.UnaryExpr:
		if node.Op == token.NOT {
			return t.polarity(node.X).negated()
		}
	case *ast.BinaryExpr:
		switch node.Op {
		case token.LAND, token.LOR:
			return junction(t.polarity(node.X), t.polarity(node.Y))
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			if polarity, ok := t.comparison(node); ok {
				return polarity
			}
		}
	case *ast.Ident:
		if obj := t.info.Uses[node]; obj != nil && obj == t.present {
			return polarityTaken
		}
	}
	if t.isLookup(expr) {
		return polarityTaken
	}
	if t.reads(expr) {
		return polarityUnknown
	}
	return polarityNone
}

// comparison reads a comparison with a constant, moved to the right side
// (0 < count[slot] is count[slot] > 0): a boolean test compared with true or
// false keeps or turns its polarity (ok == false is !ok), and the slot's
// value compared with its zero (nil, "", 0) or with 1 says free or taken. Any
// other constant (count[slot] > 2) does not tell.
func (t slotTest) comparison(node *ast.BinaryExpr) (slotPolarity, bool) {
	operand, op, fixed := node.X, node.Op, node.Y
	if t.isConstant(operand) {
		operand, op, fixed = fixed, mirrored(op), operand
	}
	if value, ok := t.boolConstant(fixed); ok {
		if (op == token.EQL) == value {
			return t.polarity(operand), true
		}
		return t.polarity(operand).negated(), true
	}
	if !t.isLookup(operand) {
		return polarityNone, false
	}
	switch {
	case isZeroConstant(t.info, fixed) && (op == token.EQL || op == token.LEQ):
		return polarityFree, true
	case isZeroConstant(t.info, fixed) && (op == token.NEQ || op == token.GTR):
		return polarityTaken, true
	case t.isOne(fixed) && op == token.LSS:
		return polarityFree, true
	case t.isOne(fixed) && op == token.GEQ:
		return polarityTaken, true
	}
	return polarityNone, false
}

// isConstant reports whether the expression is a constant or nil.
func (t slotTest) isConstant(expr ast.Expr) bool {
	operand := t.info.Types[expr]
	return operand.Value != nil || operand.IsNil()
}

// boolConstant returns the value of a constant true or false.
func (t slotTest) boolConstant(expr ast.Expr) (value, ok bool) {
	operand := t.info.Types[expr].Value
	if operand == nil || operand.Kind() != constant.Bool {
		return false, false
	}
	return constant.BoolVal(operand), true
}

// isOne reports whether the expression is the constant 1.
func (t slotTest) isOne(expr ast.Expr) bool {
	operand := t.info.Types[expr].Value
	return operand != nil && operand.Kind() == constant.Int && constant.Compare(operand, token.EQL, constant.MakeInt64(1))
}

// mirrored returns the operator that holds with the operands swapped.
func mirrored(op token.Token) token.Token {
	switch op {
	case token.LSS:
		return token.GTR
	case token.GTR:
		return token.LSS
	case token.LEQ:
		return token.GEQ
	case token.GEQ:
		return token.LEQ
	}
	return op
}

// junction combines the sides of && or ||: a side that does not read the slot
// leaves the decision to the other, and two sides that read it tell only
// when they say the same.
func junction(left, right slotPolarity) slotPolarity {
	switch {
	case left == polarityNone:
		return right
	case right == polarityNone, left == right:
		return left
	}
	return polarityUnknown
}

// isLookup reports whether the expression is the guarded lookup itself or the
// variable the if init assigned it to.
func (t slotTest) isLookup(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if ident, ok := expr.(*ast.Ident); ok && t.value != nil && t.info.Uses[ident] == t.value {
		return true
	}
	return types.ExprString(expr) == t.spelled
}

// reads reports whether the expression reads the slot's value. The comma-ok
// elsewhere than alone or compared with true or false (ok == strict) reads
// like a condition beside the slot.
func (t slotTest) reads(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && t.isLookup(e) {
			found = true
		}
		return !found
	})
	return found
}

// dedupPath is one path through the callee: what the guard found on it, whether
// the slot was filled on it, and the writes of the entry it made while the slot
// was free.
type dedupPath struct {
	outcome slotOutcome
	marked  bool
	pending []ast.Stmt
}

func dedupPathKey(path dedupPath) string {
	parts := []string{strconv.Itoa(int(path.outcome)), strconv.FormatBool(path.marked)}
	for _, write := range path.pending {
		parts = append(parts, patternkit.FlowPosKey(write.Pos()))
	}
	return patternkit.FlowPathKey(parts...)
}

// dedupFlow walks the function that holds the guard and records, for each
// write of the entry, what the guard found on the paths that reach it, and
// which writes a path fills the slot around while it is free.
type dedupFlow struct {
	guard     dedupGuard
	then, els slotOutcome
	marks     map[ast.Stmt]bool
	writes    map[ast.Stmt]bool
	reached   map[ast.Stmt]slotOutcome
	confirmed map[ast.Stmt]bool
}

// claims reports whether a write of the entry runs only past a free slot - no
// path from a taken slot reaches it - and fills the slot on its path, before
// or after the write: the first entry of a slot is kept, later ones are not.
func (f *dedupFlow) claims(body *ast.BlockStmt) bool {
	f.reached = map[ast.Stmt]slotOutcome{}
	f.confirmed = map[ast.Stmt]bool{}
	f.marks = map[ast.Stmt]bool{}
	for _, mark := range f.guard.marks {
		f.marks[mark] = true
	}
	(&patternkit.FlowWalker[[]dedupPath, struct{}]{Rule: f}).Walk(body, []dedupPath{{}}, struct{}{})
	for write := range f.confirmed {
		if f.reached[write]&slotTaken == 0 {
			return true
		}
	}
	return false
}

// CloneState copies the paths; a path never appends to pending in place, so
// the copies may share it.
func (*dedupFlow) CloneState(paths []dedupPath) []dedupPath {
	return slices.Clone(paths)
}

func (*dedupFlow) JoinStates(left, right []dedupPath) []dedupPath {
	return patternkit.JoinFlowPaths(left, right, dedupPathKey)
}

func (*dedupFlow) LiveState(paths []dedupPath) bool { return len(paths) > 0 }
func (*dedupFlow) DeadState() []dedupPath           { return nil }

func (*dedupFlow) EnterScope(_ patternkit.FlowScopeKind, _ ast.Node, parent struct{}, paths []dedupPath) (struct{}, []dedupPath) {
	return parent, paths
}

func (*dedupFlow) LeaveScope(patternkit.FlowScopeKind, struct{}, *patternkit.FlowEdges[[]dedupPath]) {
}

// SimpleStmt records the write of the entry the statement makes and fills the
// slot when it is a mark. A call that never returns (os.Exit, panic) does not
// end the path: a repeat that stops the program keeps no winner, so the path
// goes on as one that lets a taken slot through.
func (f *dedupFlow) SimpleStmt(stmt ast.Stmt, paths []dedupPath, _ struct{}) ([]dedupPath, bool) {
	if f.writes[stmt] {
		for i := range paths {
			f.reached[stmt] |= paths[i].outcome
			switch {
			case paths[i].outcome != slotFree:
			case paths[i].marked:
				f.confirmed[stmt] = true
			default:
				paths[i].pending = append(slices.Clip(paths[i].pending), stmt)
			}
		}
	}
	if f.marks[stmt] {
		for i := range paths {
			paths[i].marked = true
			for _, write := range paths[i].pending {
				f.confirmed[write] = true
			}
		}
	}
	_, returns := stmt.(*ast.ReturnStmt)
	return paths, returns
}

// IfCondition sends the paths into the branches of the guard with what it
// finds there; any other if leaves them as they are.
func (f *dedupFlow) IfCondition(stmt *ast.IfStmt, paths []dedupPath, _ struct{}) ([]dedupPath, []dedupPath) {
	if stmt != f.guard.test {
		return paths, f.CloneState(paths)
	}
	branch := func(outcome slotOutcome, paths []dedupPath) []dedupPath {
		for i := range paths {
			paths[i].outcome = outcome
		}
		return paths
	}
	elsePaths := branch(f.els, f.CloneState(paths))
	return branch(f.then, paths), elsePaths
}

func (*dedupFlow) FlowExpr(_ ast.Expr, paths []dedupPath, _ struct{}) []dedupPath { return paths }
func (*dedupFlow) RangeVars(_ *ast.RangeStmt, paths []dedupPath, _ struct{}) []dedupPath {
	return paths
}

// TypeSwitchGuard passes the paths on: v := x.(type) neither fills a slot nor
// keeps an entry.
func (*dedupFlow) TypeSwitchGuard(_ ast.Stmt, paths []dedupPath, _ struct{}) []dedupPath {
	return paths
}

func (*dedupFlow) CaseClause(_ ast.Stmt, _ *ast.CaseClause, paths []dedupPath, parent struct{}) ([]dedupPath, struct{}) {
	return paths, parent
}

func (*dedupFlow) CommClause(_ *ast.CommClause, paths []dedupPath, parent struct{}) ([]dedupPath, struct{}) {
	return paths, parent
}

func (*dedupFlow) Normalize(edges *patternkit.FlowEdges[[]dedupPath]) {
	edges.Next = patternkit.JoinFlowPaths(nil, edges.Next, dedupPathKey)
	edges.Breaks = patternkit.JoinFlowPaths(nil, edges.Breaks, dedupPathKey)
	edges.Continues = patternkit.JoinFlowPaths(nil, edges.Continues, dedupPathKey)
}

// guardBody returns the body of the innermost function the guard sits in: the
// callee, or a function literal inside it, whose return the guard's branch
// would leave.
func guardBody(body *ast.BlockStmt, guard *ast.IfStmt) *ast.BlockStmt {
	innermost := body
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		if lit.Body.Pos() <= guard.Pos() && guard.End() <= lit.Body.End() {
			innermost = lit.Body
		}
		return true
	})
	return innermost
}
