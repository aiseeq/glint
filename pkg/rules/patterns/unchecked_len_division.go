package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"math"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUncheckedLenDivisionRule())
}

// UncheckedLenDivisionRule detects an average taken over a collection that no
// branch proved non-empty:
//
//	n := float64(len(us))
//	return Point{X: x / n, Y: y / n}   // us empty → NaN
//
// With integers the empty case panics, which at least says where it happened.
// With floats it is worse: the result is NaN, every comparison with NaN is
// false, and the value travels on through the program as a coordinate, a
// threshold or a share that nothing rejects.
//
// Only division is reported, not the remainder: `hash % len(table)` is how an
// element is picked from a static table, and its empty case panics on the spot
// instead of travelling on as a number.
//
// The check follows the control flow, so a guard on any path to the division —
// an early return on the empty case, an `if len(x) > 0`, a minimum-size check,
// or being inside a loop over that same collection — makes the division safe.
type UncheckedLenDivisionRule struct {
	*rules.BaseRule
}

// NewUncheckedLenDivisionRule creates the rule
func NewUncheckedLenDivisionRule() *UncheckedLenDivisionRule {
	return &UncheckedLenDivisionRule{
		BaseRule: rules.NewBaseRule(
			"unchecked-len-division",
			"patterns",
			"Detects division by len(x) that no branch guarded against the empty case — a panic on integers, a silently spreading NaN on floats",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile walks every function of the file without type information.
func (r *UncheckedLenDivisionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *UncheckedLenDivisionRule) RequiresSSA() bool { return false }

// AnalyzeGoProject walks every file; with type information the length of an
// array, a compile-time constant, is not taken for a collection size.
func (r *UncheckedLenDivisionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze walks every function of the file. info is nil for a file without
// type information.
func (r *UncheckedLenDivisionRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	seen := make(map[string]bool)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch fn := n.(type) {
		case *ast.FuncDecl:
			body = fn.Body
		case *ast.FuncLit:
			body = fn.Body
		default:
			return true
		}
		if body == nil {
			return true
		}
		for _, found := range analyzeLenDivisions(body, info) {
			// `Point{X: x / n, Y: y / n}` is one mistake, not two.
			key := fmt.Sprintf("%d:%s", ctx.LineFor(found.node), found.collection)
			if seen[key] {
				continue
			}
			seen[key] = true
			violations = append(violations, r.report(ctx, found))
		}
		return true
	})

	return violations
}

func (r *UncheckedLenDivisionRule) report(ctx *core.FileContext, found lenDivision) *core.Violation {
	line := ctx.LineFor(found.node)
	v := r.CreateViolation(ctx.RelPath, line,
		fmt.Sprintf("Division by len(%s) with nothing on the way proving it non-empty — an empty %s divides by zero: a panic on integers, a NaN that spreads unnoticed on floats",
			found.collection, found.collection))
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Handle the empty case before dividing: if len(%s) == 0 { … }", found.collection))
	v.WithContext("pattern", "unchecked_len_division")
	v.WithContext("collection", found.collection)
	return v
}

// lenDivision is a division site whose divisor is the length of a collection.
type lenDivision struct {
	node       ast.Node
	collection string
}

// lenState is the flow state: which collections are known non-empty here, and
// which local variables hold a length.
type lenState struct {
	nonEmpty map[string]bool
	lengthOf map[string]string
}

func newLenState() *lenState {
	return &lenState{nonEmpty: make(map[string]bool), lengthOf: make(map[string]string)}
}

// lenScope carries the guards a loop header proved for its body.
type lenScope struct {
	bodyGuard []string
}

// lenDivisionAnalyzer walks one function body. info is nil for a file
// without type information.
type lenDivisionAnalyzer struct {
	found    []lenDivision
	reported map[token.Pos]bool
	info     *types.Info
}

// analyzeLenDivisions returns the unguarded divisions of one function body.
func analyzeLenDivisions(body *ast.BlockStmt, info *types.Info) []lenDivision {
	analyzer := &lenDivisionAnalyzer{reported: make(map[token.Pos]bool), info: info}
	walker := &flowWalker[*lenState, *lenScope]{rule: analyzer}
	walker.walk(body, newLenState(), &lenScope{})
	return analyzer.found
}

func (a *lenDivisionAnalyzer) cloneState(state *lenState) *lenState {
	if state == nil {
		return nil
	}
	clone := &lenState{
		nonEmpty: make(map[string]bool, len(state.nonEmpty)),
		lengthOf: make(map[string]string, len(state.lengthOf)),
	}
	for key, value := range state.nonEmpty {
		clone.nonEmpty[key] = value
	}
	for key, value := range state.lengthOf {
		clone.lengthOf[key] = value
	}
	return clone
}

// joinStates keeps only what holds on both incoming paths: a collection proved
// non-empty in one branch alone is not proved at the merge point.
func (a *lenDivisionAnalyzer) joinStates(left, right *lenState) *lenState {
	merged := newLenState()
	for key := range left.nonEmpty {
		if right.nonEmpty[key] {
			merged.nonEmpty[key] = true
		}
	}
	for name, collection := range left.lengthOf {
		if right.lengthOf[name] == collection {
			merged.lengthOf[name] = collection
		}
	}
	return merged
}

func (a *lenDivisionAnalyzer) liveState(state *lenState) bool { return state != nil }

func (a *lenDivisionAnalyzer) deadState() *lenState { return nil }

func (a *lenDivisionAnalyzer) enterScope(
	kind flowScopeKind,
	node ast.Node,
	parent *lenScope,
	state *lenState,
) (*lenScope, *lenState) {
	switch kind {
	case flowScopeForHeader:
		scope := &lenScope{}
		if loop, ok := node.(*ast.ForStmt); ok && loop.Cond != nil {
			scope.bodyGuard = a.loopBodyGuards(loop.Cond, state)
		}
		return scope, state
	case flowScopeForBody:
		for _, collection := range parent.bodyGuard {
			state.nonEmpty[collection] = true
		}
		return parent, state
	default:
		return parent, state
	}
}

func (a *lenDivisionAnalyzer) leaveScope(flowScopeKind, *lenScope, *flowEdges[*lenState]) {}

func (a *lenDivisionAnalyzer) simpleStmt(stmt ast.Stmt, state *lenState, _ *lenScope) (*lenState, bool) {
	a.inspect(stmt, state)
	if assign, ok := stmt.(*ast.AssignStmt); ok {
		a.trackAssignment(assign, state)
	}
	if _, isReturn := stmt.(*ast.ReturnStmt); isReturn {
		return nil, true
	}
	return state, isPanicStatement(stmt)
}

// trackAssignment remembers `n := len(xs)` and `xs = append(xs, v)`, and
// forgets a name that stopped holding a length or a collection that was
// replaced.
func (a *lenDivisionAnalyzer) trackAssignment(assign *ast.AssignStmt, state *lenState) {
	// The right-hand side is evaluated before any name changes.
	lengths := make([]string, len(assign.Lhs))
	isLength := make([]bool, len(assign.Lhs))
	appended := make([]bool, len(assign.Lhs))
	if len(assign.Rhs) == len(assign.Lhs) {
		for i, rhs := range assign.Rhs {
			lengths[i], isLength[i] = a.lengthCollection(rhs, state)
			appended[i] = a.appendsElements(rhs)
		}
	}
	for i, lhs := range assign.Lhs {
		var key string
		switch target := ast.Unparen(lhs).(type) {
		case *ast.Ident:
			if target.Name == "_" {
				continue
			}
			key = target.Name
		case *ast.SelectorExpr:
			key = types.ExprString(target)
		default:
			continue
		}
		delete(state.lengthOf, key)
		delete(state.nonEmpty, key)
		if isLength[i] {
			state.lengthOf[key] = lengths[i]
		}
		if appended[i] {
			state.nonEmpty[key] = true
		}
	}
}

// appendsElements reports `append(s, v, …)` with at least one element written
// out: its result is never empty. Spreading a slice (`append(s, other...)`)
// proves nothing, other may be empty.
func (a *lenDivisionAnalyzer) appendsElements(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) < 2 || call.Ellipsis.IsValid() {
		return false
	}
	return a.isBuiltinCall(call, "append")
}

// isBuiltinCall reports a call of the named builtin. Without type
// information the name is all there is.
func (a *lenDivisionAnalyzer) isBuiltinCall(call *ast.CallExpr, name string) bool {
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok || ident.Name != name {
		return false
	}
	if a.info == nil {
		return true
	}
	builtin, ok := a.info.Uses[ident].(*types.Builtin)
	return ok && builtin.Name() == name
}

func (a *lenDivisionAnalyzer) ifCondition(stmt *ast.IfStmt, state *lenState, _ *lenScope) (*lenState, *lenState) {
	a.inspectExpr(stmt.Cond, state)
	thenGuards, elseGuards := a.guardedCollections(stmt.Cond, state)

	thenState := a.cloneState(state)
	for _, collection := range thenGuards {
		thenState.nonEmpty[collection] = true
	}
	elseState := state
	for _, collection := range elseGuards {
		elseState.nonEmpty[collection] = true
	}
	return thenState, elseState
}

func (a *lenDivisionAnalyzer) flowExpr(expr ast.Expr, state *lenState, _ *lenScope) *lenState {
	a.inspectExpr(expr, state)
	return state
}

// rangeVars marks the ranged collection non-empty: the body runs only when it
// has elements.
func (a *lenDivisionAnalyzer) rangeVars(stmt *ast.RangeStmt, state *lenState, _ *lenScope) *lenState {
	state.nonEmpty[types.ExprString(stmt.X)] = true
	return state
}

func (a *lenDivisionAnalyzer) typeSwitchGuard(stmt ast.Stmt, state *lenState, scope *lenScope) *lenState {
	next, _ := a.simpleStmt(stmt, state, scope)
	return next
}

func (a *lenDivisionAnalyzer) caseClause(
	sw ast.Stmt,
	clause *ast.CaseClause,
	state *lenState,
	parent *lenScope,
) (*lenState, *lenScope) {
	switchStmt, tagless := sw.(*ast.SwitchStmt)
	for _, expression := range clause.List {
		a.inspectExpr(expression, state)
		if !tagless || switchStmt.Tag != nil {
			continue
		}
		guards, _ := a.guardedCollections(expression, state)
		for _, collection := range guards {
			state.nonEmpty[collection] = true
		}
	}
	return state, parent
}

func (a *lenDivisionAnalyzer) commClause(_ *ast.CommClause, state *lenState, parent *lenScope) (*lenState, *lenScope) {
	return state, parent
}

func (a *lenDivisionAnalyzer) normalize(*flowEdges[*lenState]) {}

// inspect looks for divisions inside a statement, skipping nested function
// literals: their body is walked on its own, with its own flow.
func (a *lenDivisionAnalyzer) inspect(node ast.Node, state *lenState) {
	ast.Inspect(node, func(n ast.Node) bool {
		if _, isFuncLit := n.(*ast.FuncLit); isFuncLit {
			return false
		}
		switch expr := n.(type) {
		case *ast.BinaryExpr:
			if expr.Op == token.QUO {
				a.check(expr, expr.Y, state)
			}
		case *ast.AssignStmt:
			if expr.Tok == token.QUO_ASSIGN {
				for _, rhs := range expr.Rhs {
					a.check(expr, rhs, state)
				}
			}
		}
		return true
	})
}

func (a *lenDivisionAnalyzer) inspectExpr(expr ast.Expr, state *lenState) {
	if expr == nil {
		return
	}
	a.inspect(expr, state)
}

// check reports the division when its divisor is the length of a collection
// that nothing on this path proved non-empty.
func (a *lenDivisionAnalyzer) check(site ast.Node, divisor ast.Expr, state *lenState) {
	collection, ok := a.lengthCollection(divisor, state)
	if !ok || state.nonEmpty[collection] {
		return
	}
	if a.reported[site.Pos()] {
		return
	}
	a.reported[site.Pos()] = true
	a.found = append(a.found, lenDivision{node: site, collection: collection})
}

// lengthCollection returns the collection whose length expr is: len(x)
// written out or a local variable holding it, under any numeric conversions.
// With type information the length of an array is a constant, not a
// collection size, and is not returned.
func (a *lenDivisionAnalyzer) lengthCollection(expr ast.Expr, state *lenState) (string, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		held, isLength := state.lengthOf[e.Name]
		return held, isLength
	case *ast.CallExpr:
		if len(e.Args) != 1 {
			return "", false
		}
		if a.isBuiltinCall(e, "len") {
			if a.info != nil {
				if tv, ok := a.info.Types[e]; ok && tv.Value != nil {
					return "", false
				}
			}
			return types.ExprString(e.Args[0]), true
		}
		if a.isNumericConversion(e) {
			return a.lengthCollection(e.Args[0], state)
		}
	}
	return "", false
}

// isNumericConversion reports a conversion to a numeric type. Without type
// information only the builtin type names are recognized.
func (a *lenDivisionAnalyzer) isNumericConversion(call *ast.CallExpr) bool {
	if a.info != nil {
		tv, ok := a.info.Types[call.Fun]
		if !ok || !tv.IsType() {
			return false
		}
		basic, ok := tv.Type.Underlying().(*types.Basic)
		return ok && basic.Info()&types.IsNumeric != 0
	}
	name, ok := ast.Unparen(call.Fun).(*ast.Ident)
	return ok && isNumericConversionName(name.Name)
}

// numericConversions are the builtin types a length is converted to before it
// becomes a divisor.
var numericConversions = map[string]bool{
	"float64": true, "float32": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
}

func isNumericConversionName(name string) bool { return numericConversions[name] }

// guardedCollections reads a condition and returns the collections proved
// non-empty in its true branch and in its false branch.
func (a *lenDivisionAnalyzer) guardedCollections(cond ast.Expr, state *lenState) (whenTrue, whenFalse []string) {
	switch expr := ast.Unparen(cond).(type) {
	case *ast.UnaryExpr:
		if expr.Op == token.NOT {
			inner, outer := a.guardedCollections(expr.X, state)
			return outer, inner
		}
	case *ast.BinaryExpr:
		switch expr.Op {
		case token.LAND:
			// Both operands hold in the true branch; the false branch says
			// only that one of them failed.
			leftTrue, _ := a.guardedCollections(expr.X, state)
			rightTrue, _ := a.guardedCollections(expr.Y, state)
			return append(leftTrue, rightTrue...), nil
		case token.LOR:
			_, leftFalse := a.guardedCollections(expr.X, state)
			_, rightFalse := a.guardedCollections(expr.Y, state)
			return nil, append(leftFalse, rightFalse...)
		default:
			return a.lengthComparisonGuard(expr, state)
		}
	}
	return nil, nil
}

// loopBodyGuards returns the collections a loop condition proves non-empty for
// the body. Besides the plain guards, a counted loop qualifies: the body of
// `for i := 0; i < len(xs); i++` runs only while something is below the length,
// so the length is not zero.
func (a *lenDivisionAnalyzer) loopBodyGuards(cond ast.Expr, state *lenState) []string {
	guards, _ := a.guardedCollections(cond, state)

	ast.Inspect(cond, func(n ast.Node) bool {
		expr, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		var side ast.Expr
		switch expr.Op {
		case token.LSS, token.LEQ:
			side = expr.Y // index < len(xs)
		case token.GTR, token.GEQ:
			side = expr.X // len(xs) > index
		default:
			return true
		}
		if collection, ok := a.lengthCollection(side, state); ok {
			guards = append(guards, collection)
		}
		return true
	})

	return guards
}

// lengthComparisonGuard reads a comparison of a length (len(x) or a variable
// holding it) with an integer literal and reports in which branch the
// collection is known to have elements.
func (a *lenDivisionAnalyzer) lengthComparisonGuard(expr *ast.BinaryExpr, state *lenState) (whenTrue, whenFalse []string) {
	collection, bound, op, ok := a.lengthComparison(expr, state)
	if !ok {
		return nil, nil
	}
	trueGuards, falseGuards := boundImpliesNonEmpty(op, bound)
	if trueGuards {
		whenTrue = []string{collection}
	}
	if falseGuards {
		whenFalse = []string{collection}
	}
	return whenTrue, whenFalse
}

// lengthComparison normalizes `len(x) op N` and `N op len(x)` into the first
// form.
func (a *lenDivisionAnalyzer) lengthComparison(expr *ast.BinaryExpr, state *lenState) (collection string, bound int, op token.Token, ok bool) {
	if collection, ok = a.lengthCollection(expr.X, state); ok {
		if bound, ok = intLiteral(expr.Y); ok {
			return collection, bound, expr.Op, true
		}
		return "", 0, expr.Op, false
	}
	if collection, ok = a.lengthCollection(expr.Y, state); ok {
		if bound, ok = intLiteral(expr.X); ok {
			return collection, bound, mirrorComparison(expr.Op), true
		}
	}
	return "", 0, expr.Op, false
}

func mirrorComparison(op token.Token) token.Token {
	switch op {
	case token.LSS:
		return token.GTR
	case token.LEQ:
		return token.GEQ
	case token.GTR:
		return token.LSS
	case token.GEQ:
		return token.LEQ
	default:
		return op
	}
}

// boundImpliesNonEmpty answers, for `len(x) op bound`, whether the true branch
// and the false branch prove the collection non-empty.
func boundImpliesNonEmpty(op token.Token, bound int) (whenTrue, whenFalse bool) {
	switch op {
	case token.EQL: // len == bound
		return bound >= 1, bound == 0
	case token.NEQ: // len != bound
		return bound == 0, bound >= 1
	case token.GTR: // len > bound
		return bound >= 0, false
	case token.GEQ: // len >= bound
		return bound >= 1, false
	case token.LSS: // len < bound
		return false, bound >= 1
	case token.LEQ: // len <= bound
		return false, bound >= 0
	default:
		return false, false
	}
}

func intLiteral(expr ast.Expr) (int, bool) {
	literal, ok := ast.Unparen(expr).(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return 0, false
	}
	// Значение имеют только маленькие границы: длину сравнивают с 0, 1, 2.
	// Всё, что записано иначе — hex, разделители, много разрядов, — заведомо
	// больше любой реальной длины, и этого достаточно для вывода о пустоте.
	digits := strings.TrimLeft(literal.Value, "0")
	if len(digits) > 3 {
		return math.MaxInt, true
	}
	value := 0
	for _, symbol := range digits {
		if symbol < '0' || symbol > '9' {
			return math.MaxInt, true
		}
		value = value*10 + int(symbol-'0')
	}
	return value, true
}
