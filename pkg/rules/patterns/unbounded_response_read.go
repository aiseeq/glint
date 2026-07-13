package patterns

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewUnboundedResponseReadRule())
}

// UnboundedResponseReadRule detects unbounded reads of HTTP response bodies.
type UnboundedResponseReadRule struct {
	*rules.BaseRule
}

// NewUnboundedResponseReadRule creates the rule.
func NewUnboundedResponseReadRule() *UnboundedResponseReadRule {
	return &UnboundedResponseReadRule{
		BaseRule: rules.NewBaseRule(
			"unbounded-response-read",
			"patterns",
			"Detects unbounded io.ReadAll calls on HTTP response bodies",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for unbounded HTTP response body reads.
func (r *UnboundedResponseReadRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}
	return helpers.AnalyzeFuncBodies(ctx, r.checkFunction)
}

func (r *UnboundedResponseReadRule) checkFunction(ctx *core.FileContext, body *ast.BlockStmt, violations *[]*core.Violation) {
	analyzer := &unboundedResponseAnalyzer{
		rule:        r,
		ctx:         ctx,
		violations:  violations,
		reported:    make(map[token.Pos]struct{}),
		httpAliases: httpImportAliases(ctx),
	}
	analyzer.checkFunctionBody(body)
}

type responseState struct {
	scopes []map[string]bool
}

func newResponseState() *responseState {
	return &responseState{scopes: []map[string]bool{{}}}
}

func (s *responseState) clone() *responseState {
	clone := &responseState{scopes: make([]map[string]bool, len(s.scopes))}
	for i, scope := range s.scopes {
		clone.scopes[i] = make(map[string]bool, len(scope))
		for name, tracked := range scope {
			clone.scopes[i][name] = tracked
		}
	}
	return clone
}

func (s *responseState) pushScope() {
	s.scopes = append(s.scopes, make(map[string]bool))
}

func (s *responseState) popScope() {
	s.scopes = s.scopes[:len(s.scopes)-1]
}

func (s *responseState) assign(name string, tracked, define bool) {
	if name == "_" {
		return
	}
	if define {
		s.scopes[len(s.scopes)-1][name] = tracked
		return
	}
	for i := len(s.scopes) - 1; i >= 0; i-- {
		if _, exists := s.scopes[i][name]; exists {
			s.scopes[i][name] = tracked
			return
		}
	}
	s.scopes[0][name] = tracked
}

func (s *responseState) isTracked(name string) bool {
	for i := len(s.scopes) - 1; i >= 0; i-- {
		if tracked, exists := s.scopes[i][name]; exists {
			return tracked
		}
	}
	return false
}

func mergeResponseStates(states ...*responseState) *responseState {
	merged := &responseState{scopes: make([]map[string]bool, len(states[0].scopes))}
	for i := range merged.scopes {
		merged.scopes[i] = make(map[string]bool)
		for _, state := range states {
			for name, tracked := range state.scopes[i] {
				if _, exists := merged.scopes[i][name]; !exists || tracked {
					merged.scopes[i][name] = tracked
				}
			}
		}
	}
	return merged
}

type unboundedResponseAnalyzer struct {
	rule        *UnboundedResponseReadRule
	ctx         *core.FileContext
	violations  *[]*core.Violation
	reported    map[token.Pos]struct{}
	httpAliases map[string]struct{}
}

type responseFlow struct {
	next      *responseState
	breaks    *responseState
	continues *responseState
}

func (a *unboundedResponseAnalyzer) checkFunctionBody(body *ast.BlockStmt) {
	a.checkBlock(body, newResponseState())
}

func (a *unboundedResponseAnalyzer) checkBlock(block *ast.BlockStmt, state *responseState) responseFlow {
	blockState := state.clone()
	blockState.pushScope()
	flow := a.checkStmtList(block.List, blockState)
	flow.popScope()
	return flow
}

func (a *unboundedResponseAnalyzer) checkStmtList(stmts []ast.Stmt, state *responseState) responseFlow {
	flow := responseFlow{next: state}
	for _, stmt := range stmts {
		if flow.next == nil {
			break
		}
		stmtFlow := a.checkStmt(stmt, flow.next)
		flow.breaks = mergeResponseStateOptions(flow.breaks, stmtFlow.breaks)
		flow.continues = mergeResponseStateOptions(flow.continues, stmtFlow.continues)
		flow.next = stmtFlow.next
	}
	return flow
}

func (a *unboundedResponseAnalyzer) checkStmt(stmt ast.Stmt, state *responseState) responseFlow {
	switch stmt := stmt.(type) {
	case *ast.IfStmt:
		return a.checkIf(stmt, state)
	case *ast.ForStmt:
		return a.checkFor(stmt, state)
	case *ast.RangeStmt:
		return a.checkRange(stmt, state)
	case *ast.SwitchStmt:
		return a.checkSwitch(stmt, state)
	case *ast.TypeSwitchStmt:
		return a.checkTypeSwitch(stmt, state)
	case *ast.SelectStmt:
		return a.checkSelect(stmt, state)
	default:
		return a.checkSimpleStmt(stmt, state)
	}
}

func (a *unboundedResponseAnalyzer) checkSimpleStmt(stmt ast.Stmt, state *responseState) responseFlow {
	switch stmt := stmt.(type) {
	case *ast.BlockStmt:
		return a.checkBlock(stmt, state)
	case *ast.AssignStmt:
		a.checkAssignment(stmt, state)
	case *ast.DeclStmt:
		a.checkDeclaration(stmt, state)
	case *ast.ExprStmt:
		a.checkExpr(stmt.X, state)
		if isPanicStatement(stmt) {
			return responseFlow{}
		}
	case *ast.DeferStmt:
		a.checkExpr(stmt.Call, state)
	case *ast.GoStmt:
		a.checkExpr(stmt.Call, state)
	case *ast.ReturnStmt:
		for _, expr := range stmt.Results {
			a.checkExpr(expr, state)
		}
		return responseFlow{}
	case *ast.BranchStmt:
		if stmt.Label != nil {
			return responseFlow{}
		}
		switch stmt.Tok {
		case token.BREAK:
			return responseFlow{breaks: state}
		case token.CONTINUE:
			return responseFlow{continues: state}
		default:
			return responseFlow{}
		}
	case *ast.SendStmt:
		a.checkExpr(stmt.Chan, state)
		a.checkExpr(stmt.Value, state)
	case *ast.IncDecStmt:
		a.checkExpr(stmt.X, state)
	case *ast.LabeledStmt:
		return a.checkStmt(stmt.Stmt, state)
	}
	return responseFlow{next: state}
}

func (a *unboundedResponseAnalyzer) checkAssignment(stmt *ast.AssignStmt, state *responseState) {
	for _, expr := range stmt.Lhs {
		a.checkExpr(expr, state)
	}
	for _, expr := range stmt.Rhs {
		a.checkExpr(expr, state)
	}
	responseAssignment := len(stmt.Rhs) == 1 && isHTTPResponseCall(stmt.Rhs[0], a.httpAliases)
	for i, lhs := range stmt.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok {
			state.assign(ident.Name, i == 0 && responseAssignment, stmt.Tok == token.DEFINE)
		}
	}
}

func (a *unboundedResponseAnalyzer) checkDeclaration(stmt *ast.DeclStmt, state *responseState) {
	decl, ok := stmt.Decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range decl.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, expr := range value.Values {
			a.checkExpr(expr, state)
		}
		responseAssignment := len(value.Values) == 1 && isHTTPResponseCall(value.Values[0], a.httpAliases)
		for i, name := range value.Names {
			state.assign(name.Name, i == 0 && responseAssignment, true)
		}
	}
}

func (a *unboundedResponseAnalyzer) checkIf(stmt *ast.IfStmt, state *responseState) responseFlow {
	ifState := state.clone()
	ifState.pushScope()
	if stmt.Init != nil {
		initFlow := a.checkStmt(stmt.Init, ifState)
		ifState = initFlow.next
		if ifState == nil {
			initFlow.popScope()
			return initFlow
		}
	}
	a.checkExpr(stmt.Cond, ifState)

	thenFlow := a.checkBlock(stmt.Body, ifState)
	elseFlow := responseFlow{next: ifState.clone()}
	if stmt.Else != nil {
		elseFlow = a.checkStmt(stmt.Else, ifState.clone())
	}
	flow := mergeResponseFlows(thenFlow, elseFlow)
	flow.popScope()
	return flow
}

func (a *unboundedResponseAnalyzer) checkFor(stmt *ast.ForStmt, state *responseState) responseFlow {
	loopState := state.clone()
	loopState.pushScope()
	if stmt.Init != nil {
		initFlow := a.checkStmt(stmt.Init, loopState)
		loopState = initFlow.next
		if loopState == nil {
			initFlow.popScope()
			return initFlow
		}
	}
	if stmt.Cond != nil {
		a.checkExpr(stmt.Cond, loopState)
	}

	bodyFlow := a.checkBlock(stmt.Body, loopState)
	iterationState := mergeResponseStateOptions(bodyFlow.next, bodyFlow.continues)
	if iterationState != nil && stmt.Post != nil {
		iterationState = a.checkStmt(stmt.Post, iterationState).next
	}

	exitState := bodyFlow.breaks
	if stmt.Cond != nil {
		exitState = mergeResponseStateOptions(exitState, loopState, iterationState)
	}
	flow := responseFlow{next: exitState}
	flow.popScope()
	return flow
}

func (a *unboundedResponseAnalyzer) checkRange(stmt *ast.RangeStmt, state *responseState) responseFlow {
	rangeState := state.clone()
	rangeState.pushScope()
	a.checkExpr(stmt.X, rangeState)
	iterationState := rangeState.clone()
	define := stmt.Tok == token.DEFINE
	if ident, ok := stmt.Key.(*ast.Ident); ok {
		iterationState.assign(ident.Name, false, define)
	}
	if ident, ok := stmt.Value.(*ast.Ident); ok {
		iterationState.assign(ident.Name, false, define)
	}
	bodyFlow := a.checkBlock(stmt.Body, iterationState)
	exitState := mergeResponseStateOptions(rangeState, bodyFlow.next, bodyFlow.breaks, bodyFlow.continues)
	flow := responseFlow{next: exitState}
	flow.popScope()
	return flow
}

func (a *unboundedResponseAnalyzer) checkSwitch(stmt *ast.SwitchStmt, state *responseState) responseFlow {
	switchState := state.clone()
	switchState.pushScope()
	if stmt.Init != nil {
		switchState = a.checkStmt(stmt.Init, switchState).next
		if switchState == nil {
			return responseFlow{}
		}
	}
	if stmt.Tag != nil {
		a.checkExpr(stmt.Tag, switchState)
	}
	flow := a.checkClauses(stmt.Body.List, switchState)
	flow.popScope()
	return flow
}

func (a *unboundedResponseAnalyzer) checkTypeSwitch(stmt *ast.TypeSwitchStmt, state *responseState) responseFlow {
	switchState := state.clone()
	switchState.pushScope()
	if stmt.Init != nil {
		switchState = a.checkStmt(stmt.Init, switchState).next
		if switchState == nil {
			return responseFlow{}
		}
	}
	switchState = a.checkStmt(stmt.Assign, switchState).next
	flow := a.checkClauses(stmt.Body.List, switchState)
	flow.popScope()
	return flow
}

func (a *unboundedResponseAnalyzer) checkClauses(clauses []ast.Stmt, state *responseState) responseFlow {
	result := responseFlow{}
	hasDefault := false
	for _, clauseStmt := range clauses {
		clause, ok := clauseStmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		clauseState := state.clone()
		clauseState.pushScope()
		for _, expr := range clause.List {
			a.checkExpr(expr, clauseState)
		}
		if len(clause.List) == 0 {
			hasDefault = true
		}
		flow := a.checkStmtList(clause.Body, clauseState)
		flow.popScope()
		result.next = mergeResponseStateOptions(result.next, flow.next, flow.breaks)
		result.continues = mergeResponseStateOptions(result.continues, flow.continues)
	}
	if !hasDefault {
		result.next = mergeResponseStateOptions(result.next, state)
	}
	return result
}

func (a *unboundedResponseAnalyzer) checkSelect(stmt *ast.SelectStmt, state *responseState) responseFlow {
	result := responseFlow{}
	for _, clauseStmt := range stmt.Body.List {
		clause, ok := clauseStmt.(*ast.CommClause)
		if !ok {
			continue
		}
		clauseState := state.clone()
		clauseState.pushScope()
		if clause.Comm != nil {
			clauseState = a.checkStmt(clause.Comm, clauseState).next
		}
		if clauseState == nil {
			continue
		}
		flow := a.checkStmtList(clause.Body, clauseState)
		flow.popScope()
		result.next = mergeResponseStateOptions(result.next, flow.next, flow.breaks)
		result.continues = mergeResponseStateOptions(result.continues, flow.continues)
	}
	return result
}

func mergeResponseFlows(flows ...responseFlow) responseFlow {
	result := responseFlow{}
	for _, flow := range flows {
		result.next = mergeResponseStateOptions(result.next, flow.next)
		result.breaks = mergeResponseStateOptions(result.breaks, flow.breaks)
		result.continues = mergeResponseStateOptions(result.continues, flow.continues)
	}
	return result
}

func mergeResponseStateOptions(states ...*responseState) *responseState {
	present := make([]*responseState, 0, len(states))
	for _, state := range states {
		if state != nil {
			present = append(present, state)
		}
	}
	if len(present) == 0 {
		return nil
	}
	return mergeResponseStates(present...)
}

func (f *responseFlow) popScope() {
	if f.next != nil {
		f.next.popScope()
	}
	if f.breaks != nil {
		f.breaks.popScope()
	}
	if f.continues != nil {
		f.continues.popScope()
	}
}

func (a *unboundedResponseAnalyzer) checkExpr(expr ast.Expr, state *responseState) {
	ast.Inspect(expr, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.FuncLit:
			a.checkFunctionBody(node.Body)
			return false
		case *ast.CallExpr:
			a.checkCall(node, state)
		}
		return true
	})
}

func (a *unboundedResponseAnalyzer) checkCall(call *ast.CallExpr, state *responseState) {
	response, ok := unboundedResponseBodyRead(call)
	if !ok || !state.isTracked(response.Name) {
		return
	}
	if _, exists := a.reported[call.Pos()]; exists {
		return
	}
	line := a.ctx.PositionFor(call).Line
	if a.ctx.IsSuppressed(line, a.rule.Name()) {
		return
	}
	a.reported[call.Pos()] = struct{}{}
	finding := a.rule.CreateViolation(a.ctx.RelPath, line, "HTTP response body read without a size limit")
	finding.WithCode(a.ctx.GetLine(line))
	finding.WithSuggestion("Wrap " + response.Name + ".Body with io.LimitReader before calling io.ReadAll")
	finding.WithContext("pattern", "unbounded_response_read")
	finding.WithContext("variable", response.Name)
	*a.violations = append(*a.violations, finding)
}

func unboundedResponseBodyRead(call *ast.CallExpr) (*ast.Ident, bool) {
	readAll, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || readAll.Sel.Name != "ReadAll" || len(call.Args) != 1 {
		return nil, false
	}
	ioPackage, ok := readAll.X.(*ast.Ident)
	if !ok || ioPackage.Name != "io" {
		return nil, false
	}
	body, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || body.Sel.Name != "Body" {
		return nil, false
	}
	response, ok := body.X.(*ast.Ident)
	if !ok {
		return nil, false
	}
	return response, true
}
