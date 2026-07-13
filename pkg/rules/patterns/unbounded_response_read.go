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

func (a *unboundedResponseAnalyzer) checkFunctionBody(body *ast.BlockStmt) {
	state := newResponseState()
	a.checkBlock(body, state)
}

func (a *unboundedResponseAnalyzer) checkBlock(block *ast.BlockStmt, state *responseState) bool {
	state.pushScope()
	defer state.popScope()
	return a.checkStmtList(block.List, state)
}

func (a *unboundedResponseAnalyzer) checkStmtList(stmts []ast.Stmt, state *responseState) bool {
	for _, stmt := range stmts {
		if !a.checkStmt(stmt, state) {
			return false
		}
	}
	return true
}

func (a *unboundedResponseAnalyzer) checkStmt(stmt ast.Stmt, state *responseState) bool {
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

func (a *unboundedResponseAnalyzer) checkSimpleStmt(stmt ast.Stmt, state *responseState) bool {
	switch stmt := stmt.(type) {
	case *ast.BlockStmt:
		return a.checkBlock(stmt, state)
	case *ast.AssignStmt:
		a.checkAssignment(stmt, state)
	case *ast.DeclStmt:
		a.checkDeclaration(stmt, state)
	case *ast.ExprStmt:
		a.checkExpr(stmt.X, state)
	case *ast.DeferStmt:
		a.checkExpr(stmt.Call, state)
	case *ast.GoStmt:
		a.checkExpr(stmt.Call, state)
	case *ast.ReturnStmt:
		for _, expr := range stmt.Results {
			a.checkExpr(expr, state)
		}
		return false
	case *ast.SendStmt:
		a.checkExpr(stmt.Chan, state)
		a.checkExpr(stmt.Value, state)
	case *ast.IncDecStmt:
		a.checkExpr(stmt.X, state)
	case *ast.LabeledStmt:
		return a.checkStmt(stmt.Stmt, state)
	}
	return true
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

func (a *unboundedResponseAnalyzer) checkIf(stmt *ast.IfStmt, state *responseState) bool {
	state.pushScope()
	defer state.popScope()
	if stmt.Init != nil {
		a.checkStmt(stmt.Init, state)
	}
	a.checkExpr(stmt.Cond, state)

	thenState := state.clone()
	thenContinues := a.checkBlock(stmt.Body, thenState)
	elseState := state.clone()
	elseContinues := true
	if stmt.Else != nil {
		elseContinues = a.checkStmt(stmt.Else, elseState)
	}
	return mergeContinuingStates(state, thenState, thenContinues, elseState, elseContinues)
}

func (a *unboundedResponseAnalyzer) checkFor(stmt *ast.ForStmt, state *responseState) bool {
	state.pushScope()
	defer state.popScope()
	if stmt.Init != nil {
		a.checkStmt(stmt.Init, state)
	}
	if stmt.Cond != nil {
		a.checkExpr(stmt.Cond, state)
	}

	iterationState := state.clone()
	iterationContinues := a.checkBlock(stmt.Body, iterationState)
	if iterationContinues && stmt.Post != nil {
		a.checkStmt(stmt.Post, iterationState)
	}
	if iterationContinues {
		*state = *mergeResponseStates(state, iterationState)
	}
	return true
}

func (a *unboundedResponseAnalyzer) checkRange(stmt *ast.RangeStmt, state *responseState) bool {
	state.pushScope()
	defer state.popScope()
	a.checkExpr(stmt.X, state)
	iterationState := state.clone()
	define := stmt.Tok == token.DEFINE
	if ident, ok := stmt.Key.(*ast.Ident); ok {
		iterationState.assign(ident.Name, false, define)
	}
	if ident, ok := stmt.Value.(*ast.Ident); ok {
		iterationState.assign(ident.Name, false, define)
	}
	if a.checkBlock(stmt.Body, iterationState) {
		*state = *mergeResponseStates(state, iterationState)
	}
	return true
}

func (a *unboundedResponseAnalyzer) checkSwitch(stmt *ast.SwitchStmt, state *responseState) bool {
	state.pushScope()
	defer state.popScope()
	if stmt.Init != nil {
		a.checkStmt(stmt.Init, state)
	}
	if stmt.Tag != nil {
		a.checkExpr(stmt.Tag, state)
	}
	return a.checkClauses(stmt.Body.List, state)
}

func (a *unboundedResponseAnalyzer) checkTypeSwitch(stmt *ast.TypeSwitchStmt, state *responseState) bool {
	state.pushScope()
	defer state.popScope()
	if stmt.Init != nil {
		a.checkStmt(stmt.Init, state)
	}
	a.checkStmt(stmt.Assign, state)
	return a.checkClauses(stmt.Body.List, state)
}

func (a *unboundedResponseAnalyzer) checkClauses(clauses []ast.Stmt, state *responseState) bool {
	states := make([]*responseState, 0, len(clauses)+1)
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
		continues := a.checkStmtList(clause.Body, clauseState)
		clauseState.popScope()
		if continues {
			states = append(states, clauseState)
		}
	}
	if !hasDefault {
		states = append(states, state.clone())
	}
	if len(states) > 0 {
		*state = *mergeResponseStates(states...)
		return true
	}
	return len(clauses) == 0
}

func (a *unboundedResponseAnalyzer) checkSelect(stmt *ast.SelectStmt, state *responseState) bool {
	states := make([]*responseState, 0, len(stmt.Body.List))
	for _, clauseStmt := range stmt.Body.List {
		clause, ok := clauseStmt.(*ast.CommClause)
		if !ok {
			continue
		}
		clauseState := state.clone()
		clauseState.pushScope()
		if clause.Comm != nil {
			a.checkStmt(clause.Comm, clauseState)
		}
		continues := a.checkStmtList(clause.Body, clauseState)
		clauseState.popScope()
		if continues {
			states = append(states, clauseState)
		}
	}
	if len(states) > 0 {
		*state = *mergeResponseStates(states...)
		return true
	}
	return len(stmt.Body.List) == 0
}

func mergeContinuingStates(target, first *responseState, firstContinues bool, second *responseState, secondContinues bool) bool {
	switch {
	case firstContinues && secondContinues:
		*target = *mergeResponseStates(first, second)
	case firstContinues:
		*target = *first
	case secondContinues:
		*target = *second
	default:
		return false
	}
	return true
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
