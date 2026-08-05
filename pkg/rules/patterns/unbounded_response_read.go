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
	walker := &flowWalker[*responseState, struct{}]{rule: a}
	walker.walk(body, newResponseState(), struct{}{})
}

func (a *unboundedResponseAnalyzer) cloneState(state *responseState) *responseState {
	return state.clone()
}

func (a *unboundedResponseAnalyzer) joinStates(left, right *responseState) *responseState {
	return mergeResponseStates(left, right)
}

func (a *unboundedResponseAnalyzer) liveState(state *responseState) bool { return state != nil }

func (a *unboundedResponseAnalyzer) deadState() *responseState { return nil }

func (a *unboundedResponseAnalyzer) enterScope(
	_ flowScopeKind,
	_ ast.Node,
	parent struct{},
	state *responseState,
) (struct{}, *responseState) {
	state.pushScope()
	return parent, state
}

func (a *unboundedResponseAnalyzer) leaveScope(_ flowScopeKind, _ struct{}, edges *flowEdges[*responseState]) {
	for _, state := range []*responseState{edges.next, edges.breaks, edges.continues} {
		if state != nil {
			state.popScope()
		}
	}
}

func (a *unboundedResponseAnalyzer) simpleStmt(stmt ast.Stmt, state *responseState, _ struct{}) (*responseState, bool) {
	switch stmt := stmt.(type) {
	case *ast.AssignStmt:
		a.checkAssignment(stmt, state)
	case *ast.DeclStmt:
		a.checkDeclaration(stmt, state)
	case *ast.ExprStmt:
		a.checkExpr(stmt.X, state)
		if isPanicStatement(stmt) {
			return nil, true
		}
	case *ast.DeferStmt:
		a.checkExpr(stmt.Call, state)
	case *ast.GoStmt:
		a.checkExpr(stmt.Call, state)
	case *ast.ReturnStmt:
		for _, expr := range stmt.Results {
			a.checkExpr(expr, state)
		}
		return nil, true
	case *ast.SendStmt:
		a.checkExpr(stmt.Chan, state)
		a.checkExpr(stmt.Value, state)
	case *ast.IncDecStmt:
		a.checkExpr(stmt.X, state)
	}
	return state, false
}

func (a *unboundedResponseAnalyzer) ifCondition(
	stmt *ast.IfStmt,
	state *responseState,
	_ struct{},
) (*responseState, *responseState) {
	a.checkExpr(stmt.Cond, state)
	return state, state.clone()
}

func (a *unboundedResponseAnalyzer) flowExpr(expr ast.Expr, state *responseState, _ struct{}) *responseState {
	a.checkExpr(expr, state)
	return state
}

func (a *unboundedResponseAnalyzer) rangeVars(stmt *ast.RangeStmt, state *responseState, _ struct{}) *responseState {
	define := stmt.Tok == token.DEFINE
	if ident, ok := stmt.Key.(*ast.Ident); ok {
		state.assign(ident.Name, false, define)
	}
	if ident, ok := stmt.Value.(*ast.Ident); ok {
		state.assign(ident.Name, false, define)
	}
	return state
}

func (a *unboundedResponseAnalyzer) typeSwitchGuard(stmt ast.Stmt, state *responseState, scope struct{}) *responseState {
	next, _ := a.simpleStmt(stmt, state, scope)
	return next
}

func (a *unboundedResponseAnalyzer) caseClause(
	_ ast.Stmt,
	clause *ast.CaseClause,
	state *responseState,
	parent struct{},
) (*responseState, struct{}) {
	state.pushScope()
	for _, expr := range clause.List {
		a.checkExpr(expr, state)
	}
	return state, parent
}

func (a *unboundedResponseAnalyzer) commClause(
	_ *ast.CommClause,
	state *responseState,
	parent struct{},
) (*responseState, struct{}) {
	state.pushScope()
	return state, parent
}

func (a *unboundedResponseAnalyzer) normalize(*flowEdges[*responseState]) {}

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
