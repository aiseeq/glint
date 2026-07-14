package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

var terminalAfterCheckpointMethods = map[string]struct{}{
	"SaveProgress":     {},
	"SaveCheckpoint":   {},
	"PersistProgress":  {},
	"UpdateCheckpoint": {},
}

var terminalAfterCheckpointTerminalMethods = map[string]struct{}{
	"Finish":        {},
	"Complete":      {},
	"MarkDone":      {},
	"MarkCompleted": {},
}

func init() {
	rules.Register(NewTerminalAfterFailedCheckpointRule())
}

// TerminalAfterFailedCheckpointRule detects terminal success after a durable checkpoint failure was ignored.
type TerminalAfterFailedCheckpointRule struct {
	*rules.BaseRule
}

// NewTerminalAfterFailedCheckpointRule creates the rule.
func NewTerminalAfterFailedCheckpointRule() *TerminalAfterFailedCheckpointRule {
	return &TerminalAfterFailedCheckpointRule{BaseRule: rules.NewBaseRule(
		"terminal-after-failed-checkpoint",
		"patterns",
		"Detects terminal success calls reachable after a failed durable checkpoint is only logged or ignored",
		core.SeverityHigh,
	)}
}

type failedCheckpoint struct {
	ifStmt   *ast.IfStmt
	receiver string
	method   string
}

type terminalCall struct {
	call     *ast.CallExpr
	receiver string
	method   string
}

type checkpointAssignment struct {
	receiver string
	method   string
}

type checkpointBindingID token.Pos

type checkpointLexicalScope struct {
	parent   *checkpointLexicalScope
	bindings map[string]checkpointBindingID
}

func newCheckpointLexicalScope(parent *checkpointLexicalScope) *checkpointLexicalScope {
	return &checkpointLexicalScope{parent: parent, bindings: make(map[string]checkpointBindingID)}
}

func (s *checkpointLexicalScope) declare(identifier *ast.Ident) checkpointBindingID {
	if identifier == nil || identifier.Name == "_" {
		return 0
	}
	if binding, ok := s.bindings[identifier.Name]; ok {
		return binding
	}
	binding := checkpointBindingID(identifier.Pos())
	s.bindings[identifier.Name] = binding
	return binding
}

func (s *checkpointLexicalScope) lookup(name string) (checkpointBindingID, bool) {
	for current := s; current != nil; current = current.parent {
		if binding, ok := current.bindings[name]; ok {
			return binding, true
		}
	}
	return 0, false
}

func (s *checkpointLexicalScope) declaredBindings() []checkpointBindingID {
	bindings := make([]checkpointBindingID, 0, len(s.bindings))
	for _, binding := range s.bindings {
		bindings = append(bindings, binding)
	}
	return bindings
}

type checkpointFlow struct {
	assignments map[checkpointBindingID]checkpointAssignment
	failures    []failedCheckpoint
}

type checkpointStatementFlow struct {
	next      []checkpointFlow
	breaks    []checkpointFlow
	continues []checkpointFlow
}

type checkpointFinding struct {
	checkpoint failedCheckpoint
	terminal   terminalCall
}

type checkpointFlowAnalyzer struct {
	findings         []checkpointFinding
	reported         map[*ast.IfStmt]bool
	analyzedClosures map[*ast.FuncLit]bool
}

// AnalyzeFile checks each production Go function independently.
func (r *TerminalAfterFailedCheckpointRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	fileScope := checkpointFileScope(ctx.GoAST)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		for _, finding := range checkpointFindings(fn, fileScope) {
			checkpoint := finding.checkpoint
			terminal := finding.terminal

			line := ctx.PositionFor(checkpoint.ifStmt).Line
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}

			terminalLine := ctx.PositionFor(terminal.call).Line
			v := r.CreateViolation(ctx.RelPath, line,
				"terminal method "+terminal.method+" can run after "+checkpoint.method+" failed without stopping the flow")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Return or panic when the durable checkpoint fails; call the terminal method only after the checkpoint succeeds")
			v.WithContext("pattern", "terminal_after_failed_checkpoint")
			v.WithContext("function", fn.Name.Name)
			v.WithContext("checkpoint_method", checkpoint.method)
			v.WithContext("terminal_method", terminal.method)
			v.WithContext("terminal_line", terminalLine)
			violations = append(violations, v)
		}
	}

	return violations
}

func checkpointFindings(function *ast.FuncDecl, fileScope *checkpointLexicalScope) []checkpointFinding {
	analyzer := &checkpointFlowAnalyzer{
		reported:         make(map[*ast.IfStmt]bool),
		analyzedClosures: make(map[*ast.FuncLit]bool),
	}
	analyzer.analyzeCallable(function.Body, fileScope, function.Recv, function.Type.Params, function.Type.Results)
	return analyzer.findings
}

func (a *checkpointFlowAnalyzer) analyzeCallable(
	body *ast.BlockStmt,
	parent *checkpointLexicalScope,
	fields ...*ast.FieldList,
) {
	scope := newCheckpointLexicalScope(parent)
	for _, fieldList := range fields {
		declareCheckpointFields(scope, fieldList)
	}
	initial := checkpointFlow{assignments: make(map[checkpointBindingID]checkpointAssignment)}
	a.analyzeBlockInScope(body, []checkpointFlow{initial}, scope)
}

func (a *checkpointFlowAnalyzer) analyzeBlock(
	block *ast.BlockStmt,
	paths []checkpointFlow,
	parent *checkpointLexicalScope,
) checkpointStatementFlow {
	return a.analyzeBlockInScope(block, paths, newCheckpointLexicalScope(parent))
}

func (a *checkpointFlowAnalyzer) analyzeBlockInScope(
	block *ast.BlockStmt,
	paths []checkpointFlow,
	scope *checkpointLexicalScope,
) checkpointStatementFlow {
	if block == nil {
		return checkpointStatementFlow{next: paths}
	}
	flow := checkpointStatementFlow{next: paths}
	for _, stmt := range block.List {
		if len(flow.next) == 0 {
			break
		}
		statementFlow := a.analyzeStatement(stmt, flow.next, scope)
		flow.breaks = append(flow.breaks, statementFlow.breaks...)
		flow.continues = append(flow.continues, statementFlow.continues...)
		flow.next = statementFlow.next
	}
	removeCheckpointAssignments(&flow, scope.declaredBindings())
	flow.next = compactCheckpointFlows(flow.next)
	flow.breaks = compactCheckpointFlows(flow.breaks)
	flow.continues = compactCheckpointFlows(flow.continues)
	return flow
}

func (a *checkpointFlowAnalyzer) analyzeStatement(
	stmt ast.Stmt,
	paths []checkpointFlow,
	scope *checkpointLexicalScope,
) checkpointStatementFlow {
	switch node := stmt.(type) {
	case *ast.AssignStmt:
		return checkpointStatementFlow{next: a.assign(node, paths, scope)}
	case *ast.DeclStmt:
		a.findTerminalsOnPaths(node, paths, scope)
		declareCheckpointDeclaration(scope, node.Decl)
		return checkpointStatementFlow{next: paths}
	case *ast.BlockStmt:
		return a.analyzeBlock(node, cloneCheckpointFlows(paths), scope)
	case *ast.ReturnStmt:
		a.findTerminalsOnPaths(node, paths, scope)
		return checkpointStatementFlow{}
	case *ast.BranchStmt:
		if node.Label != nil {
			return checkpointStatementFlow{}
		}
		switch node.Tok {
		case token.BREAK:
			return checkpointStatementFlow{breaks: paths}
		case token.CONTINUE:
			return checkpointStatementFlow{continues: paths}
		default:
			return checkpointStatementFlow{}
		}
	case *ast.IfStmt:
		return a.analyzeIf(node, paths, scope)
	case *ast.ForStmt:
		return a.analyzeFor(node, paths, scope)
	case *ast.RangeStmt:
		return a.analyzeRange(node, paths, scope)
	case *ast.SwitchStmt:
		return a.analyzeSwitch(node, paths, scope)
	case *ast.TypeSwitchStmt:
		return a.analyzeTypeSwitch(node, paths, scope)
	case *ast.SelectStmt:
		return a.analyzeSelect(node, paths, scope)
	case *ast.LabeledStmt:
		return a.analyzeStatement(node.Stmt, paths, scope)
	default:
		a.findTerminalsOnPaths(node, paths, scope)
		if isPanicStatement(node) {
			return checkpointStatementFlow{}
		}
		return checkpointStatementFlow{next: paths}
	}
}

func (a *checkpointFlowAnalyzer) analyzeIf(
	ifStmt *ast.IfStmt,
	paths []checkpointFlow,
	parent *checkpointLexicalScope,
) checkpointStatementFlow {
	result := checkpointStatementFlow{}
	scope := newCheckpointLexicalScope(parent)
	for _, path := range paths {
		conditionPaths := []checkpointFlow{copyCheckpointFlow(path)}
		if ifStmt.Init != nil {
			conditionPaths = a.analyzeStatement(ifStmt.Init, conditionPaths, scope).next
		}
		a.findTerminalsOnPaths(ifStmt.Cond, conditionPaths, scope)

		truePaths, falsePaths := conditionCheckpointPaths(ifStmt, conditionPaths, scope)
		body := a.analyzeBlock(ifStmt.Body, truePaths, scope)
		otherwise := checkpointStatementFlow{next: falsePaths}
		if ifStmt.Else != nil {
			otherwise = a.analyzeStatement(ifStmt.Else, falsePaths, scope)
		}

		result.next = append(result.next, body.next...)
		result.next = append(result.next, otherwise.next...)
		result.breaks = append(result.breaks, body.breaks...)
		result.breaks = append(result.breaks, otherwise.breaks...)
		result.continues = append(result.continues, body.continues...)
		result.continues = append(result.continues, otherwise.continues...)
	}
	result.next = compactCheckpointFlows(result.next)
	result.breaks = compactCheckpointFlows(result.breaks)
	result.continues = compactCheckpointFlows(result.continues)
	removeCheckpointAssignments(&result, scope.declaredBindings())
	return result
}

func (a *checkpointFlowAnalyzer) analyzeFor(
	stmt *ast.ForStmt,
	paths []checkpointFlow,
	parent *checkpointLexicalScope,
) checkpointStatementFlow {
	scope := newCheckpointLexicalScope(parent)
	if stmt.Init != nil {
		paths = a.analyzeStatement(stmt.Init, paths, scope).next
	}
	if stmt.Cond != nil {
		a.findTerminalsOnPaths(stmt.Cond, paths, scope)
	}
	var exits []checkpointFlow
	if stmt.Cond != nil {
		exits = cloneCheckpointFlows(paths)
	}
	body := a.analyzeBlock(stmt.Body, cloneCheckpointFlows(paths), scope)
	iterationEnds := append(body.next, body.continues...)
	if stmt.Post != nil {
		iterationEnds = a.analyzeStatement(stmt.Post, iterationEnds, scope).next
	}
	exits = append(exits, body.breaks...)
	if stmt.Cond != nil {
		exits = append(exits, iterationEnds...)
	}
	result := checkpointStatementFlow{next: compactCheckpointFlows(exits)}
	removeCheckpointAssignments(&result, scope.declaredBindings())
	return result
}

func (a *checkpointFlowAnalyzer) analyzeRange(
	stmt *ast.RangeStmt,
	paths []checkpointFlow,
	parent *checkpointLexicalScope,
) checkpointStatementFlow {
	a.findTerminalsOnPaths(stmt.X, paths, parent)
	exits := cloneCheckpointFlows(paths)
	scope := newCheckpointLexicalScope(parent)
	bindings := checkpointExpressionBindings([]ast.Expr{stmt.Key, stmt.Value}, stmt.Tok, scope)
	bodyPaths := invalidateCheckpointBindings(cloneCheckpointFlows(paths), bindings)
	body := a.analyzeBlock(stmt.Body, bodyPaths, scope)
	exits = append(exits, body.breaks...)
	exits = append(exits, body.next...)
	exits = append(exits, body.continues...)
	result := checkpointStatementFlow{next: compactCheckpointFlows(exits)}
	removeCheckpointAssignments(&result, scope.declaredBindings())
	return result
}

func (a *checkpointFlowAnalyzer) analyzeSwitch(
	stmt *ast.SwitchStmt,
	paths []checkpointFlow,
	parent *checkpointLexicalScope,
) checkpointStatementFlow {
	scope := newCheckpointLexicalScope(parent)
	if stmt.Init != nil {
		paths = a.analyzeStatement(stmt.Init, paths, scope).next
	}
	if stmt.Tag != nil {
		a.findTerminalsOnPaths(stmt.Tag, paths, scope)
	}
	result := a.analyzeCaseClauses(stmt.Body, paths, scope, nil)
	removeCheckpointAssignments(&result, scope.declaredBindings())
	return result
}

func (a *checkpointFlowAnalyzer) analyzeTypeSwitch(
	stmt *ast.TypeSwitchStmt,
	paths []checkpointFlow,
	parent *checkpointLexicalScope,
) checkpointStatementFlow {
	scope := newCheckpointLexicalScope(parent)
	if stmt.Init != nil {
		paths = a.analyzeStatement(stmt.Init, paths, scope).next
	}
	a.findTerminalsOnPaths(stmt.Assign, paths, scope)
	result := a.analyzeCaseClauses(stmt.Body, paths, scope, typeSwitchIdentifiers(stmt.Assign))
	removeCheckpointAssignments(&result, scope.declaredBindings())
	return result
}

func (a *checkpointFlowAnalyzer) analyzeCaseClauses(
	body *ast.BlockStmt,
	paths []checkpointFlow,
	parent *checkpointLexicalScope,
	clauseDeclarations []*ast.Ident,
) checkpointStatementFlow {
	result := checkpointStatementFlow{}
	hasDefault := false
	for _, item := range body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			continue
		}
		hasDefault = hasDefault || len(clause.List) == 0
		clausePaths := cloneCheckpointFlows(paths)
		clauseScope := newCheckpointLexicalScope(parent)
		for _, identifier := range clauseDeclarations {
			clauseScope.declare(identifier)
		}
		for _, expr := range clause.List {
			a.findTerminalsOnPaths(expr, clausePaths, parent)
		}
		clauseFlow := a.analyzeBlockInScope(&ast.BlockStmt{List: clause.Body}, clausePaths, clauseScope)
		result.next = append(result.next, clauseFlow.next...)
		result.next = append(result.next, clauseFlow.breaks...)
		result.continues = append(result.continues, clauseFlow.continues...)
	}
	if !hasDefault {
		result.next = append(result.next, cloneCheckpointFlows(paths)...)
	}
	result.next = compactCheckpointFlows(result.next)
	result.continues = compactCheckpointFlows(result.continues)
	return result
}

func (a *checkpointFlowAnalyzer) analyzeSelect(
	stmt *ast.SelectStmt,
	paths []checkpointFlow,
	parent *checkpointLexicalScope,
) checkpointStatementFlow {
	result := checkpointStatementFlow{}
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok {
			continue
		}
		clausePaths := cloneCheckpointFlows(paths)
		clauseScope := newCheckpointLexicalScope(parent)
		if clause.Comm != nil {
			clausePaths = a.analyzeStatement(clause.Comm, clausePaths, clauseScope).next
		}
		clauseFlow := a.analyzeBlockInScope(&ast.BlockStmt{List: clause.Body}, clausePaths, clauseScope)
		result.next = append(result.next, clauseFlow.next...)
		result.next = append(result.next, clauseFlow.breaks...)
		result.continues = append(result.continues, clauseFlow.continues...)
	}
	result.next = compactCheckpointFlows(result.next)
	result.continues = compactCheckpointFlows(result.continues)
	return result
}

func (a *checkpointFlowAnalyzer) assign(
	assign *ast.AssignStmt,
	paths []checkpointFlow,
	scope *checkpointLexicalScope,
) []checkpointFlow {
	bindings := checkpointExpressionBindings(assign.Lhs, assign.Tok, scope)
	result := make([]checkpointFlow, 0, len(paths))
	for _, path := range paths {
		a.findTerminals(assign, path.failures, scope)
		result = append(result, flowWithAssignment(copyCheckpointFlow(path), assign, bindings))
	}
	return compactCheckpointFlows(result)
}

func (a *checkpointFlowAnalyzer) findTerminalsOnPaths(
	node ast.Node,
	paths []checkpointFlow,
	scope *checkpointLexicalScope,
) {
	for _, path := range paths {
		a.findTerminals(node, path.failures, scope)
	}
}

func (a *checkpointFlowAnalyzer) findTerminals(
	node ast.Node,
	failures []failedCheckpoint,
	scope *checkpointLexicalScope,
) {
	ast.Inspect(node, func(child ast.Node) bool {
		if closure, nested := child.(*ast.FuncLit); nested {
			if !a.analyzedClosures[closure] {
				a.analyzedClosures[closure] = true
				a.analyzeCallable(closure.Body, scope, closure.Type.Params, closure.Type.Results)
			}
			return false
		}
		call, ok := child.(*ast.CallExpr)
		if !ok {
			return true
		}
		receiver, method, ok := selectedCall(call, terminalAfterCheckpointTerminalMethods)
		if !ok {
			return true
		}
		terminal := terminalCall{call: call, receiver: receiver, method: method}
		for _, failure := range failures {
			if failure.receiver != terminal.receiver || a.reported[failure.ifStmt] {
				continue
			}
			a.findings = append(a.findings, checkpointFinding{checkpoint: failure, terminal: terminal})
			a.reported[failure.ifStmt] = true
		}
		return true
	})
}

func flowWithAssignment(
	flow checkpointFlow,
	assign *ast.AssignStmt,
	bindings []checkpointBindingID,
) checkpointFlow {
	if assign.Tok != token.DEFINE && assign.Tok != token.ASSIGN {
		return flow
	}
	for _, binding := range bindings {
		delete(flow.assignments, binding)
	}
	if len(assign.Rhs) != 1 {
		return flow
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return flow
	}
	receiver, method, ok := selectedCall(call, terminalAfterCheckpointMethods)
	if !ok {
		return flow
	}
	checkpoint := checkpointAssignment{receiver: receiver, method: method}
	for _, binding := range bindings {
		flow.assignments[binding] = checkpoint
	}
	return flow
}

func conditionCheckpointPaths(
	ifStmt *ast.IfStmt,
	paths []checkpointFlow,
	scope *checkpointLexicalScope,
) ([]checkpointFlow, []checkpointFlow) {
	var truePaths []checkpointFlow
	var falsePaths []checkpointFlow
	for _, path := range paths {
		var errBinding checkpointBindingID
		var checkpoint checkpointAssignment
		for _, binding := range nilComparedBindings(ifStmt.Cond, scope) {
			if assignment, ok := path.assignments[binding]; ok {
				errBinding = binding
				checkpoint = assignment
				break
			}
		}
		if errBinding == 0 {
			truePaths = append(truePaths, copyCheckpointFlow(path))
			falsePaths = append(falsePaths, copyCheckpointFlow(path))
			continue
		}

		resolvedPath := copyCheckpointFlow(path)
		delete(resolvedPath.assignments, errBinding)
		successTruth := conditionTruthForCheckpoint(ifStmt.Cond, errBinding, false, scope)
		if successTruth&conditionTrue != 0 {
			truePaths = append(truePaths, copyCheckpointFlow(resolvedPath))
		}
		if successTruth&conditionFalse != 0 {
			falsePaths = append(falsePaths, copyCheckpointFlow(resolvedPath))
		}

		failure := failedCheckpoint{
			ifStmt:   ifStmt,
			receiver: checkpoint.receiver,
			method:   checkpoint.method,
		}
		resolvedPath.failures = appendCheckpointFailure(resolvedPath.failures, failure)
		failureTruth := conditionTruthForCheckpoint(ifStmt.Cond, errBinding, true, scope)
		if failureTruth&conditionTrue != 0 {
			truePaths = append(truePaths, copyCheckpointFlow(resolvedPath))
		}
		if failureTruth&conditionFalse != 0 {
			falsePaths = append(falsePaths, copyCheckpointFlow(resolvedPath))
		}
	}
	return compactCheckpointFlows(truePaths), compactCheckpointFlows(falsePaths)
}

const (
	conditionFalse uint8 = 1 << iota
	conditionTrue
)

func conditionTruthForCheckpoint(
	expr ast.Expr,
	errBinding checkpointBindingID,
	failed bool,
	scope *checkpointLexicalScope,
) uint8 {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return conditionTruthForCheckpoint(node.X, errBinding, failed, scope)
	case *ast.UnaryExpr:
		if node.Op != token.NOT {
			return conditionFalse | conditionTrue
		}
		truth := conditionTruthForCheckpoint(node.X, errBinding, failed, scope)
		return ((truth & conditionFalse) << 1) | ((truth & conditionTrue) >> 1)
	case *ast.BinaryExpr:
		if truth, ok := nilComparisonTruthForCheckpoint(node, errBinding, failed, scope); ok {
			return truth
		}
		if node.Op == token.LAND || node.Op == token.LOR {
			return combineConditionTruth(
				conditionTruthForCheckpoint(node.X, errBinding, failed, scope),
				conditionTruthForCheckpoint(node.Y, errBinding, failed, scope),
				node.Op,
			)
		}
	}
	return conditionFalse | conditionTrue
}

func nilComparisonTruthForCheckpoint(
	expr *ast.BinaryExpr,
	errBinding checkpointBindingID,
	failed bool,
	scope *checkpointLexicalScope,
) (uint8, bool) {
	if expr.Op != token.EQL && expr.Op != token.NEQ {
		return 0, false
	}
	for _, pair := range [][2]ast.Expr{{expr.X, expr.Y}, {expr.Y, expr.X}} {
		ident, ok := pair[0].(*ast.Ident)
		binding, resolved := checkpointIdentifierBinding(ident, scope)
		if !ok || !resolved || binding != errBinding || !isNilIdent(pair[1]) {
			continue
		}
		if expr.Op == token.NEQ && failed || expr.Op == token.EQL && !failed {
			return conditionTrue, true
		}
		return conditionFalse, true
	}
	return 0, false
}

func combineConditionTruth(left, right uint8, operator token.Token) uint8 {
	var result uint8
	for _, leftValue := range []uint8{conditionFalse, conditionTrue} {
		if left&leftValue == 0 {
			continue
		}
		for _, rightValue := range []uint8{conditionFalse, conditionTrue} {
			if right&rightValue == 0 {
				continue
			}
			leftTrue := leftValue == conditionTrue
			rightTrue := rightValue == conditionTrue
			if operator == token.LAND && leftTrue && rightTrue || operator == token.LOR && (leftTrue || rightTrue) {
				result |= conditionTrue
			} else {
				result |= conditionFalse
			}
		}
	}
	return result
}

func selectedCall(call *ast.CallExpr, methods map[string]struct{}) (string, string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	_, ok = methods[selector.Sel.Name]
	if !ok {
		return "", "", false
	}
	receiver, ok := checkpointReceiver(selector.X)
	if !ok {
		return "", "", false
	}
	return receiver, selector.Sel.Name, true
}

func checkpointReceiver(expr ast.Expr) (string, bool) {
	switch node := expr.(type) {
	case *ast.Ident:
		return node.Name, true
	case *ast.SelectorExpr:
		parent, ok := checkpointReceiver(node.X)
		if !ok {
			return "", false
		}
		return parent + "." + node.Sel.Name, true
	case *ast.ParenExpr:
		return checkpointReceiver(node.X)
	default:
		return "", false
	}
}

func nilComparedBindings(expr ast.Expr, scope *checkpointLexicalScope) []checkpointBindingID {
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return nilComparedBindings(paren.X, scope)
	}
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return nil
	}
	if binary.Op == token.LAND || binary.Op == token.LOR {
		return append(nilComparedBindings(binary.X, scope), nilComparedBindings(binary.Y, scope)...)
	}
	if binary.Op != token.EQL && binary.Op != token.NEQ {
		return nil
	}
	for _, pair := range [][2]ast.Expr{{binary.X, binary.Y}, {binary.Y, binary.X}} {
		ident, ok := pair[0].(*ast.Ident)
		binding, resolved := checkpointIdentifierBinding(ident, scope)
		if ok && resolved && isNilIdent(pair[1]) {
			return []checkpointBindingID{binding}
		}
	}
	return nil
}

func copyCheckpointFlow(flow checkpointFlow) checkpointFlow {
	copyFlow := checkpointFlow{
		assignments: make(map[checkpointBindingID]checkpointAssignment, len(flow.assignments)),
		failures:    append([]failedCheckpoint(nil), flow.failures...),
	}
	for object, assignment := range flow.assignments {
		copyFlow.assignments[object] = assignment
	}
	return copyFlow
}

func cloneCheckpointFlows(flows []checkpointFlow) []checkpointFlow {
	clones := make([]checkpointFlow, 0, len(flows))
	for _, flow := range flows {
		clones = append(clones, copyCheckpointFlow(flow))
	}
	return clones
}

func removeCheckpointAssignments(flow *checkpointStatementFlow, bindings []checkpointBindingID) {
	for _, paths := range [][]checkpointFlow{flow.next, flow.breaks, flow.continues} {
		for i := range paths {
			for _, binding := range bindings {
				delete(paths[i].assignments, binding)
			}
		}
	}
}

func invalidateCheckpointBindings(paths []checkpointFlow, bindings []checkpointBindingID) []checkpointFlow {
	for i := range paths {
		for _, binding := range bindings {
			delete(paths[i].assignments, binding)
		}
	}
	return paths
}

func checkpointExpressionBindings(
	expressions []ast.Expr,
	operator token.Token,
	scope *checkpointLexicalScope,
) []checkpointBindingID {
	bindings := make([]checkpointBindingID, 0, len(expressions))
	for _, expression := range expressions {
		identifier, ok := expression.(*ast.Ident)
		if !ok || identifier.Name == "_" {
			continue
		}

		var binding checkpointBindingID
		var resolved bool
		if operator == token.DEFINE {
			binding, resolved = scope.bindings[identifier.Name]
			if !resolved {
				binding = scope.declare(identifier)
			}
		} else {
			binding, resolved = scope.lookup(identifier.Name)
		}
		if resolved || operator == token.DEFINE {
			bindings = append(bindings, binding)
		}
	}
	return bindings
}

func checkpointIdentifierBinding(
	identifier *ast.Ident,
	scope *checkpointLexicalScope,
) (checkpointBindingID, bool) {
	if identifier == nil || identifier.Name == "_" {
		return 0, false
	}
	return scope.lookup(identifier.Name)
}

func checkpointFileScope(file *ast.File) *checkpointLexicalScope {
	scope := newCheckpointLexicalScope(nil)
	for _, declaration := range file.Decls {
		declareCheckpointDeclaration(scope, declaration)
	}
	return scope
}

func declareCheckpointDeclaration(scope *checkpointLexicalScope, declaration ast.Decl) {
	switch node := declaration.(type) {
	case *ast.GenDecl:
		for _, spec := range node.Specs {
			switch item := spec.(type) {
			case *ast.ValueSpec:
				for _, identifier := range item.Names {
					scope.declare(identifier)
				}
			case *ast.TypeSpec:
				scope.declare(item.Name)
			}
		}
	case *ast.FuncDecl:
		scope.declare(node.Name)
	}
}

func declareCheckpointFields(scope *checkpointLexicalScope, fields *ast.FieldList) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		for _, identifier := range field.Names {
			scope.declare(identifier)
		}
	}
}

func typeSwitchIdentifiers(statement ast.Stmt) []*ast.Ident {
	assign, ok := statement.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE {
		return nil
	}
	identifiers := make([]*ast.Ident, 0, len(assign.Lhs))
	for _, expression := range assign.Lhs {
		if identifier, ok := expression.(*ast.Ident); ok && identifier.Name != "_" {
			identifiers = append(identifiers, identifier)
		}
	}
	return identifiers
}

func appendCheckpointFailure(current []failedCheckpoint, addition failedCheckpoint) []failedCheckpoint {
	for _, checkpoint := range current {
		if checkpoint.ifStmt == addition.ifStmt {
			return current
		}
	}
	return append(current, addition)
}

func compactCheckpointFlows(flows []checkpointFlow) []checkpointFlow {
	compacted := make([]checkpointFlow, 0, len(flows))
	for _, flow := range flows {
		duplicate := false
		for _, existing := range compacted {
			if equalCheckpointFlow(existing, flow) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			compacted = append(compacted, flow)
		}
	}
	return compacted
}

func equalCheckpointFlow(left, right checkpointFlow) bool {
	if len(left.assignments) != len(right.assignments) || len(left.failures) != len(right.failures) {
		return false
	}
	for object, assignment := range left.assignments {
		if right.assignments[object] != assignment {
			return false
		}
	}
	for i, failure := range left.failures {
		if right.failures[i].ifStmt != failure.ifStmt {
			return false
		}
	}
	return true
}

func isPanicStatement(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "panic"
}
