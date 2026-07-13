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

type checkpointFlow struct {
	assignments map[string]checkpointAssignment
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
	findings []checkpointFinding
	reported map[*ast.IfStmt]bool
}

// AnalyzeFile checks each production Go function independently.
func (r *TerminalAfterFailedCheckpointRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		for _, finding := range checkpointFindings(fn.Body) {
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

func checkpointFindings(body *ast.BlockStmt) []checkpointFinding {
	analyzer := &checkpointFlowAnalyzer{reported: make(map[*ast.IfStmt]bool)}
	analyzer.analyzeCallable(body)
	return analyzer.findings
}

func (a *checkpointFlowAnalyzer) analyzeCallable(body *ast.BlockStmt) {
	initial := checkpointFlow{assignments: make(map[string]checkpointAssignment)}
	a.analyzeBlock(body, []checkpointFlow{initial})

	var closures []*ast.FuncLit
	ast.Inspect(body, func(node ast.Node) bool {
		closure, ok := node.(*ast.FuncLit)
		if !ok {
			return true
		}
		closures = append(closures, closure)
		return false
	})
	for _, closure := range closures {
		a.analyzeCallable(closure.Body)
	}
}

func (a *checkpointFlowAnalyzer) analyzeBlock(block *ast.BlockStmt, paths []checkpointFlow) checkpointStatementFlow {
	if block == nil {
		return checkpointStatementFlow{next: paths}
	}
	flow := checkpointStatementFlow{next: paths}
	for _, stmt := range block.List {
		if len(flow.next) == 0 {
			break
		}
		statementFlow := a.analyzeStatement(stmt, flow.next)
		flow.breaks = append(flow.breaks, statementFlow.breaks...)
		flow.continues = append(flow.continues, statementFlow.continues...)
		flow.next = statementFlow.next
	}
	flow.next = compactCheckpointFlows(flow.next)
	flow.breaks = compactCheckpointFlows(flow.breaks)
	flow.continues = compactCheckpointFlows(flow.continues)
	return flow
}

func (a *checkpointFlowAnalyzer) analyzeStatement(stmt ast.Stmt, paths []checkpointFlow) checkpointStatementFlow {
	switch node := stmt.(type) {
	case *ast.AssignStmt:
		return checkpointStatementFlow{next: a.assign(node, paths)}
	case *ast.BlockStmt:
		return a.analyzeBlock(node, cloneCheckpointFlows(paths))
	case *ast.ReturnStmt:
		a.findTerminalsOnPaths(node, paths)
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
		return a.analyzeIf(node, paths)
	case *ast.ForStmt:
		return a.analyzeFor(node, paths)
	case *ast.RangeStmt:
		return a.analyzeRange(node, paths)
	case *ast.SwitchStmt:
		return a.analyzeSwitch(node, paths)
	case *ast.TypeSwitchStmt:
		return a.analyzeTypeSwitch(node, paths)
	case *ast.SelectStmt:
		return a.analyzeSelect(node, paths)
	case *ast.LabeledStmt:
		return a.analyzeStatement(node.Stmt, paths)
	default:
		a.findTerminalsOnPaths(node, paths)
		if isPanicStatement(node) {
			return checkpointStatementFlow{}
		}
		return checkpointStatementFlow{next: paths}
	}
}

func (a *checkpointFlowAnalyzer) analyzeIf(ifStmt *ast.IfStmt, paths []checkpointFlow) checkpointStatementFlow {
	result := checkpointStatementFlow{}
	for _, path := range paths {
		conditionPaths := []checkpointFlow{copyCheckpointFlow(path)}
		if ifStmt.Init != nil {
			conditionPaths = a.analyzeStatement(ifStmt.Init, conditionPaths).next
		}
		a.findTerminalsOnPaths(ifStmt.Cond, conditionPaths)

		truePaths, falsePaths := conditionCheckpointPaths(ifStmt, conditionPaths)
		body := a.analyzeBlock(ifStmt.Body, truePaths)
		otherwise := checkpointStatementFlow{next: falsePaths}
		if ifStmt.Else != nil {
			otherwise = a.analyzeStatement(ifStmt.Else, falsePaths)
		}
		scopedNames := checkpointScopedNames(ifStmt.Init)
		restoreCheckpointAssignments(&body, path.assignments, scopedNames)
		restoreCheckpointAssignments(&otherwise, path.assignments, scopedNames)

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
	return result
}

func (a *checkpointFlowAnalyzer) analyzeFor(stmt *ast.ForStmt, paths []checkpointFlow) checkpointStatementFlow {
	if stmt.Init != nil {
		paths = a.analyzeStatement(stmt.Init, paths).next
	}
	if stmt.Cond != nil {
		a.findTerminalsOnPaths(stmt.Cond, paths)
	}
	var exits []checkpointFlow
	if stmt.Cond != nil {
		exits = cloneCheckpointFlows(paths)
	}
	body := a.analyzeBlock(stmt.Body, cloneCheckpointFlows(paths))
	iterationEnds := append(body.next, body.continues...)
	if stmt.Post != nil {
		iterationEnds = a.analyzeStatement(stmt.Post, iterationEnds).next
	}
	exits = append(exits, body.breaks...)
	if stmt.Cond != nil {
		exits = append(exits, iterationEnds...)
	}
	return checkpointStatementFlow{next: compactCheckpointFlows(exits)}
}

func (a *checkpointFlowAnalyzer) analyzeRange(stmt *ast.RangeStmt, paths []checkpointFlow) checkpointStatementFlow {
	a.findTerminalsOnPaths(stmt.X, paths)
	exits := cloneCheckpointFlows(paths)
	body := a.analyzeBlock(stmt.Body, cloneCheckpointFlows(paths))
	exits = append(exits, body.breaks...)
	exits = append(exits, body.next...)
	exits = append(exits, body.continues...)
	return checkpointStatementFlow{next: compactCheckpointFlows(exits)}
}

func (a *checkpointFlowAnalyzer) analyzeSwitch(stmt *ast.SwitchStmt, paths []checkpointFlow) checkpointStatementFlow {
	if stmt.Init != nil {
		paths = a.analyzeStatement(stmt.Init, paths).next
	}
	if stmt.Tag != nil {
		a.findTerminalsOnPaths(stmt.Tag, paths)
	}
	return a.analyzeCaseClauses(stmt.Body, paths)
}

func (a *checkpointFlowAnalyzer) analyzeTypeSwitch(stmt *ast.TypeSwitchStmt, paths []checkpointFlow) checkpointStatementFlow {
	if stmt.Init != nil {
		paths = a.analyzeStatement(stmt.Init, paths).next
	}
	paths = a.analyzeStatement(stmt.Assign, paths).next
	return a.analyzeCaseClauses(stmt.Body, paths)
}

func (a *checkpointFlowAnalyzer) analyzeCaseClauses(body *ast.BlockStmt, paths []checkpointFlow) checkpointStatementFlow {
	result := checkpointStatementFlow{}
	hasDefault := false
	for _, item := range body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			continue
		}
		hasDefault = hasDefault || len(clause.List) == 0
		clausePaths := cloneCheckpointFlows(paths)
		for _, expr := range clause.List {
			a.findTerminalsOnPaths(expr, clausePaths)
		}
		clauseFlow := a.analyzeBlock(&ast.BlockStmt{List: clause.Body}, clausePaths)
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

func (a *checkpointFlowAnalyzer) analyzeSelect(stmt *ast.SelectStmt, paths []checkpointFlow) checkpointStatementFlow {
	result := checkpointStatementFlow{}
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok {
			continue
		}
		clausePaths := cloneCheckpointFlows(paths)
		if clause.Comm != nil {
			clausePaths = a.analyzeStatement(clause.Comm, clausePaths).next
		}
		clauseFlow := a.analyzeBlock(&ast.BlockStmt{List: clause.Body}, clausePaths)
		result.next = append(result.next, clauseFlow.next...)
		result.next = append(result.next, clauseFlow.breaks...)
		result.continues = append(result.continues, clauseFlow.continues...)
	}
	result.next = compactCheckpointFlows(result.next)
	result.continues = compactCheckpointFlows(result.continues)
	return result
}

func (a *checkpointFlowAnalyzer) assign(assign *ast.AssignStmt, paths []checkpointFlow) []checkpointFlow {
	result := make([]checkpointFlow, 0, len(paths))
	for _, path := range paths {
		a.findTerminals(assign, path.failures)
		result = append(result, flowWithAssignment(copyCheckpointFlow(path), assign))
	}
	return compactCheckpointFlows(result)
}

func (a *checkpointFlowAnalyzer) findTerminalsOnPaths(node ast.Node, paths []checkpointFlow) {
	for _, path := range paths {
		a.findTerminals(node, path.failures)
	}
}

func (a *checkpointFlowAnalyzer) findTerminals(node ast.Node, failures []failedCheckpoint) {
	ast.Inspect(node, func(child ast.Node) bool {
		if _, nested := child.(*ast.FuncLit); nested {
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

func flowWithAssignment(flow checkpointFlow, assign *ast.AssignStmt) checkpointFlow {
	if assign.Tok != token.DEFINE && assign.Tok != token.ASSIGN {
		return flow
	}
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok {
			delete(flow.assignments, ident.Name)
		}
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
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
			flow.assignments[ident.Name] = checkpoint
		}
	}
	return flow
}

func conditionCheckpointPaths(ifStmt *ast.IfStmt, paths []checkpointFlow) ([]checkpointFlow, []checkpointFlow) {
	var truePaths []checkpointFlow
	var falsePaths []checkpointFlow
	for _, path := range paths {
		var errName string
		var checkpoint checkpointAssignment
		for _, name := range notNilComparedNames(ifStmt.Cond) {
			if assignment, ok := path.assignments[name]; ok {
				errName = name
				checkpoint = assignment
				break
			}
		}
		if errName == "" {
			truePaths = append(truePaths, copyCheckpointFlow(path))
			falsePaths = append(falsePaths, copyCheckpointFlow(path))
			continue
		}

		resolvedPath := copyCheckpointFlow(path)
		delete(resolvedPath.assignments, errName)
		successTruth := conditionTruthForCheckpoint(ifStmt.Cond, errName, false)
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
		failureTruth := conditionTruthForCheckpoint(ifStmt.Cond, errName, true)
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

func conditionTruthForCheckpoint(expr ast.Expr, errName string, failed bool) uint8 {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return conditionTruthForCheckpoint(node.X, errName, failed)
	case *ast.UnaryExpr:
		if node.Op != token.NOT {
			return conditionFalse | conditionTrue
		}
		truth := conditionTruthForCheckpoint(node.X, errName, failed)
		return ((truth & conditionFalse) << 1) | ((truth & conditionTrue) >> 1)
	case *ast.BinaryExpr:
		if truth, ok := nilComparisonTruthForCheckpoint(node, errName, failed); ok {
			return truth
		}
		if node.Op == token.LAND || node.Op == token.LOR {
			return combineConditionTruth(
				conditionTruthForCheckpoint(node.X, errName, failed),
				conditionTruthForCheckpoint(node.Y, errName, failed),
				node.Op,
			)
		}
	}
	return conditionFalse | conditionTrue
}

func nilComparisonTruthForCheckpoint(expr *ast.BinaryExpr, errName string, failed bool) (uint8, bool) {
	if expr.Op != token.EQL && expr.Op != token.NEQ {
		return 0, false
	}
	for _, pair := range [][2]ast.Expr{{expr.X, expr.Y}, {expr.Y, expr.X}} {
		ident, ok := pair[0].(*ast.Ident)
		if !ok || ident.Name != errName || !isNilIdent(pair[1]) {
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

func notNilComparedNames(expr ast.Expr) []string {
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return notNilComparedNames(paren.X)
	}
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return nil
	}
	if binary.Op == token.LAND || binary.Op == token.LOR {
		return append(notNilComparedNames(binary.X), notNilComparedNames(binary.Y)...)
	}
	if binary.Op != token.NEQ {
		return nil
	}
	for _, pair := range [][2]ast.Expr{{binary.X, binary.Y}, {binary.Y, binary.X}} {
		ident, ok := pair[0].(*ast.Ident)
		if ok && isNilIdent(pair[1]) {
			return []string{ident.Name}
		}
	}
	return nil
}

func copyCheckpointFlow(flow checkpointFlow) checkpointFlow {
	copyFlow := checkpointFlow{
		assignments: make(map[string]checkpointAssignment, len(flow.assignments)),
		failures:    append([]failedCheckpoint(nil), flow.failures...),
	}
	for name, assignment := range flow.assignments {
		copyFlow.assignments[name] = assignment
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

func checkpointScopedNames(stmt ast.Stmt) []string {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE {
		return nil
	}
	var names []string
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
			names = append(names, ident.Name)
		}
	}
	return names
}

func restoreCheckpointAssignments(flow *checkpointStatementFlow, original map[string]checkpointAssignment, names []string) {
	for _, paths := range [][]checkpointFlow{flow.next, flow.breaks, flow.continues} {
		for i := range paths {
			for _, name := range names {
				delete(paths[i].assignments, name)
				if assignment, ok := original[name]; ok {
					paths[i].assignments[name] = assignment
				}
			}
		}
	}
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
	for name, assignment := range left.assignments {
		if right.assignments[name] != assignment {
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
