package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

var providerCommandMethods = map[string]bool{
	"SendTransaction":   true,
	"ExecutePayment":    true,
	"SubmitPayment":     true,
	"CreatePayout":      true,
	"SendPayout":        true,
	"TransferFunds":     true,
	"CancelTransaction": true,
	"CancelPayment":     true,
	"RefundPayment":     true,
	"CreateRefund":      true,
	"SendRefund":        true,
}

var durableIntentActions = []string{"persist", "save", "record", "create", "enqueue", "claim"}
var durableIntentSubjects = []string{"request", "intent", "attempt", "outbox", "command"}
var providerReceiverMarkers = []string{"paywho", "provider", "payment", "payout", "bank", "remit"}
var stateReceiverMarkers = []string{"repo", "store", "db", "outbox", "ledger"}
var statePersistencePrefixes = []string{"update", "save", "persist", "record", "create"}

func init() {
	rules.Register(NewProviderCommandBeforeIntentPersistRule())
}

// ProviderCommandBeforeIntentPersistRule detects financial provider commands
// executed before their durable request or intent is recorded.
type ProviderCommandBeforeIntentPersistRule struct {
	*rules.BaseRule
}

// NewProviderCommandBeforeIntentPersistRule creates the rule.
func NewProviderCommandBeforeIntentPersistRule() *ProviderCommandBeforeIntentPersistRule {
	return &ProviderCommandBeforeIntentPersistRule{BaseRule: rules.NewBaseRule(
		"provider-command-before-intent-persist",
		"patterns",
		"Detects financial provider commands executed before durable intent persistence",
		core.SeverityCritical,
	)}
}

// AnalyzeFile checks command and persistence ordering within each function.
func (r *ProviderCommandBeforeIntentPersistRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	for _, root := range providerAnalysisRoots(ctx.GoAST) {
		for _, command := range analyzeProviderCommandFlow(root.body) {
			line := ctx.GoFileSet.Position(command.call.Pos()).Line
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"financial provider command '"+command.method+"' executes before durable request/intent persistence")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Persist a request, intent, attempt, outbox entry, or command before invoking the provider")
			v.WithContext("pattern", "provider_command_before_intent_persist")
			v.WithContext("function", root.name)
			violations = append(violations, v)
		}
	}
	return violations
}

type providerAnalysisRoot struct {
	body *ast.BlockStmt
	name string
}

func providerAnalysisRoots(file *ast.File) []providerAnalysisRoot {
	var roots []providerAnalysisRoot
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		roots = append(roots, providerAnalysisRoot{body: fn.Body, name: fn.Name.Name})
	}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.FuncLit)
		if ok && literal.Body != nil {
			roots = append(roots, providerAnalysisRoot{body: literal.Body, name: "(anonymous)"})
		}
		return true
	})
	return roots
}

type providerCommandCall struct {
	call   *ast.CallExpr
	method string
}

type durableIntentEvidence struct {
	method string
	entity string
	owner  string
}

type providerFlowState struct {
	durableObserved bool
	durableEvidence []durableIntentEvidence
	pending         []providerCommandCall
}

type providerFlowAnalyzer struct {
	detected []providerCommandCall
	seen     map[*ast.CallExpr]bool
}

func analyzeProviderCommandFlow(body *ast.BlockStmt) []providerCommandCall {
	analyzer := providerFlowAnalyzer{seen: make(map[*ast.CallExpr]bool)}
	analyzer.block(body, []providerFlowState{{}})
	return analyzer.detected
}

func (a *providerFlowAnalyzer) block(block *ast.BlockStmt, states []providerFlowState) []providerFlowState {
	if block == nil {
		return states
	}
	for _, stmt := range block.List {
		if len(states) == 0 {
			break
		}
		if _, stopsBlock := stmt.(*ast.BranchStmt); stopsBlock {
			break
		}
		states = a.statement(stmt, states)
	}
	return compactProviderFlowStates(states)
}

func (a *providerFlowAnalyzer) statement(stmt ast.Stmt, states []providerFlowState) []providerFlowState {
	switch node := stmt.(type) {
	case *ast.BlockStmt:
		return a.block(node, states)
	case *ast.ExprStmt:
		return a.expression(node.X, states)
	case *ast.AssignStmt:
		return a.expressions(node.Rhs, states)
	case *ast.DeclStmt:
		return a.declaration(node.Decl, states)
	case *ast.SendStmt:
		states = a.expression(node.Chan, states)
		return a.expression(node.Value, states)
	case *ast.IncDecStmt:
		return a.expression(node.X, states)
	case *ast.ReturnStmt:
		a.expressions(node.Results, states)
		return nil
	case *ast.IfStmt:
		return a.ifStatement(node, states)
	case *ast.ForStmt:
		return a.forStatement(node, states)
	case *ast.RangeStmt:
		return a.rangeStatement(node, states)
	case *ast.SwitchStmt:
		return a.switchStatement(node, states)
	case *ast.TypeSwitchStmt:
		return a.typeSwitchStatement(node, states)
	case *ast.SelectStmt:
		return a.selectStatement(node, states)
	case *ast.GoStmt:
		states = a.callOperands(node.Call, states)
		method, command := matchingSelectorCall(node.Call, providerCommandMethods, providerReceiverMarkers)
		if !command {
			return states
		}
		return compactProviderFlowStates(a.recordProviderCommand(node.Call, method, providerCallEntity(node.Call), providerCallEntityOwner(node.Call), states))
	case *ast.DeferStmt:
		return a.callOperands(node.Call, states)
	case *ast.LabeledStmt:
		return a.statement(node.Stmt, states)
	default:
		return states
	}
}

func (a *providerFlowAnalyzer) declaration(decl ast.Decl, states []providerFlowState) []providerFlowState {
	gen, ok := decl.(*ast.GenDecl)
	if !ok {
		return states
	}
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if ok {
			states = a.expressions(value.Values, states)
		}
	}
	return states
}

func (a *providerFlowAnalyzer) ifStatement(stmt *ast.IfStmt, states []providerFlowState) []providerFlowState {
	if stmt.Init != nil {
		states = a.statement(stmt.Init, states)
	}
	trueStates, falseStates := a.condition(stmt.Cond, states)
	branches := a.block(stmt.Body, trueStates)
	if stmt.Else == nil {
		branches = append(branches, falseStates...)
	} else {
		branches = append(branches, a.statement(stmt.Else, falseStates)...)
	}
	return compactProviderFlowStates(branches)
}

func (a *providerFlowAnalyzer) condition(
	expr ast.Expr,
	states []providerFlowState,
) (trueStates, falseStates []providerFlowState) {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return a.condition(node.X, states)
	case *ast.UnaryExpr:
		if node.Op == token.NOT {
			falseStates, trueStates = a.condition(node.X, states)
			return trueStates, falseStates
		}
	case *ast.BinaryExpr:
		switch node.Op {
		case token.LAND:
			leftTrue, leftFalse := a.condition(node.X, states)
			rightTrue, rightFalse := a.condition(node.Y, leftTrue)
			return rightTrue, compactProviderFlowStates(append(leftFalse, rightFalse...))
		case token.LOR:
			leftTrue, leftFalse := a.condition(node.X, states)
			rightTrue, rightFalse := a.condition(node.Y, leftFalse)
			return compactProviderFlowStates(append(leftTrue, rightTrue...)), rightFalse
		}
	}

	evaluated := a.expression(expr, states)
	return cloneProviderFlowStates(evaluated), cloneProviderFlowStates(evaluated)
}

func (a *providerFlowAnalyzer) forStatement(stmt *ast.ForStmt, states []providerFlowState) []providerFlowState {
	if stmt.Init != nil {
		states = a.statement(stmt.Init, states)
	}
	if stmt.Cond != nil {
		states = a.expression(stmt.Cond, states)
	}
	exits := cloneProviderFlowStates(states)
	oneIteration := a.block(stmt.Body, cloneProviderFlowStates(states))
	if stmt.Post != nil {
		oneIteration = a.statement(stmt.Post, oneIteration)
	}
	return compactProviderFlowStates(append(exits, oneIteration...))
}

func (a *providerFlowAnalyzer) rangeStatement(stmt *ast.RangeStmt, states []providerFlowState) []providerFlowState {
	states = a.expression(stmt.X, states)
	exits := cloneProviderFlowStates(states)
	oneIteration := a.block(stmt.Body, cloneProviderFlowStates(states))
	return compactProviderFlowStates(append(exits, oneIteration...))
}

func (a *providerFlowAnalyzer) switchStatement(stmt *ast.SwitchStmt, states []providerFlowState) []providerFlowState {
	if stmt.Init != nil {
		states = a.statement(stmt.Init, states)
	}
	if stmt.Tag != nil {
		states = a.expression(stmt.Tag, states)
	}
	return a.caseClauses(stmt.Body, states)
}

func (a *providerFlowAnalyzer) typeSwitchStatement(stmt *ast.TypeSwitchStmt, states []providerFlowState) []providerFlowState {
	if stmt.Init != nil {
		states = a.statement(stmt.Init, states)
	}
	if stmt.Assign != nil {
		states = a.statement(stmt.Assign, states)
	}
	return a.caseClauses(stmt.Body, states)
}

func (a *providerFlowAnalyzer) caseClauses(body *ast.BlockStmt, states []providerFlowState) []providerFlowState {
	var exits []providerFlowState
	hasDefault := false
	for _, item := range body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			continue
		}
		hasDefault = hasDefault || len(clause.List) == 0
		branch := a.block(&ast.BlockStmt{List: clause.Body}, cloneProviderFlowStates(states))
		exits = append(exits, branch...)
	}
	if !hasDefault {
		exits = append(exits, cloneProviderFlowStates(states)...)
	}
	return compactProviderFlowStates(exits)
}

func (a *providerFlowAnalyzer) selectStatement(stmt *ast.SelectStmt, states []providerFlowState) []providerFlowState {
	var exits []providerFlowState
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok {
			continue
		}
		branch := cloneProviderFlowStates(states)
		if clause.Comm != nil {
			branch = a.statement(clause.Comm, branch)
		}
		branch = a.block(&ast.BlockStmt{List: clause.Body}, branch)
		exits = append(exits, branch...)
	}
	return compactProviderFlowStates(exits)
}

func (a *providerFlowAnalyzer) expressions(expressions []ast.Expr, states []providerFlowState) []providerFlowState {
	for _, expr := range expressions {
		states = a.expression(expr, states)
	}
	return states
}

func (a *providerFlowAnalyzer) expression(expr ast.Expr, states []providerFlowState) []providerFlowState {
	switch node := expr.(type) {
	case nil, *ast.Ident, *ast.BasicLit, *ast.FuncLit:
		return states
	case *ast.CallExpr:
		states = a.callOperands(node, states)
		return a.call(node, states)
	case *ast.SelectorExpr:
		return a.expression(node.X, states)
	case *ast.IndexExpr:
		states = a.expression(node.X, states)
		return a.expression(node.Index, states)
	case *ast.IndexListExpr:
		states = a.expression(node.X, states)
		return a.expressions(node.Indices, states)
	case *ast.SliceExpr:
		states = a.expression(node.X, states)
		states = a.expression(node.Low, states)
		states = a.expression(node.High, states)
		return a.expression(node.Max, states)
	case *ast.ParenExpr:
		return a.expression(node.X, states)
	case *ast.StarExpr:
		return a.expression(node.X, states)
	case *ast.UnaryExpr:
		return a.expression(node.X, states)
	case *ast.BinaryExpr:
		states = a.expression(node.X, states)
		if node.Op == token.LAND || node.Op == token.LOR {
			skipped := cloneProviderFlowStates(states)
			evaluated := a.expression(node.Y, cloneProviderFlowStates(states))
			return compactProviderFlowStates(append(skipped, evaluated...))
		}
		return a.expression(node.Y, states)
	case *ast.KeyValueExpr:
		states = a.expression(node.Key, states)
		return a.expression(node.Value, states)
	case *ast.CompositeLit:
		return a.expressions(node.Elts, states)
	case *ast.TypeAssertExpr:
		return a.expression(node.X, states)
	default:
		return states
	}
}

func (a *providerFlowAnalyzer) callOperands(call *ast.CallExpr, states []providerFlowState) []providerFlowState {
	states = a.expression(call.Fun, states)
	return a.expressions(call.Args, states)
}

func (a *providerFlowAnalyzer) call(call *ast.CallExpr, states []providerFlowState) []providerFlowState {
	method, command := matchingSelectorCall(call, providerCommandMethods, providerReceiverMarkers)
	persistsState := matchesSelectorCallPrefix(call, statePersistencePrefixes, stateReceiverMarkers)
	durable := isDurableIntentCall(call)
	entity := providerCallEntity(call)
	entityOwner := providerCallEntityOwner(call)
	if command {
		states = a.recordProviderCommand(call, method, entity, entityOwner, states)
	}

	for i := range states {
		if persistsState {
			for _, pending := range states[i].pending {
				a.detect(pending)
			}
			states[i].pending = nil
		}
		if durable {
			states[i].durableObserved = true
			evidence := durableIntentEvidence{method: selectorCallMethod(call), entity: entity, owner: entityOwner}
			if !containsDurableIntentEvidence(states[i].durableEvidence, evidence) {
				states[i].durableEvidence = append(append([]durableIntentEvidence(nil), states[i].durableEvidence...), evidence)
			}
		}
	}
	return compactProviderFlowStates(states)
}

func (a *providerFlowAnalyzer) recordProviderCommand(
	call *ast.CallExpr,
	method string,
	entity string,
	entityOwner string,
	states []providerFlowState,
) []providerFlowState {
	anyDurableObserved := false
	for _, state := range states {
		anyDurableObserved = anyDurableObserved || state.durableObserved
	}

	for i := range states {
		if !durableEvidenceMatchesProvider(states[i].durableEvidence, call, entity, entityOwner) {
			pending := providerCommandCall{
				call: call, method: method,
			}
			states[i].pending = append(append([]providerCommandCall(nil), states[i].pending...), pending)
			if anyDurableObserved {
				a.detect(pending)
			}
		}
	}
	return states
}

func (a *providerFlowAnalyzer) detect(command providerCommandCall) {
	if a.seen[command.call] {
		return
	}
	a.seen[command.call] = true
	a.detected = append(a.detected, command)
}

func isDurableIntentCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !receiverContainsAny(sel.X, stateReceiverMarkers) {
		return false
	}
	return containsAnyFold(sel.Sel.Name, durableIntentActions) &&
		containsAnyFold(sel.Sel.Name, durableIntentSubjects)
}

func cloneProviderFlowStates(states []providerFlowState) []providerFlowState {
	cloned := make([]providerFlowState, len(states))
	for i, state := range states {
		cloned[i] = state
		cloned[i].durableEvidence = append([]durableIntentEvidence(nil), state.durableEvidence...)
		cloned[i].pending = append([]providerCommandCall(nil), state.pending...)
	}
	return cloned
}

func compactProviderFlowStates(states []providerFlowState) []providerFlowState {
	compacted := make([]providerFlowState, 0, len(states))
	for _, state := range states {
		duplicate := false
		for _, existing := range compacted {
			if sameProviderFlowState(existing, state) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			compacted = append(compacted, state)
		}
	}
	return compacted
}

func sameProviderFlowState(left, right providerFlowState) bool {
	if left.durableObserved != right.durableObserved ||
		len(left.durableEvidence) != len(right.durableEvidence) || len(left.pending) != len(right.pending) {
		return false
	}
	for i := range left.durableEvidence {
		if left.durableEvidence[i] != right.durableEvidence[i] {
			return false
		}
	}
	for i := range left.pending {
		if left.pending[i].call != right.pending[i].call {
			return false
		}
	}
	return true
}

func providerCallEntity(call *ast.CallExpr) string {
	for _, arg := range call.Args {
		if isProviderContextArgument(arg) {
			continue
		}
		return normalizedProviderEntity(arg)
	}
	return ""
}

func providerCallEntityOwner(call *ast.CallExpr) string {
	for _, arg := range call.Args {
		if isProviderContextArgument(arg) {
			continue
		}
		return providerEntityOwner(arg)
	}
	return ""
}

func providerEntityOwner(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return providerEntityOwner(node.X)
	case *ast.StarExpr:
		return providerEntityOwner(node.X)
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			return providerEntityOwner(node.X)
		}
	case *ast.Ident:
		return normalizedProviderEntity(node)
	case *ast.SelectorExpr:
		return normalizedProviderEntity(node.X)
	case *ast.IndexExpr:
		return normalizedProviderEntity(node)
	}
	return ""
}

func isProviderContextArgument(expr ast.Expr) bool {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return isProviderContextArgument(node.X)
	case *ast.StarExpr:
		return isProviderContextArgument(node.X)
	case *ast.UnaryExpr:
		return node.Op == token.AND && isProviderContextArgument(node.X)
	case *ast.Ident:
		return isProviderContextName(node.Name)
	case *ast.SelectorExpr:
		return isProviderContextName(node.Sel.Name)
	case *ast.CallExpr:
		switch fun := node.Fun.(type) {
		case *ast.Ident:
			return isProviderContextName(fun.Name)
		case *ast.SelectorExpr:
			return isProviderContextName(fun.Sel.Name) || isProviderContextArgument(fun.X)
		}
	}
	return false
}

func isProviderContextName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "ctx" || strings.HasSuffix(lower, "ctx") || strings.HasSuffix(lower, "context")
}

func normalizedProviderEntity(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return normalizedProviderEntity(node.X)
	case *ast.StarExpr:
		return normalizedProviderEntity(node.X)
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			return normalizedProviderEntity(node.X)
		}
		return ""
	case *ast.Ident:
		return "ident(" + node.Name + ")"
	case *ast.SelectorExpr:
		base := normalizedProviderEntity(node.X)
		if base == "" {
			return ""
		}
		return "selector(" + base + "," + node.Sel.Name + ")"
	case *ast.IndexExpr:
		base := normalizedProviderEntity(node.X)
		index := normalizedProviderEntity(node.Index)
		if base == "" || index == "" {
			return ""
		}
		return "index(" + base + "," + index + ")"
	case *ast.BasicLit:
		return "literal(" + node.Kind.String() + "," + node.Value + ")"
	default:
		return ""
	}
}

func selectorCallMethod(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	return sel.Sel.Name
}

func durableEvidenceMatchesProvider(evidence []durableIntentEvidence, call *ast.CallExpr, entity, owner string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver := providerReceiverName(sel.X)
	providerOperation := canonicalProviderOperation(sel.Sel.Name)
	for _, durable := range evidence {
		durableOperation := canonicalProviderOperation(durable.method)
		if durable.entity == entity && entity != "" &&
			(providerOperation == "" || durableOperation == "" || durableOperation == providerOperation) {
			return true
		}
		if owner != "" && durable.owner == owner && providerOperation != "" && durableOperation == providerOperation {
			return true
		}
		if receiver != "" && !isGenericProviderReceiver(receiver) &&
			strings.Contains(strings.ToLower(durable.method), receiver) {
			return true
		}
	}
	return false
}

func containsDurableIntentEvidence(items []durableIntentEvidence, evidence durableIntentEvidence) bool {
	for _, item := range items {
		if item == evidence {
			return true
		}
	}
	return false
}

func canonicalProviderOperation(method string) string {
	lower := strings.ToLower(method)
	switch {
	case strings.Contains(lower, "cancel"):
		return "cancel"
	case strings.Contains(lower, "refund"):
		return "refund"
	default:
		return ""
	}
}

func providerReceiverName(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.Ident:
		return strings.ToLower(node.Name)
	case *ast.SelectorExpr:
		return strings.ToLower(node.Sel.Name)
	case *ast.IndexExpr:
		return providerReceiverName(node.X)
	case *ast.IndexListExpr:
		return providerReceiverName(node.X)
	case *ast.ParenExpr:
		return providerReceiverName(node.X)
	case *ast.StarExpr:
		return providerReceiverName(node.X)
	default:
		return ""
	}
}

func isGenericProviderReceiver(receiver string) bool {
	for _, generic := range []string{"provider", "payment", "payout", "bank", "remit"} {
		if receiver == generic {
			return true
		}
	}
	return false
}

func matchingSelectorCall(call *ast.CallExpr, methods map[string]bool, receiverMarkers []string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !methods[sel.Sel.Name] || !receiverContainsAny(sel.X, receiverMarkers) {
		return "", false
	}
	return sel.Sel.Name, true
}

func matchesSelectorCallPrefix(call *ast.CallExpr, prefixes, receiverMarkers []string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !receiverContainsAny(sel.X, receiverMarkers) {
		return false
	}
	lowerMethod := strings.ToLower(sel.Sel.Name)
	for _, prefix := range prefixes {
		if strings.HasPrefix(lowerMethod, prefix) {
			return true
		}
	}
	return false
}

func receiverContainsAny(receiver ast.Expr, markers []string) bool {
	switch expr := receiver.(type) {
	case *ast.Ident:
		return containsAnyFold(expr.Name, markers)
	case *ast.SelectorExpr:
		return containsAnyFold(expr.Sel.Name, markers) || receiverContainsAny(expr.X, markers)
	case *ast.IndexExpr:
		return receiverContainsAny(expr.X, markers)
	case *ast.IndexListExpr:
		return receiverContainsAny(expr.X, markers)
	case *ast.ParenExpr:
		return receiverContainsAny(expr.X, markers)
	case *ast.StarExpr:
		return receiverContainsAny(expr.X, markers)
	default:
		return false
	}
}

func containsAnyFold(value string, needles []string) bool {
	lower := strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
