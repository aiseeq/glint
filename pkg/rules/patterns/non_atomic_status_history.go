package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNonAtomicStatusHistoryRule())
}

// NonAtomicStatusHistoryRule detects status mutations followed by a separate
// history write on the same repository in one function.
type NonAtomicStatusHistoryRule struct {
	*rules.BaseRule
}

// NewNonAtomicStatusHistoryRule creates the rule.
func NewNonAtomicStatusHistoryRule() *NonAtomicStatusHistoryRule {
	return &NonAtomicStatusHistoryRule{
		BaseRule: rules.NewBaseRule(
			"non-atomic-status-history",
			"patterns",
			"Detects status mutations followed by a separate non-atomic status history write",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks each production Go function independently.
func (r *NonAtomicStatusHistoryRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Body == nil {
			continue
		}
		for _, scope := range statusHistoryScopes(fn) {
			violations = append(violations, r.analyzeStatusHistoryScope(ctx, fn.Name.Name, scope)...)
		}
	}

	return violations
}

func (r *NonAtomicStatusHistoryRule) analyzeStatusHistoryScope(ctx *core.FileContext, function string, scope statusHistoryFunctionScope) []*core.Violation {
	var violations []*core.Violation
	reported := make(map[*ast.CallExpr]bool)
	for _, pair := range statusHistoryPairs(scope) {
		mutation := pair.mutation
		history := pair.history
		if reported[mutation.call] {
			continue
		}
		mutationLine := ctx.PositionFor(mutation.call).Line
		if ctx.IsSuppressed(mutationLine, r.Name()) {
			continue
		}
		if !sameStatusHistoryReceiver(mutation, history) ||
			!mutation.hasEntity || !history.hasEntity ||
			!sameStatusHistoryReference(mutation.entity, history.entity) {
			continue
		}

		historyLine := ctx.PositionFor(history.call).Line
		if ctx.IsSuppressed(historyLine, r.Name()) {
			continue
		}

		v := r.CreateViolation(ctx.RelPath, mutationLine,
			mutation.method+" followed by separate RecordStatusHistory is not atomic")
		v.WithCode(ctx.GetLine(mutationLine))
		v.WithEndLine(historyLine)
		v.WithSuggestion("Combine the status mutation and history insert in one atomic repository method or transaction")
		v.WithContext("pattern", "non_atomic_status_history")
		v.WithContext("function", function)
		v.WithContext("receiver", mutation.receiver.display)
		v.WithContext("mutation_method", mutation.method)
		v.WithContext("history_method", history.method)
		violations = append(violations, v)
		reported[mutation.call] = true
	}
	return violations
}

type statusHistoryFunctionScope struct {
	body   *ast.BlockStmt
	fields []*ast.FieldList
}

func statusHistoryScopes(function *ast.FuncDecl) []statusHistoryFunctionScope {
	scopes := []statusHistoryFunctionScope{{
		body:   function.Body,
		fields: []*ast.FieldList{function.Recv, function.Type.Params, function.Type.Results},
	}}
	for i := 0; i < len(scopes); i++ {
		ast.Inspect(scopes[i].body, func(node ast.Node) bool {
			literal, ok := node.(*ast.FuncLit)
			if !ok {
				return true
			}
			scopes = append(scopes, statusHistoryFunctionScope{
				body:   literal.Body,
				fields: []*ast.FieldList{literal.Type.Params, literal.Type.Results},
			})
			return false
		})
	}
	return scopes
}

type statusHistoryIdentity struct {
	name        string
	declaration token.Pos
}

type statusHistoryReference struct {
	root      statusHistoryIdentity
	selectors []string
	display   string
}

type statusHistoryCall struct {
	call      *ast.CallExpr
	receiver  statusHistoryReference
	method    string
	entity    statusHistoryReference
	hasEntity bool
}

type statusHistoryPair struct {
	mutation statusHistoryCall
	history  statusHistoryCall
}

type statusHistoryPath struct {
	mutations []statusHistoryCall
}

type statusHistoryFlow struct {
	next      []statusHistoryPath
	breaks    []statusHistoryPath
	continues []statusHistoryPath
}

type statusHistoryLexicalScope struct {
	parent  *statusHistoryLexicalScope
	symbols map[string]token.Pos
}

func newStatusHistoryLexicalScope(parent *statusHistoryLexicalScope) *statusHistoryLexicalScope {
	return &statusHistoryLexicalScope{parent: parent, symbols: make(map[string]token.Pos)}
}

func (s *statusHistoryLexicalScope) declare(identifier *ast.Ident) {
	if identifier != nil && identifier.Name != "_" {
		if _, declared := s.symbols[identifier.Name]; !declared {
			s.symbols[identifier.Name] = identifier.Pos()
		}
	}
}

func (s *statusHistoryLexicalScope) resolve(identifier *ast.Ident) statusHistoryIdentity {
	for current := s; current != nil; current = current.parent {
		if position, ok := current.symbols[identifier.Name]; ok {
			return statusHistoryIdentity{name: identifier.Name, declaration: position}
		}
	}
	return statusHistoryIdentity{name: identifier.Name}
}

type statusHistoryFlowAnalyzer struct {
	pairs []statusHistoryPair
	seen  map[[2]*ast.CallExpr]bool
}

func statusHistoryPairs(function statusHistoryFunctionScope) []statusHistoryPair {
	analyzer := statusHistoryFlowAnalyzer{seen: make(map[[2]*ast.CallExpr]bool)}
	scope := newStatusHistoryLexicalScope(nil)
	for _, fields := range function.fields {
		declareStatusHistoryFields(scope, fields)
	}
	analyzer.block(function.body.List, []statusHistoryPath{{}}, scope)
	return analyzer.pairs
}

func (a *statusHistoryFlowAnalyzer) block(statements []ast.Stmt, paths []statusHistoryPath, scope *statusHistoryLexicalScope) statusHistoryFlow {
	flow := statusHistoryFlow{next: paths}
	for _, statement := range statements {
		if len(flow.next) == 0 {
			break
		}
		statementFlow := a.statement(statement, flow.next, scope)
		flow.breaks = append(flow.breaks, statementFlow.breaks...)
		flow.continues = append(flow.continues, statementFlow.continues...)
		flow.next = statementFlow.next
	}
	return flow
}

func (a *statusHistoryFlowAnalyzer) statement(statement ast.Stmt, paths []statusHistoryPath, scope *statusHistoryLexicalScope) statusHistoryFlow {
	switch node := statement.(type) {
	case *ast.AssignStmt:
		paths = a.applyCalls(paths, scope, node)
		paths = invalidateStatusHistoryAssignments(paths, scope, node)
		if node.Tok == token.DEFINE {
			declareStatusHistoryExpressions(scope, node.Lhs)
		}
		return statusHistoryFlow{next: paths}
	case *ast.DeclStmt:
		return statusHistoryFlow{next: a.declaration(node.Decl, paths, scope)}
	case *ast.ReturnStmt:
		a.applyCalls(paths, scope, node)
		return statusHistoryFlow{}
	case *ast.BranchStmt:
		if node.Label != nil {
			return statusHistoryFlow{}
		}
		switch node.Tok {
		case token.BREAK:
			return statusHistoryFlow{breaks: paths}
		case token.CONTINUE:
			return statusHistoryFlow{continues: paths}
		default:
			return statusHistoryFlow{}
		}
	case *ast.BlockStmt:
		return a.block(node.List, paths, newStatusHistoryLexicalScope(scope))
	case *ast.IfStmt:
		return a.ifStatement(node, paths, scope)
	case *ast.ForStmt:
		return a.forStatement(node, paths, scope)
	case *ast.RangeStmt:
		return a.rangeStatement(node, paths, scope)
	case *ast.SwitchStmt:
		return a.switchStatement(node, paths, scope)
	case *ast.TypeSwitchStmt:
		return a.typeSwitchStatement(node, paths, scope)
	case *ast.SelectStmt:
		return a.selectStatement(node, paths, scope)
	case *ast.LabeledStmt:
		return a.statement(node.Stmt, paths, scope)
	default:
		return statusHistoryFlow{next: a.applyCalls(paths, scope, node)}
	}
}

func (a *statusHistoryFlowAnalyzer) ifStatement(statement *ast.IfStmt, paths []statusHistoryPath, parent *statusHistoryLexicalScope) statusHistoryFlow {
	scope := newStatusHistoryLexicalScope(parent)
	if statement.Init != nil {
		paths = a.statement(statement.Init, paths, scope).next
	}
	paths = a.applyCalls(paths, scope, statement.Cond)
	body := a.block(statement.Body.List, cloneStatusHistoryPaths(paths), newStatusHistoryLexicalScope(scope))
	otherwise := statusHistoryFlow{next: cloneStatusHistoryPaths(paths)}
	if statement.Else != nil {
		otherwise = a.statement(statement.Else, otherwise.next, scope)
	}
	return mergeStatusHistoryFlows(body, otherwise)
}

func (a *statusHistoryFlowAnalyzer) forStatement(statement *ast.ForStmt, paths []statusHistoryPath, parent *statusHistoryLexicalScope) statusHistoryFlow {
	scope := newStatusHistoryLexicalScope(parent)
	if statement.Init != nil {
		paths = a.statement(statement.Init, paths, scope).next
	}
	paths = a.applyCalls(paths, scope, statement.Cond)
	body := a.block(statement.Body.List, cloneStatusHistoryPaths(paths), newStatusHistoryLexicalScope(scope))
	if statement.Post != nil {
		body.next = a.statement(statement.Post, body.next, scope).next
		body.continues = a.statement(statement.Post, body.continues, scope).next
	}
	next := body.breaks
	if statement.Cond != nil {
		next = append(next, cloneStatusHistoryPaths(paths)...)
		next = append(next, body.next...)
		next = append(next, body.continues...)
	}
	return statusHistoryFlow{next: next}
}

func (a *statusHistoryFlowAnalyzer) rangeStatement(statement *ast.RangeStmt, paths []statusHistoryPath, parent *statusHistoryLexicalScope) statusHistoryFlow {
	paths = a.applyCalls(paths, parent, statement.X)
	scope := newStatusHistoryLexicalScope(parent)
	if statement.Tok == token.DEFINE {
		declareStatusHistoryExpressions(scope, []ast.Expr{statement.Key, statement.Value})
	}
	body := a.block(statement.Body.List, cloneStatusHistoryPaths(paths), newStatusHistoryLexicalScope(scope))
	next := append(cloneStatusHistoryPaths(paths), body.next...)
	next = append(next, body.continues...)
	next = append(next, body.breaks...)
	return statusHistoryFlow{next: next}
}

func (a *statusHistoryFlowAnalyzer) switchStatement(statement *ast.SwitchStmt, paths []statusHistoryPath, parent *statusHistoryLexicalScope) statusHistoryFlow {
	scope := newStatusHistoryLexicalScope(parent)
	if statement.Init != nil {
		paths = a.statement(statement.Init, paths, scope).next
	}
	paths = a.applyCalls(paths, scope, statement.Tag)
	return a.caseClauses(statement.Body.List, paths, scope)
}

func (a *statusHistoryFlowAnalyzer) typeSwitchStatement(statement *ast.TypeSwitchStmt, paths []statusHistoryPath, parent *statusHistoryLexicalScope) statusHistoryFlow {
	scope := newStatusHistoryLexicalScope(parent)
	if statement.Init != nil {
		paths = a.statement(statement.Init, paths, scope).next
	}
	paths = a.applyCalls(paths, scope, statement.Assign)
	return a.caseClauses(statement.Body.List, paths, scope)
}

func (a *statusHistoryFlowAnalyzer) caseClauses(statements []ast.Stmt, paths []statusHistoryPath, parent *statusHistoryLexicalScope) statusHistoryFlow {
	var result statusHistoryFlow
	hasDefault := false
	for _, statement := range statements {
		clause, ok := statement.(*ast.CaseClause)
		if !ok {
			continue
		}
		scope := newStatusHistoryLexicalScope(parent)
		clausePaths := cloneStatusHistoryPaths(paths)
		for _, expression := range clause.List {
			clausePaths = a.applyCalls(clausePaths, scope, expression)
		}
		flow := a.block(clause.Body, clausePaths, scope)
		result.next = append(result.next, flow.next...)
		result.next = append(result.next, flow.breaks...)
		result.continues = append(result.continues, flow.continues...)
		hasDefault = hasDefault || len(clause.List) == 0
	}
	if !hasDefault {
		result.next = append(result.next, cloneStatusHistoryPaths(paths)...)
	}
	return result
}

func (a *statusHistoryFlowAnalyzer) selectStatement(statement *ast.SelectStmt, paths []statusHistoryPath, parent *statusHistoryLexicalScope) statusHistoryFlow {
	var result statusHistoryFlow
	for _, item := range statement.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok {
			continue
		}
		scope := newStatusHistoryLexicalScope(parent)
		clausePaths := cloneStatusHistoryPaths(paths)
		if clause.Comm != nil {
			clausePaths = a.statement(clause.Comm, clausePaths, scope).next
		}
		flow := a.block(clause.Body, clausePaths, scope)
		result.next = append(result.next, flow.next...)
		result.next = append(result.next, flow.breaks...)
		result.continues = append(result.continues, flow.continues...)
	}
	return result
}

func (a *statusHistoryFlowAnalyzer) applyCalls(paths []statusHistoryPath, scope *statusHistoryLexicalScope, node ast.Node) []statusHistoryPath {
	if node == nil {
		return paths
	}
	ast.Inspect(node, func(current ast.Node) bool {
		if _, ok := current.(*ast.FuncLit); ok {
			return false
		}
		call, ok := current.(*ast.CallExpr)
		if !ok {
			return true
		}
		statusCall, ok := newStatusHistoryCall(call, scope)
		if !ok {
			return true
		}
		if isStatusMutationMethod(statusCall.method) {
			for i := range paths {
				paths[i].mutations = append(paths[i].mutations, statusCall)
			}
			return true
		}
		for _, path := range paths {
			for _, mutation := range path.mutations {
				key := [2]*ast.CallExpr{mutation.call, statusCall.call}
				if a.seen[key] {
					continue
				}
				a.seen[key] = true
				a.pairs = append(a.pairs, statusHistoryPair{mutation: mutation, history: statusCall})
			}
		}
		return true
	})
	return paths
}

func (a *statusHistoryFlowAnalyzer) declaration(declaration ast.Decl, paths []statusHistoryPath, scope *statusHistoryLexicalScope) []statusHistoryPath {
	general, ok := declaration.(*ast.GenDecl)
	if !ok {
		return a.applyCalls(paths, scope, declaration)
	}
	for _, spec := range general.Specs {
		paths = a.applyCalls(paths, scope, spec)
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range value.Names {
			scope.declare(name)
		}
	}
	return paths
}

func invalidateStatusHistoryAssignments(paths []statusHistoryPath, scope *statusHistoryLexicalScope, assignment *ast.AssignStmt) []statusHistoryPath {
	reassigned := make(map[statusHistoryIdentity]struct{})
	for _, expression := range assignment.Lhs {
		identifier, ok := expression.(*ast.Ident)
		if !ok || identifier.Name == "_" {
			continue
		}
		if assignment.Tok == token.DEFINE {
			declaration, alreadyDeclared := scope.symbols[identifier.Name]
			if !alreadyDeclared {
				continue
			}
			reassigned[statusHistoryIdentity{name: identifier.Name, declaration: declaration}] = struct{}{}
			continue
		}
		reassigned[scope.resolve(identifier)] = struct{}{}
	}
	if len(reassigned) == 0 {
		return paths
	}

	for index := range paths {
		kept := make([]statusHistoryCall, 0, len(paths[index].mutations))
		for _, mutation := range paths[index].mutations {
			_, receiverChanged := reassigned[mutation.receiver.root]
			_, entityChanged := reassigned[mutation.entity.root]
			if receiverChanged || mutation.hasEntity && entityChanged {
				continue
			}
			kept = append(kept, mutation)
		}
		paths[index].mutations = kept
	}
	return paths
}

func newStatusHistoryCall(call *ast.CallExpr, scope *statusHistoryLexicalScope) (statusHistoryCall, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (!isStatusMutationMethod(selector.Sel.Name) && selector.Sel.Name != "RecordStatusHistory") {
		return statusHistoryCall{}, false
	}
	receiver, ok := statusHistoryReferenceFor(selector.X, scope)
	if !ok {
		return statusHistoryCall{}, false
	}
	entity, hasEntity := statusHistoryEntity(call.Args, scope)
	return statusHistoryCall{
		call:      call,
		receiver:  receiver,
		method:    selector.Sel.Name,
		entity:    entity,
		hasEntity: hasEntity,
	}, true
}

func cloneStatusHistoryPaths(paths []statusHistoryPath) []statusHistoryPath {
	cloned := make([]statusHistoryPath, len(paths))
	for i, path := range paths {
		cloned[i].mutations = append([]statusHistoryCall(nil), path.mutations...)
	}
	return cloned
}

func mergeStatusHistoryFlows(flows ...statusHistoryFlow) statusHistoryFlow {
	var merged statusHistoryFlow
	for _, flow := range flows {
		merged.next = append(merged.next, flow.next...)
		merged.breaks = append(merged.breaks, flow.breaks...)
		merged.continues = append(merged.continues, flow.continues...)
	}
	return merged
}

func declareStatusHistoryExpressions(scope *statusHistoryLexicalScope, expressions []ast.Expr) {
	for _, expression := range expressions {
		if identifier, ok := expression.(*ast.Ident); ok {
			scope.declare(identifier)
		}
	}
}

func declareStatusHistoryFields(scope *statusHistoryLexicalScope, fields *ast.FieldList) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		for _, name := range field.Names {
			scope.declare(name)
		}
	}
}

func statusHistoryEntity(args []ast.Expr, scope *statusHistoryLexicalScope) (statusHistoryReference, bool) {
	if len(args) == 0 {
		return statusHistoryReference{}, false
	}
	entityIndex := 0
	if len(args) > 1 && isStatusHistoryContext(args[0], scope) {
		entityIndex = 1
	}
	return statusHistoryEntityRoot(args[entityIndex], scope)
}

func isStatusHistoryContext(expr ast.Expr, scope *statusHistoryLexicalScope) bool {
	reference, ok := statusHistoryReferenceFor(expr, scope)
	if !ok {
		return false
	}
	parts := strings.Split(reference.display, ".")
	name := strings.ToLower(parts[len(parts)-1])
	return name == "context" || strings.HasSuffix(name, "ctx")
}

func statusHistoryEntityRoot(expr ast.Expr, scope *statusHistoryLexicalScope) (statusHistoryReference, bool) {
	switch value := expr.(type) {
	case *ast.Ident:
		return statusHistoryReferenceFor(value, scope)
	case *ast.SelectorExpr:
		if strings.EqualFold(value.Sel.Name, "id") {
			return statusHistoryReferenceFor(value.X, scope)
		}
		return statusHistoryReferenceFor(value, scope)
	case *ast.ParenExpr:
		return statusHistoryEntityRoot(value.X, scope)
	case *ast.StarExpr:
		return statusHistoryEntityRoot(value.X, scope)
	case *ast.UnaryExpr:
		return statusHistoryEntityRoot(value.X, scope)
	default:
		return statusHistoryReference{}, false
	}
}

func statusHistoryReferenceFor(expr ast.Expr, scope *statusHistoryLexicalScope) (statusHistoryReference, bool) {
	switch value := expr.(type) {
	case *ast.Ident:
		return statusHistoryReference{root: scope.resolve(value), display: value.Name}, true
	case *ast.SelectorExpr:
		prefix, ok := statusHistoryReferenceFor(value.X, scope)
		if !ok {
			return statusHistoryReference{}, false
		}
		prefix.selectors = append(prefix.selectors, value.Sel.Name)
		prefix.display += "." + value.Sel.Name
		return prefix, true
	case *ast.ParenExpr:
		return statusHistoryReferenceFor(value.X, scope)
	default:
		return statusHistoryReference{}, false
	}
}

func isStatusMutationMethod(name string) bool {
	switch name {
	case "UpdateStatus", "UpdateStatusWithPaywho", "UpdateQuote", "UpdateSentToProvider",
		"MarkWaitingApproval", "Create", "CreateOrGet":
		return true
	default:
		lower := strings.ToLower(name)
		return strings.Contains(lower, "update") && strings.Contains(lower, "quote")
	}
}

func sameStatusHistoryReceiver(mutation, history statusHistoryCall) bool {
	if sameStatusHistoryReference(mutation.receiver, history.receiver) {
		return true
	}
	if !isStatusHistoryQuoteHelper(mutation.method) {
		return false
	}
	if mutation.receiver.root != history.receiver.root ||
		len(history.receiver.selectors) != len(mutation.receiver.selectors)+1 {
		return false
	}
	for i, selector := range mutation.receiver.selectors {
		if history.receiver.selectors[i] != selector {
			return false
		}
	}
	return true
}

func sameStatusHistoryReference(left, right statusHistoryReference) bool {
	if left.root != right.root || len(left.selectors) != len(right.selectors) {
		return false
	}
	for i, selector := range left.selectors {
		if right.selectors[i] != selector {
			return false
		}
	}
	return true
}

func isStatusHistoryQuoteHelper(method string) bool {
	if method == "UpdateQuote" {
		return false
	}
	lower := strings.ToLower(method)
	return strings.Contains(lower, "update") && strings.Contains(lower, "quote")
}
