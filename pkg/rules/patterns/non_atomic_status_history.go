package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNonAtomicStatusHistoryRule())
}

// defaultStatusMutationMethods are the repository methods that change an
// entity's status when the config names none (setting mutation_methods).
var defaultStatusMutationMethods = []string{
	"UpdateStatus", "UpdateStatusWithPayprov", "UpdateQuote", "UpdateSentToProvider",
	"MarkWaitingApproval", "Create", "CreateOrGet",
}

// defaultStatusHistoryMethods are the repository methods that append a status
// history row when the config names none (setting history_methods).
var defaultStatusHistoryMethods = []string{"RecordStatusHistory"}

// NonAtomicStatusHistoryRule detects status mutations followed by a separate
// history write on the same repository and entity in one function.
//
// The method names are the project's vocabulary: mutation_methods and
// history_methods replace the defaults. A method whose name holds both
// "update" and "quote" is a status mutation as well. Writes inside the
// callback of a transaction runner (transaction_functions, the same setting
// and defaults multi-write-no-transaction reads) are atomic and not reported.
type NonAtomicStatusHistoryRule struct {
	*rules.BaseRule

	mutationMethods map[string]bool
	historyMethods  map[string]bool
	// transactions recognises transaction runner calls.
	transactions *MultiWriteNoTransactionRule
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
		mutationMethods: statusHistoryNameSet(defaultStatusMutationMethods),
		historyMethods:  statusHistoryNameSet(defaultStatusHistoryMethods),
		transactions:    NewMultiWriteNoTransactionRule(),
	}
}

func statusHistoryNameSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// Configure reads mutation_methods, history_methods and
// transaction_functions; a setting left out keeps its default.
func (r *NonAtomicStatusHistoryRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return fmt.Errorf("configure non-atomic-status-history: %w", err)
	}
	mutations, err := configuredStatusHistoryNames(settings, "mutation_methods", defaultStatusMutationMethods)
	if err != nil {
		return err
	}
	histories, err := configuredStatusHistoryNames(settings, "history_methods", defaultStatusHistoryMethods)
	if err != nil {
		return err
	}
	transactions := NewMultiWriteNoTransactionRule()
	if raw, ok := settings["transaction_functions"]; ok {
		if err := transactions.Configure(map[string]any{"transaction_functions": raw}); err != nil {
			return fmt.Errorf("configure non-atomic-status-history: %w", err)
		}
	}
	r.mutationMethods, r.historyMethods, r.transactions = mutations, histories, transactions
	return nil
}

// configuredStatusHistoryNames reads a list-of-names setting.
func configuredStatusHistoryNames(settings map[string]any, key string, defaults []string) (map[string]bool, error) {
	names, present, err := rules.NameSetSetting(settings, "non-atomic-status-history", key)
	if err != nil || !present {
		return statusHistoryNameSet(defaults), err
	}
	return names, nil
}

// AnalyzeFile checks each production Go function independently, judging
// identities and context arguments by what the file declares.
func (r *NonAtomicStatusHistoryRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NonAtomicStatusHistoryRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information identities are
// the type checker's objects and a context argument is known by its type.
func (r *NonAtomicStatusHistoryRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks each function. info is nil for a file without type
// information: then an identifier resolves through the lexical scopes the
// rule tracks, and a first argument the file does not declare leaves the
// entity unknown and the call out of the analysis.
func (r *NonAtomicStatusHistoryRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Body == nil {
			continue
		}
		env := statusHistoryEnv{
			rule:     r,
			info:     info,
			contexts: newContextClassifier(ctx.GoAST, fn, info),
		}
		for _, scope := range r.statusHistoryScopes(fn) {
			violations = append(violations, r.analyzeStatusHistoryScope(ctx, fn.Name.Name, scope, env)...)
		}
	}

	return violations
}

// statusHistoryEnv is what the flow analysis of one function needs besides
// the syntax: the rule's vocabulary, type information and the context
// classifier.
type statusHistoryEnv struct {
	rule     *NonAtomicStatusHistoryRule
	info     *types.Info
	contexts contextClassifier
}

// isMutationMethod reports whether a method changes an entity's status: a
// configured mutation method or a quote-update helper.
func (r *NonAtomicStatusHistoryRule) isMutationMethod(name string) bool {
	return r.mutationMethods[name] || isStatusHistoryQuoteHelper(name)
}

func (r *NonAtomicStatusHistoryRule) analyzeStatusHistoryScope(ctx *core.FileContext, function string, scope statusHistoryFunctionScope, env statusHistoryEnv) []*core.Violation {
	var violations []*core.Violation
	reported := make(map[*ast.CallExpr]bool)
	for _, pair := range statusHistoryPairs(scope, env) {
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
			mutation.method+" followed by separate "+history.method+" is not atomic")
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

// statusHistoryScopes lists the function body and every function literal in
// it as separate flows. A literal handed to a transaction runner is left out
// together with everything inside it: its writes commit or roll back as one.
func (r *NonAtomicStatusHistoryRule) statusHistoryScopes(function *ast.FuncDecl) []statusHistoryFunctionScope {
	transactional := make(map[*ast.FuncLit]bool)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !r.transactions.isTransactionRunner(call, nil, nil) {
			return true
		}
		for _, argument := range call.Args {
			if literal, isLiteral := ast.Unparen(argument).(*ast.FuncLit); isLiteral {
				transactional[literal] = true
			}
		}
		return true
	})

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
			if transactional[literal] {
				return false
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

// statusHistoryLexicalScope resolves identifiers to their declarations. With
// type information the type checker's object is the declaration; without it
// the scope tracks the declarations the walk has seen.
type statusHistoryLexicalScope struct {
	parent  *statusHistoryLexicalScope
	symbols map[string]token.Pos
	info    *types.Info
}

func newStatusHistoryLexicalScope(parent *statusHistoryLexicalScope) *statusHistoryLexicalScope {
	scope := &statusHistoryLexicalScope{parent: parent, symbols: make(map[string]token.Pos)}
	if parent != nil {
		scope.info = parent.info
	}
	return scope
}

func (s *statusHistoryLexicalScope) declare(identifier *ast.Ident) {
	if identifier != nil && identifier.Name != "_" {
		if _, declared := s.symbols[identifier.Name]; !declared {
			s.symbols[identifier.Name] = identifier.Pos()
		}
	}
}

func (s *statusHistoryLexicalScope) resolve(identifier *ast.Ident) statusHistoryIdentity {
	if s.info != nil {
		if object := s.info.ObjectOf(identifier); object != nil {
			return statusHistoryIdentity{name: identifier.Name, declaration: object.Pos()}
		}
	}
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
	env   statusHistoryEnv
}

func statusHistoryPairs(function statusHistoryFunctionScope, env statusHistoryEnv) []statusHistoryPair {
	analyzer := &statusHistoryFlowAnalyzer{seen: make(map[[2]*ast.CallExpr]bool), env: env}
	scope := newStatusHistoryLexicalScope(nil)
	scope.info = env.info
	for _, fields := range function.fields {
		declareStatusHistoryFields(scope, fields)
	}
	walker := &flowWalker[[]statusHistoryPath, *statusHistoryLexicalScope]{rule: analyzer}
	walker.walk(function.body, []statusHistoryPath{{}}, scope)
	return analyzer.pairs
}

func (a *statusHistoryFlowAnalyzer) cloneState(paths []statusHistoryPath) []statusHistoryPath {
	return cloneStatusHistoryPaths(paths)
}

func (a *statusHistoryFlowAnalyzer) joinStates(left, right []statusHistoryPath) []statusHistoryPath {
	return joinFlowPaths(left, right, statusHistoryPathKey)
}

// statusHistoryPathKey identifies a path by the mutations recorded on it: the
// rule looks at nothing else, so two paths with the same mutations are one.
func statusHistoryPathKey(path statusHistoryPath) string {
	parts := make([]string, 0, len(path.mutations))
	for _, mutation := range path.mutations {
		parts = append(parts, flowPosKey(mutation.call.Pos()))
	}
	return flowPathKey(parts...)
}

func (a *statusHistoryFlowAnalyzer) liveState(paths []statusHistoryPath) bool { return len(paths) > 0 }

func (a *statusHistoryFlowAnalyzer) deadState() []statusHistoryPath { return nil }

func (a *statusHistoryFlowAnalyzer) enterScope(
	_ flowScopeKind,
	_ ast.Node,
	parent *statusHistoryLexicalScope,
	paths []statusHistoryPath,
) (*statusHistoryLexicalScope, []statusHistoryPath) {
	return newStatusHistoryLexicalScope(parent), paths
}

func (a *statusHistoryFlowAnalyzer) leaveScope(
	flowScopeKind,
	*statusHistoryLexicalScope,
	*flowEdges[[]statusHistoryPath],
) {
}

func (a *statusHistoryFlowAnalyzer) simpleStmt(
	statement ast.Stmt,
	paths []statusHistoryPath,
	scope *statusHistoryLexicalScope,
) ([]statusHistoryPath, bool) {
	switch node := statement.(type) {
	case *ast.AssignStmt:
		paths = a.applyCalls(paths, scope, node)
		paths = invalidateStatusHistoryAssignments(paths, scope, node)
		if node.Tok == token.DEFINE {
			declareStatusHistoryExpressions(scope, node.Lhs)
		}
		return paths, false
	case *ast.DeclStmt:
		return a.declaration(node.Decl, paths, scope), false
	case *ast.ReturnStmt:
		a.applyCalls(paths, scope, node)
		return nil, true
	default:
		return a.applyCalls(paths, scope, node), false
	}
}

func (a *statusHistoryFlowAnalyzer) ifCondition(
	statement *ast.IfStmt,
	paths []statusHistoryPath,
	scope *statusHistoryLexicalScope,
) ([]statusHistoryPath, []statusHistoryPath) {
	paths = a.applyCalls(paths, scope, statement.Cond)
	return cloneStatusHistoryPaths(paths), cloneStatusHistoryPaths(paths)
}

func (a *statusHistoryFlowAnalyzer) flowExpr(
	expr ast.Expr,
	paths []statusHistoryPath,
	scope *statusHistoryLexicalScope,
) []statusHistoryPath {
	return a.applyCalls(paths, scope, expr)
}

func (a *statusHistoryFlowAnalyzer) rangeVars(
	statement *ast.RangeStmt,
	paths []statusHistoryPath,
	scope *statusHistoryLexicalScope,
) []statusHistoryPath {
	if statement.Tok == token.DEFINE {
		declareStatusHistoryExpressions(scope, []ast.Expr{statement.Key, statement.Value})
	}
	return paths
}

func (a *statusHistoryFlowAnalyzer) typeSwitchGuard(
	statement ast.Stmt,
	paths []statusHistoryPath,
	scope *statusHistoryLexicalScope,
) []statusHistoryPath {
	// The legacy engine only scanned the guard for calls without declaring
	// the guard variable, so shadowed outer identifiers keep resolving to
	// their outer declarations inside the clauses.
	return a.applyCalls(paths, scope, statement)
}

func (a *statusHistoryFlowAnalyzer) caseClause(
	_ ast.Stmt,
	clause *ast.CaseClause,
	paths []statusHistoryPath,
	parent *statusHistoryLexicalScope,
) ([]statusHistoryPath, *statusHistoryLexicalScope) {
	scope := newStatusHistoryLexicalScope(parent)
	for _, expression := range clause.List {
		paths = a.applyCalls(paths, scope, expression)
	}
	return paths, scope
}

func (a *statusHistoryFlowAnalyzer) commClause(
	_ *ast.CommClause,
	paths []statusHistoryPath,
	parent *statusHistoryLexicalScope,
) ([]statusHistoryPath, *statusHistoryLexicalScope) {
	return paths, newStatusHistoryLexicalScope(parent)
}

func (a *statusHistoryFlowAnalyzer) normalize(*flowEdges[[]statusHistoryPath]) {}

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
		statusCall, ok := a.newStatusHistoryCall(call, scope)
		if !ok {
			return true
		}
		if a.env.rule.isMutationMethod(statusCall.method) {
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

func (a *statusHistoryFlowAnalyzer) newStatusHistoryCall(call *ast.CallExpr, scope *statusHistoryLexicalScope) (statusHistoryCall, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (!a.env.rule.isMutationMethod(selector.Sel.Name) && !a.env.rule.historyMethods[selector.Sel.Name]) {
		return statusHistoryCall{}, false
	}
	receiver, ok := statusHistoryReferenceFor(selector.X, scope)
	if !ok {
		return statusHistoryCall{}, false
	}
	entity, hasEntity := a.statusHistoryEntity(call.Args, scope)
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

// statusHistoryEntity returns the entity a call is about: its first argument,
// or the second when the first is a context.Context. When it is not known
// whether a leading argument is a context, the entity is unknown.
func (a *statusHistoryFlowAnalyzer) statusHistoryEntity(args []ast.Expr, scope *statusHistoryLexicalScope) (statusHistoryReference, bool) {
	if len(args) == 0 {
		return statusHistoryReference{}, false
	}
	entityIndex := 0
	if len(args) > 1 {
		isContext, known := a.env.contexts.classify(args[0])
		if !known {
			return statusHistoryReference{}, false
		}
		if isContext {
			entityIndex = 1
		}
	}
	return statusHistoryEntityRoot(args[entityIndex], scope)
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
