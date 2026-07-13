package patterns

import (
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewIdempotencyCheckThenCreateRule())
}

// IdempotencyCheckThenCreateRule detects non-atomic idempotency checks followed
// by a create on the same repository.
type IdempotencyCheckThenCreateRule struct {
	*rules.BaseRule
}

// NewIdempotencyCheckThenCreateRule creates the rule.
func NewIdempotencyCheckThenCreateRule() *IdempotencyCheckThenCreateRule {
	return &IdempotencyCheckThenCreateRule{
		BaseRule: rules.NewBaseRule(
			"idempotency-check-then-create",
			"patterns",
			"Detects TOCTOU races caused by checking an idempotency key or reference before a non-atomic create",
			core.SeverityHigh,
		),
	}
}

type idempotencyRepositoryCall struct {
	call          *ast.CallExpr
	receiver      string
	receiverKey   idempotencyReceiverKey
	method        string
	entity        idempotencyBinding
	entityIsKnown bool
}

type idempotencyBinding struct {
	declaration *ast.Ident
	unresolved  string
}

type idempotencyReceiverKey struct {
	binding idempotencyBinding
	path    string
}

type idempotencyScope struct {
	parent   *idempotencyScope
	bindings map[string]*ast.Ident
}

func newIdempotencyScope(parent *idempotencyScope) *idempotencyScope {
	return &idempotencyScope{parent: parent, bindings: make(map[string]*ast.Ident)}
}

func (s *idempotencyScope) lookup(name string) *ast.Ident {
	for current := s; current != nil; current = current.parent {
		if declaration, ok := current.bindings[name]; ok {
			return declaration
		}
	}
	return nil
}

func (s *idempotencyScope) declare(ident *ast.Ident) {
	if ident != nil && ident.Name != "_" {
		s.bindings[ident.Name] = ident
	}
}

type idempotencyPath struct {
	lookups map[idempotencyReceiverKey][]idempotencyRepositoryCall
	truths  map[idempotencyBinding]bool
}

func newIdempotencyPath() idempotencyPath {
	return idempotencyPath{
		lookups: make(map[idempotencyReceiverKey][]idempotencyRepositoryCall),
		truths:  make(map[idempotencyBinding]bool),
	}
}

func (p idempotencyPath) clone() idempotencyPath {
	clone := newIdempotencyPath()
	for receiver, calls := range p.lookups {
		clone.lookups[receiver] = append([]idempotencyRepositoryCall(nil), calls...)
	}
	for binding, truth := range p.truths {
		clone.truths[binding] = truth
	}
	return clone
}

type idempotencyFlow struct {
	next      []idempotencyPath
	breaks    []idempotencyPath
	continues []idempotencyPath
}

type idempotencyFunctionAnalyzer struct {
	rule                     *IdempotencyCheckThenCreateRule
	ctx                      *core.FileContext
	function                 string
	dataAccessBindings       map[*ast.Ident]struct{}
	analyzedFunctionLiterals map[*ast.FuncLit]struct{}
	reportedCreates          map[*ast.CallExpr]struct{}
	violations               []*core.Violation
}

// AnalyzeFile checks each production function independently.
func (r *IdempotencyCheckThenCreateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		analyzer := &idempotencyFunctionAnalyzer{
			rule:                     r,
			ctx:                      ctx,
			function:                 fn.Name.Name,
			dataAccessBindings:       make(map[*ast.Ident]struct{}),
			analyzedFunctionLiterals: make(map[*ast.FuncLit]struct{}),
			reportedCreates:          make(map[*ast.CallExpr]struct{}),
		}
		analyzer.analyzeFuncDecl(fn)
		violations = append(violations, analyzer.violations...)
	}
	return violations
}

func (a *idempotencyFunctionAnalyzer) analyzeFuncDecl(fn *ast.FuncDecl) {
	scope := newIdempotencyScope(nil)
	declareIdempotencyFields(scope, fn.Recv, a.dataAccessBindings)
	declareIdempotencyFields(scope, fn.Type.Params, a.dataAccessBindings)
	declareIdempotencyFields(scope, fn.Type.Results, a.dataAccessBindings)
	a.analyzeBlock([]idempotencyPath{newIdempotencyPath()}, scope, fn.Body.List)
}

func (a *idempotencyFunctionAnalyzer) analyzeFuncLit(fn *ast.FuncLit, parent *idempotencyScope) {
	if _, analyzed := a.analyzedFunctionLiterals[fn]; analyzed {
		return
	}
	a.analyzedFunctionLiterals[fn] = struct{}{}
	scope := newIdempotencyScope(parent)
	declareIdempotencyFields(scope, fn.Type.Params, a.dataAccessBindings)
	declareIdempotencyFields(scope, fn.Type.Results, a.dataAccessBindings)
	a.analyzeBlock([]idempotencyPath{newIdempotencyPath()}, scope, fn.Body.List)
}

func (a *idempotencyFunctionAnalyzer) analyzeBlock(paths []idempotencyPath, scope *idempotencyScope, statements []ast.Stmt) idempotencyFlow {
	flow := idempotencyFlow{next: paths}
	for _, statement := range statements {
		if len(flow.next) == 0 {
			break
		}
		statementFlow := a.analyzeStatement(flow.next, scope, statement)
		flow.breaks = append(flow.breaks, statementFlow.breaks...)
		flow.continues = append(flow.continues, statementFlow.continues...)
		flow.next = statementFlow.next
	}
	return flow
}

func (a *idempotencyFunctionAnalyzer) analyzeStatement(paths []idempotencyPath, scope *idempotencyScope, statement ast.Stmt) idempotencyFlow {
	switch node := statement.(type) {
	case *ast.AssignStmt:
		paths = a.applyCalls(paths, scope, node)
		paths = invalidateIdempotencyAssignments(paths, scope, node)
		declareIdempotencyAssignment(scope, node)
		return idempotencyFlow{next: paths}
	case *ast.DeclStmt:
		return idempotencyFlow{next: a.analyzeDeclaration(paths, scope, node.Decl)}
	case *ast.ReturnStmt:
		a.applyCalls(paths, scope, node)
		return idempotencyFlow{}
	case *ast.BranchStmt:
		if node.Label != nil {
			return idempotencyFlow{}
		}
		switch node.Tok {
		case token.BREAK:
			return idempotencyFlow{breaks: paths}
		case token.CONTINUE:
			return idempotencyFlow{continues: paths}
		default:
			return idempotencyFlow{}
		}
	case *ast.BlockStmt:
		return a.analyzeBlock(paths, newIdempotencyScope(scope), node.List)
	case *ast.IfStmt:
		return a.analyzeIf(paths, scope, node)
	case *ast.ForStmt:
		return a.analyzeFor(paths, scope, node)
	case *ast.RangeStmt:
		return a.analyzeRange(paths, scope, node)
	case *ast.SwitchStmt:
		return a.analyzeSwitch(paths, scope, node)
	case *ast.TypeSwitchStmt:
		return a.analyzeTypeSwitch(paths, scope, node)
	case *ast.SelectStmt:
		return a.analyzeSelect(paths, scope, node)
	case *ast.LabeledStmt:
		return a.analyzeStatement(paths, scope, node.Stmt)
	case *ast.EmptyStmt:
		return idempotencyFlow{next: paths}
	default:
		return idempotencyFlow{next: a.applyCalls(paths, scope, node)}
	}
}

func (a *idempotencyFunctionAnalyzer) analyzeIf(paths []idempotencyPath, parent *idempotencyScope, statement *ast.IfStmt) idempotencyFlow {
	scope := newIdempotencyScope(parent)
	if statement.Init != nil {
		paths = a.analyzeStatement(paths, scope, statement.Init).next
	}
	truePaths, falsePaths := a.analyzeCondition(paths, scope, statement.Cond)
	body := a.analyzeBlock(truePaths, newIdempotencyScope(scope), statement.Body.List)
	otherwise := idempotencyFlow{next: falsePaths}
	if statement.Else != nil {
		otherwise = a.analyzeStatement(falsePaths, scope, statement.Else)
	}
	return idempotencyFlow{
		next:      mergeIdempotencyPaths(append(body.next, otherwise.next...)),
		breaks:    append(body.breaks, otherwise.breaks...),
		continues: append(body.continues, otherwise.continues...),
	}
}

func (a *idempotencyFunctionAnalyzer) analyzeCondition(paths []idempotencyPath, scope *idempotencyScope, expression ast.Expr) ([]idempotencyPath, []idempotencyPath) {
	switch node := unparenIdempotencyExpr(expression).(type) {
	case *ast.Ident:
		binding := idempotencyBindingFor(node, scope)
		return constrainIdempotencyPaths(paths, binding, true), constrainIdempotencyPaths(paths, binding, false)
	case *ast.UnaryExpr:
		if node.Op == token.NOT {
			whenTrue, whenFalse := a.analyzeCondition(paths, scope, node.X)
			return whenFalse, whenTrue
		}
	case *ast.BinaryExpr:
		switch node.Op {
		case token.LAND:
			leftTrue, leftFalse := a.analyzeCondition(paths, scope, node.X)
			rightTrue, rightFalse := a.analyzeCondition(leftTrue, scope, node.Y)
			return rightTrue, mergeIdempotencyPaths(append(leftFalse, rightFalse...))
		case token.LOR:
			leftTrue, leftFalse := a.analyzeCondition(paths, scope, node.X)
			rightTrue, rightFalse := a.analyzeCondition(leftFalse, scope, node.Y)
			return mergeIdempotencyPaths(append(leftTrue, rightTrue...)), rightFalse
		}
	}

	paths = a.applyCalls(paths, scope, expression)
	return cloneIdempotencyPaths(paths), cloneIdempotencyPaths(paths)
}

func (a *idempotencyFunctionAnalyzer) analyzeFor(paths []idempotencyPath, parent *idempotencyScope, statement *ast.ForStmt) idempotencyFlow {
	scope := newIdempotencyScope(parent)
	if statement.Init != nil {
		paths = a.analyzeStatement(paths, scope, statement.Init).next
	}
	if statement.Cond != nil {
		paths = a.applyCalls(paths, scope, statement.Cond)
	}
	zeroIterations := cloneIdempotencyPaths(paths)
	body := a.analyzeBlock(cloneIdempotencyPaths(paths), newIdempotencyScope(scope), statement.Body.List)
	iterationEnds := append(body.next, body.continues...)
	if statement.Post != nil {
		iterationEnds = a.analyzeStatement(iterationEnds, scope, statement.Post).next
	}
	after := body.breaks
	if statement.Cond != nil {
		after = append(append(zeroIterations, after...), iterationEnds...)
	}
	return idempotencyFlow{next: mergeIdempotencyPaths(after)}
}

func (a *idempotencyFunctionAnalyzer) analyzeRange(paths []idempotencyPath, parent *idempotencyScope, statement *ast.RangeStmt) idempotencyFlow {
	paths = a.applyCalls(paths, parent, statement.X)
	bodyScope := newIdempotencyScope(parent)
	if statement.Tok == token.DEFINE {
		if ident, ok := statement.Key.(*ast.Ident); ok {
			bodyScope.declare(ident)
		}
		if ident, ok := statement.Value.(*ast.Ident); ok {
			bodyScope.declare(ident)
		}
	}
	zeroIterations := cloneIdempotencyPaths(paths)
	body := a.analyzeBlock(cloneIdempotencyPaths(paths), bodyScope, statement.Body.List)
	iterationEnds := append(body.next, body.continues...)
	return idempotencyFlow{next: mergeIdempotencyPaths(append(append(zeroIterations, body.breaks...), iterationEnds...))}
}

func (a *idempotencyFunctionAnalyzer) analyzeSwitch(paths []idempotencyPath, parent *idempotencyScope, statement *ast.SwitchStmt) idempotencyFlow {
	scope := newIdempotencyScope(parent)
	if statement.Init != nil {
		paths = a.analyzeStatement(paths, scope, statement.Init).next
	}
	if statement.Tag != nil {
		paths = a.applyCalls(paths, scope, statement.Tag)
	}
	flow := idempotencyFlow{}
	hasDefault := false
	for _, item := range statement.Body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			continue
		}
		clausePaths := cloneIdempotencyPaths(paths)
		if clause.List == nil {
			hasDefault = true
		}
		for _, expression := range clause.List {
			clausePaths = a.applyCalls(clausePaths, scope, expression)
		}
		clauseFlow := a.analyzeBlock(clausePaths, newIdempotencyScope(scope), clause.Body)
		flow.next = append(flow.next, clauseFlow.next...)
		flow.next = append(flow.next, clauseFlow.breaks...)
		flow.continues = append(flow.continues, clauseFlow.continues...)
	}
	if !hasDefault {
		flow.next = append(flow.next, cloneIdempotencyPaths(paths)...)
	}
	flow.next = mergeIdempotencyPaths(flow.next)
	return flow
}

func (a *idempotencyFunctionAnalyzer) analyzeTypeSwitch(paths []idempotencyPath, parent *idempotencyScope, statement *ast.TypeSwitchStmt) idempotencyFlow {
	scope := newIdempotencyScope(parent)
	if statement.Init != nil {
		paths = a.analyzeStatement(paths, scope, statement.Init).next
	}
	paths = a.analyzeStatement(paths, scope, statement.Assign).next
	flow := idempotencyFlow{}
	hasDefault := false
	for _, item := range statement.Body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			continue
		}
		if clause.List == nil {
			hasDefault = true
		}
		clauseFlow := a.analyzeBlock(cloneIdempotencyPaths(paths), newIdempotencyScope(scope), clause.Body)
		flow.next = append(flow.next, clauseFlow.next...)
		flow.next = append(flow.next, clauseFlow.breaks...)
		flow.continues = append(flow.continues, clauseFlow.continues...)
	}
	if !hasDefault {
		flow.next = append(flow.next, cloneIdempotencyPaths(paths)...)
	}
	flow.next = mergeIdempotencyPaths(flow.next)
	return flow
}

func (a *idempotencyFunctionAnalyzer) analyzeSelect(paths []idempotencyPath, scope *idempotencyScope, statement *ast.SelectStmt) idempotencyFlow {
	flow := idempotencyFlow{}
	for _, item := range statement.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok {
			continue
		}
		clauseScope := newIdempotencyScope(scope)
		clausePaths := cloneIdempotencyPaths(paths)
		if clause.Comm != nil {
			clausePaths = a.analyzeStatement(clausePaths, clauseScope, clause.Comm).next
		}
		clauseFlow := a.analyzeBlock(clausePaths, clauseScope, clause.Body)
		flow.next = append(flow.next, clauseFlow.next...)
		flow.next = append(flow.next, clauseFlow.breaks...)
		flow.continues = append(flow.continues, clauseFlow.continues...)
	}
	flow.next = mergeIdempotencyPaths(flow.next)
	return flow
}

func (a *idempotencyFunctionAnalyzer) analyzeDeclaration(paths []idempotencyPath, scope *idempotencyScope, declaration ast.Decl) []idempotencyPath {
	general, ok := declaration.(*ast.GenDecl)
	if !ok || general.Tok != token.VAR {
		return paths
	}
	for _, item := range general.Specs {
		spec, ok := item.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, value := range spec.Values {
			paths = a.applyCalls(paths, scope, value)
		}
		for _, name := range spec.Names {
			scope.declare(name)
			if isDataAccessReceiver(idempotencyReceiverTypeName(spec.Type)) {
				a.dataAccessBindings[name] = struct{}{}
			}
		}
	}
	return paths
}

func (a *idempotencyFunctionAnalyzer) applyCalls(paths []idempotencyPath, scope *idempotencyScope, node ast.Node) []idempotencyPath {
	var calls []*ast.CallExpr
	ast.Inspect(node, func(current ast.Node) bool {
		if literal, ok := current.(*ast.FuncLit); ok {
			a.analyzeFuncLit(literal, scope)
			return false
		}
		if call, ok := current.(*ast.CallExpr); ok {
			calls = append(calls, call)
		}
		return true
	})
	sort.SliceStable(calls, func(left, right int) bool {
		if calls[left].End() == calls[right].End() {
			return calls[left].Pos() < calls[right].Pos()
		}
		return calls[left].End() < calls[right].End()
	})

	for _, expression := range calls {
		call, ok := idempotencyDataAccessCall(expression, scope, a.dataAccessBindings)
		if !ok {
			continue
		}
		if isIdempotencyLookupMethod(call.method) {
			for index := range paths {
				paths[index] = paths[index].clone()
				paths[index].lookups[call.receiverKey] = append(paths[index].lookups[call.receiverKey], call)
			}
			continue
		}
		if !isNonAtomicCreateMethod(call.method) {
			continue
		}
		for _, path := range paths {
			lookup, found := precedingIdempotencyLookup(path, call)
			if found {
				a.report(lookup, call)
				break
			}
		}
	}
	return paths
}

func (a *idempotencyFunctionAnalyzer) report(lookup, create idempotencyRepositoryCall) {
	if _, reported := a.reportedCreates[create.call]; reported {
		return
	}
	a.reportedCreates[create.call] = struct{}{}
	line := lineFromNode(a.ctx, create.call)
	if a.ctx.IsSuppressed(line, a.rule.Name()) {
		return
	}

	lookupLine := lineFromNode(a.ctx, lookup.call)
	v := a.rule.CreateViolation(a.ctx.RelPath, line,
		"idempotency lookup '"+lookup.method+"' followed by non-atomic '"+create.method+"' on '"+create.receiver+"' creates a TOCTOU race")
	v.WithCode(a.ctx.GetLine(line))
	v.WithSuggestion("Use an atomic repository operation such as CreateOrGet, Upsert, or INSERT ... ON CONFLICT backed by a unique constraint")
	v.WithContext("pattern", "idempotency_check_then_create")
	v.WithContext("function", a.function)
	v.WithContext("receiver", create.receiver)
	v.WithContext("lookup_method", lookup.method)
	v.WithContext("create_method", create.method)
	v.WithContext("lookup_line", lookupLine)
	a.violations = append(a.violations, v)
}

func precedingIdempotencyLookup(path idempotencyPath, create idempotencyRepositoryCall) (idempotencyRepositoryCall, bool) {
	calls := path.lookups[create.receiverKey]
	for index := len(calls) - 1; index >= 0; index-- {
		candidate := calls[index]
		if candidate.entityIsKnown && create.entityIsKnown && candidate.entity != create.entity {
			continue
		}
		return candidate, true
	}
	return idempotencyRepositoryCall{}, false
}

func idempotencyDataAccessCall(call *ast.CallExpr, scope *idempotencyScope, dataAccessBindings map[*ast.Ident]struct{}) (idempotencyRepositoryCall, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return idempotencyRepositoryCall{}, false
	}
	receiver, receiverKey, dataAccess := idempotencyReceiverChain(selector.X, scope, dataAccessBindings)
	if receiver == "" || !dataAccess {
		return idempotencyRepositoryCall{}, false
	}
	result := idempotencyRepositoryCall{
		call:        call,
		receiver:    receiver,
		receiverKey: receiverKey,
		method:      selector.Sel.Name,
	}
	if isIdempotencyLookupMethod(result.method) {
		result.entity, result.entityIsKnown = idempotencyLookupEntity(call.Args, scope)
	} else if isNonAtomicCreateMethod(result.method) {
		result.entity, result.entityIsKnown = idempotencyCreateEntity(call.Args, scope)
	}
	return result, true
}

func idempotencyReceiverChain(expr ast.Expr, scope *idempotencyScope, dataAccessBindings map[*ast.Ident]struct{}) (string, idempotencyReceiverKey, bool) {
	switch node := expr.(type) {
	case *ast.Ident:
		binding := idempotencyBindingFor(node, scope)
		_, typedDataAccess := dataAccessBindings[binding.declaration]
		return node.Name, idempotencyReceiverKey{binding: binding}, typedDataAccess || isDataAccessReceiver(node.Name)
	case *ast.SelectorExpr:
		parent, key, dataAccess := idempotencyReceiverChain(node.X, scope, dataAccessBindings)
		if parent == "" {
			return "", idempotencyReceiverKey{}, false
		}
		key.path += "." + node.Sel.Name
		return parent + "." + node.Sel.Name, key, dataAccess || isDataAccessReceiver(node.Sel.Name)
	case *ast.ParenExpr:
		return idempotencyReceiverChain(node.X, scope, dataAccessBindings)
	default:
		return "", idempotencyReceiverKey{}, false
	}
}

func idempotencyLookupEntity(arguments []ast.Expr, scope *idempotencyScope) (idempotencyBinding, bool) {
	for _, argument := range arguments {
		selector, ok := unparenIdempotencyExpr(argument).(*ast.SelectorExpr)
		if !ok || !isIdempotencyEntityField(selector.Sel.Name) {
			continue
		}
		ident, ok := unparenIdempotencyExpr(selector.X).(*ast.Ident)
		if ok {
			return idempotencyBindingFor(ident, scope), true
		}
	}
	return idempotencyBinding{}, false
}

func idempotencyCreateEntity(arguments []ast.Expr, scope *idempotencyScope) (idempotencyBinding, bool) {
	var entity idempotencyBinding
	found := false
	for _, argument := range arguments {
		ident, ok := directIdempotencyIdent(argument)
		if !ok || isContextIdentifier(ident.Name) || ident.Name == "nil" {
			continue
		}
		if found {
			return idempotencyBinding{}, false
		}
		entity = idempotencyBindingFor(ident, scope)
		found = true
	}
	return entity, found
}

func directIdempotencyIdent(expr ast.Expr) (*ast.Ident, bool) {
	switch node := unparenIdempotencyExpr(expr).(type) {
	case *ast.Ident:
		return node, true
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			ident, ok := unparenIdempotencyExpr(node.X).(*ast.Ident)
			return ident, ok
		}
	}
	return nil, false
}

func unparenIdempotencyExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

func idempotencyBindingFor(ident *ast.Ident, scope *idempotencyScope) idempotencyBinding {
	if declaration := scope.lookup(ident.Name); declaration != nil {
		return idempotencyBinding{declaration: declaration}
	}
	return idempotencyBinding{unresolved: ident.Name}
}

func isIdempotencyEntityField(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "idempotency") || strings.Contains(lower, "reference")
}

func isContextIdentifier(name string) bool {
	lower := strings.ToLower(name)
	return lower == "ctx" || lower == "context" || strings.HasSuffix(lower, "ctx") || strings.HasSuffix(lower, "context")
}

func declareIdempotencyFields(scope *idempotencyScope, fields *ast.FieldList, dataAccessBindings map[*ast.Ident]struct{}) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		for _, name := range field.Names {
			scope.declare(name)
			if isDataAccessReceiver(idempotencyReceiverTypeName(field.Type)) {
				dataAccessBindings[name] = struct{}{}
			}
		}
	}
}

func invalidateIdempotencyAssignments(paths []idempotencyPath, scope *idempotencyScope, assignment *ast.AssignStmt) []idempotencyPath {
	reassigned := make(map[idempotencyBinding]struct{})
	for _, expression := range assignment.Lhs {
		ident, ok := expression.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		if assignment.Tok == token.DEFINE {
			declaration, alreadyDeclared := scope.bindings[ident.Name]
			if !alreadyDeclared {
				continue
			}
			reassigned[idempotencyBinding{declaration: declaration}] = struct{}{}
			continue
		}
		reassigned[idempotencyBindingFor(ident, scope)] = struct{}{}
	}
	if len(reassigned) == 0 {
		return paths
	}

	for index := range paths {
		paths[index] = paths[index].clone()
		for binding := range reassigned {
			delete(paths[index].truths, binding)
		}
		for receiver, calls := range paths[index].lookups {
			if _, changed := reassigned[receiver.binding]; changed {
				delete(paths[index].lookups, receiver)
				continue
			}
			kept := calls[:0]
			for _, call := range calls {
				_, entityChanged := reassigned[call.entity]
				if call.entityIsKnown && entityChanged {
					continue
				}
				kept = append(kept, call)
			}
			if len(kept) == 0 {
				delete(paths[index].lookups, receiver)
				continue
			}
			paths[index].lookups[receiver] = kept
		}
	}
	return paths
}

func declareIdempotencyAssignment(scope *idempotencyScope, assignment *ast.AssignStmt) {
	if assignment.Tok != token.DEFINE {
		return
	}
	for _, expression := range assignment.Lhs {
		ident, ok := expression.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		if _, alreadyDeclared := scope.bindings[ident.Name]; !alreadyDeclared {
			scope.declare(ident)
		}
	}
}

func cloneIdempotencyPaths(paths []idempotencyPath) []idempotencyPath {
	clones := make([]idempotencyPath, len(paths))
	for index, path := range paths {
		clones[index] = path.clone()
	}
	return clones
}

func constrainIdempotencyPaths(paths []idempotencyPath, binding idempotencyBinding, truth bool) []idempotencyPath {
	constrained := make([]idempotencyPath, 0, len(paths))
	for _, path := range paths {
		if known, ok := path.truths[binding]; ok && known != truth {
			continue
		}
		path = path.clone()
		path.truths[binding] = truth
		constrained = append(constrained, path)
	}
	return constrained
}

func mergeIdempotencyPaths(paths []idempotencyPath) []idempotencyPath {
	merged := make([]idempotencyPath, 0, len(paths))
	for _, candidate := range paths {
		duplicate := false
		for _, existing := range merged {
			if equalIdempotencyPaths(existing, candidate) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			merged = append(merged, candidate)
		}
	}
	return merged
}

func equalIdempotencyPaths(left, right idempotencyPath) bool {
	if len(left.lookups) != len(right.lookups) || len(left.truths) != len(right.truths) {
		return false
	}
	for receiver, leftCalls := range left.lookups {
		rightCalls, ok := right.lookups[receiver]
		if !ok || len(leftCalls) != len(rightCalls) {
			return false
		}
		for index := range leftCalls {
			if leftCalls[index].call != rightCalls[index].call {
				return false
			}
		}
	}
	for binding, leftTruth := range left.truths {
		if rightTruth, ok := right.truths[binding]; !ok || leftTruth != rightTruth {
			return false
		}
	}
	return true
}

func idempotencyReceiverTypeName(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.SelectorExpr:
		return node.Sel.Name
	case *ast.StarExpr:
		return idempotencyReceiverTypeName(node.X)
	case *ast.IndexExpr:
		return idempotencyReceiverTypeName(node.X)
	case *ast.IndexListExpr:
		return idempotencyReceiverTypeName(node.X)
	default:
		return ""
	}
}

func isIdempotencyLookupMethod(method string) bool {
	lower := strings.ToLower(method)
	lookup := false
	for _, prefix := range []string{"get", "find", "exists", "lookup", "check", "has"} {
		if strings.HasPrefix(lower, prefix) {
			lookup = true
			break
		}
	}
	if !lookup {
		return false
	}
	if strings.Contains(lower, "idempotency") {
		return true
	}
	by := strings.Index(lower, "by")
	return by >= 0 && strings.Contains(lower[by+2:], "reference")
}

func isNonAtomicCreateMethod(method string) bool {
	lower := strings.ToLower(method)
	if strings.Contains(lower, "createorget") || strings.Contains(lower, "upsert") || strings.Contains(lower, "insertonconflict") {
		return false
	}
	return strings.HasPrefix(lower, "create") || strings.HasPrefix(lower, "insert")
}
