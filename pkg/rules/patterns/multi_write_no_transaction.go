package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMultiWriteNoTransactionRule())
}

// MultiWriteNoTransactionRule detects a function that changes persistent state more than
// once without a transaction around the changes.
//
// The failure is not hypothetical and it is not loud. Each write succeeds on its own, so
// nothing in the logs says "half of this operation happened". The record simply disagrees
// with itself from then on, and the disagreement is found later, by a human, in money.
//
// Real case (ProjectA, 2026-07-31). Completing a withdrawal wrote four rows in sequence: the
// transaction hash onto the request, a posting into `transactions`, the request's status to
// `completed`, and finally the ledger entries in `fund_transfers`. The last step was allowed
// to fail — the code even carried a comment saying rollback was impossible at that point. A
// failure there left the withdrawal marked completed, with a posting under it, and no ledger
// entry: the money was recorded as gone and unaccounted for at the same time. The four writes
// are now one transaction, and the regression test asserts that a failing last step leaves
// the request in its previous status.
//
// What is reported: two or more calls, with distinct method names, that mutate a store
// (a receiver whose type name reads as a repository, store or DAO) and that can both run in
// the same pass through the function. What is not reported:
//
//   - Calls in mutually exclusive arms of the same if or switch — only one of them runs.
//   - A retry of the same call: the same method name twice is one write attempted twice.
//   - Writes already inside a transaction runner's callback, and functions that are only
//     ever reached from inside one — the wrapper does not have to sit in the same function
//     as the writes, and requiring that would push every helper back into one long method.
//
// Deliberately separate steps do exist: crediting a deposit and auto-investing it are two
// operations, and rolling back the credit because the investment failed would be worse than
// leaving them apart. Such a pair is exempted by naming the runner in transaction_functions
// only if it truly runs under one, so the honest way to silence this rule for a deliberate
// split is a comment on the function and a rule exclusion, not a fake transaction.
type MultiWriteNoTransactionRule struct {
	*rules.BaseRule

	mutation  *regexp.Regexp
	storeType *regexp.Regexp
	txRunners map[string]bool
	txOpeners map[string]bool
}

// NewMultiWriteNoTransactionRule creates the rule.
func NewMultiWriteNoTransactionRule() *MultiWriteNoTransactionRule {
	return &MultiWriteNoTransactionRule{
		BaseRule: rules.NewBaseRule(
			"multi-write-no-transaction",
			"patterns",
			"Detects two or more persistent writes in one function that are not wrapped in a transaction",
			core.SeverityHigh,
		),
		// Имя метода, меняющего состояние. Get/List/Find/Count сюда не попадают.
		mutation: regexp.MustCompile(`^(Create|Insert|Update|Upsert|Delete|Remove|Save|Store|Set|Mark|Apply|Attach|Detach|Claim|Reject|Approve|Cancel|Expire|Increment|Decrement)[A-Z]\w*$`),
		// Тип получателя, который считается хранилищем.
		storeType: regexp.MustCompile(`(?i)(repo|repository|store|dao)(interface|impl)?$`),
		txRunners: map[string]bool{
			"RunInTx":          true,
			"RunInTransaction": true,
			"WithTransaction":  true,
			"InTransaction":    true,
			"Transact":         true,
		},
		// Функция, сама открывающая транзакцию и пишущая через её объект, а не через колбэк.
		txOpeners: map[string]bool{"BeginTx": true, "BeginTxx": true, "Begin": true},
	}
}

// Configure accepts overrides for what counts as a store and as a transaction runner.
func (r *MultiWriteNoTransactionRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return fmt.Errorf("configure multi-write-no-transaction: %w", err)
	}
	if raw, ok := settings["store_types"]; ok {
		pattern, ok := raw.(string)
		if !ok {
			return fmt.Errorf("configure multi-write-no-transaction: store_types must be a string, got %T", raw)
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("configure multi-write-no-transaction: store_types %q: %w", pattern, err)
		}
		r.storeType = compiled
	}
	if raw, ok := settings["transaction_functions"]; ok {
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("configure multi-write-no-transaction: transaction_functions must be a list, got %T", raw)
		}
		runners := make(map[string]bool, len(list))
		for i, item := range list {
			name, ok := item.(string)
			if !ok {
				return fmt.Errorf("configure multi-write-no-transaction: transaction_functions item %d must be a string, got %T", i, item)
			}
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("configure multi-write-no-transaction: transaction_functions item %d is empty", i)
			}
			runners[name] = true
		}
		r.txRunners = runners
	}
	return nil
}

// AnalyzeFile is a no-op: whether a helper already runs inside a transaction is decided by
// its callers, which live in other files.
func (r *MultiWriteNoTransactionRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed packages are enough.
func (r *MultiWriteNoTransactionRule) RequiresSSA() bool { return false }

// AnalyzeGoProject collects the functions that run under a transaction, then reports the rest.
func (r *MultiWriteNoTransactionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("multi write no transaction: nil Go project context")
	}

	covered := r.functionsUnderTransaction(ctx)
	graph := r.buildGraph(ctx)

	var violations []*core.Violation
	for _, node := range graph {
		if node.name != "" && covered[node.name] {
			continue
		}
		writes := graph.writesOf(node.name, node, map[string]bool{})
		if _, ok := firstConcurrentPair(writes); !ok {
			continue
		}
		// Сообщаем о самом внутреннем нарушителе: если записи разъезжаются уже
		// в вызываемой функции, чинить надо её, а не каждого её вызывающего.
		if graph.calleeAlreadyOffends(node) {
			continue
		}
		violations = append(violations, r.violation(ctx, node, writes))
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

// branchArm identifies one arm of one branching statement, and says whether that arm
// leaves the function. An arm that returns makes everything after the branch unreachable
// from inside it, so its writes never meet the later ones.
type branchArm struct {
	node       string
	arm        string
	terminates bool
}

// writeCall is one mutating call together with the branch arms enclosing it.
type writeCall struct {
	method string
	arms   []branchArm
}

// funcNode is one analysed function: its own writes and the functions it calls outside a
// transaction callback.
type funcNode struct {
	name    string
	display string
	file    string
	pos     token.Pos
	writes  []writeCall
	// callArms — плечи ветвления в точке вызова: записи вызываемой функции наследуют их,
	// иначе вызов из ветки if выглядел бы безусловным.
	calls []callSite
}

type callSite struct {
	name string
	arms []branchArm
}

// callGraph maps a function's full name to its node.
type callGraph map[string]*funcNode

// writesOf returns the writes the function performs directly and through its callees.
func (g callGraph) writesOf(name string, node *funcNode, visiting map[string]bool) []writeCall {
	if node == nil || visiting[name] {
		return nil
	}
	visiting[name] = true
	defer delete(visiting, name)

	writes := append([]writeCall(nil), node.writes...)
	for _, call := range node.calls {
		callee, ok := g[call.name]
		if !ok {
			continue
		}
		for _, w := range g.writesOf(call.name, callee, visiting) {
			w.arms = append(append([]branchArm(nil), call.arms...), w.arms...)
			writes = append(writes, w)
		}
	}
	return writes
}

// calleeAlreadyOffends reports whether some callee already splits writes on its own.
func (g callGraph) calleeAlreadyOffends(node *funcNode) bool {
	for _, call := range node.calls {
		callee, ok := g[call.name]
		if !ok {
			continue
		}
		if _, offends := firstConcurrentPair(g.writesOf(call.name, callee, map[string]bool{})); offends {
			return true
		}
	}
	return false
}

// buildGraph collects every project function with its own writes and outgoing calls.
func (r *MultiWriteNoTransactionRule) buildGraph(ctx *core.GoProjectContext) callGraph {
	graph := make(callGraph)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file == nil || file.GoAST == nil || file.IsTestFile() {
				continue
			}
			for _, decl := range file.GoAST.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				obj, ok := info.Defs[fn.Name].(*types.Func)
				if !ok {
					continue
				}
				writes, calls := r.scanBody(fn.Body, info)
				graph[obj.FullName()] = &funcNode{
					name:    obj.FullName(),
					display: fn.Name.Name,
					file:    file.RelPath,
					pos:     fn.Pos(),
					writes:  writes,
					calls:   calls,
				}
			}
		}
	}
	return graph
}

// violation renders the report for a function whose writes are not atomic.
func (r *MultiWriteNoTransactionRule) violation(ctx *core.GoProjectContext, node *funcNode, writes []writeCall) *core.Violation {
	pair, _ := firstConcurrentPair(writes)
	pos := ctx.FileSet.Position(node.pos)
	return &core.Violation{
		Rule:   r.Name(),
		File:   node.file,
		Line:   pos.Line,
		Column: pos.Column,
		Message: fmt.Sprintf(
			"%s changes stored state more than once without a transaction: %s and %s — a failure between them leaves the record half-applied",
			node.display, pair[0].method, pair[1].method,
		),
		Severity:   r.DefaultSeverity(),
		Category:   r.Category(),
		Suggestion: "Wrap the writes in one transaction so the operation either applies fully or leaves no trace",
	}
}

// scanBody collects the store mutations the body performs itself and the project functions
// it calls, both outside any transaction callback.
func (r *MultiWriteNoTransactionRule) scanBody(body *ast.BlockStmt, info *types.Info) ([]writeCall, []callSite) {
	var writes []writeCall
	var calls []callSite
	var arms []branchArm

	var walk func(n ast.Node)
	visitWithArm := func(n ast.Node, arm branchArm) {
		if n == nil {
			return
		}
		arms = append(arms, arm)
		walk(n)
		arms = arms[:len(arms)-1]
	}
	walkChildren := func(n ast.Node) {
		for _, child := range directChildren(n) {
			walk(child)
		}
	}

	walk = func(n ast.Node) {
		if n == nil {
			return
		}
		switch node := n.(type) {
		case *ast.IfStmt:
			// Ветки одного if исключают друг друга — помечаем их разными метками
			// с общим идентификатором ветвления.
			id := fmt.Sprintf("if%d", node.Pos())
			walk(node.Init)
			walk(node.Cond)
			visitWithArm(node.Body, branchArm{node: id, arm: "then", terminates: blockTerminates(node.Body)})
			visitWithArm(node.Else, branchArm{node: id, arm: "else", terminates: nodeTerminates(node.Else)})
			return
		case *ast.SwitchStmt:
			id := fmt.Sprintf("switch%d", node.Pos())
			walk(node.Init)
			walk(node.Tag)
			walkCases(node.Body, id, visitWithArm, walk)
			return
		case *ast.TypeSwitchStmt:
			id := fmt.Sprintf("typeswitch%d", node.Pos())
			walk(node.Init)
			walk(node.Assign)
			walkCases(node.Body, id, visitWithArm, walk)
			return
		case *ast.CallExpr:
			if r.isTransactionRunner(node) {
				// Записи внутри колбэка транзакции уже защищены — вглубь не идём.
				return
			}
			// Вызов, сам являющийся записью, дальше не разворачиваем: делегирующая
			// обёртка иначе считалась бы второй записью поверх той же самой.
			if method, ok := r.storeMutation(node, info); ok {
				writes = append(writes, writeCall{method: method, arms: append([]branchArm(nil), arms...)})
			} else if callee := resolvedCalleeName(node, info); callee != "" {
				calls = append(calls, callSite{name: callee, arms: append([]branchArm(nil), arms...)})
			}
		}
		walkChildren(n)
	}

	walk(body)
	return writes, calls
}

// resolvedCalleeName resolves the callee of a direct call, or "" if it is not a known function.
func resolvedCalleeName(call *ast.CallExpr, info *types.Info) string {
	var ident *ast.Ident
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		ident = fun
	case *ast.SelectorExpr:
		ident = fun.Sel
	}
	if ident == nil || info == nil {
		return ""
	}
	if fn, ok := info.Uses[ident].(*types.Func); ok {
		return fn.FullName()
	}
	return ""
}

// walkCases обходит ветки switch, помечая каждую своим плечом общего ветвления.
func walkCases(body *ast.BlockStmt, id string, visitWithArm func(ast.Node, branchArm), walk func(ast.Node)) {
	if body == nil {
		return
	}
	for i, stmt := range body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			walk(stmt)
			continue
		}
		for _, expr := range clause.List {
			walk(expr)
		}
		arm := branchArm{node: id, arm: fmt.Sprintf("case%d", i), terminates: stmtsTerminate(clause.Body)}
		for _, inner := range clause.Body {
			visitWithArm(inner, arm)
		}
	}
}

// directChildren returns the node's immediate children.
func directChildren(n ast.Node) []ast.Node {
	var children []ast.Node
	ast.Inspect(n, func(child ast.Node) bool {
		if child == nil || child == n {
			return child == n
		}
		children = append(children, child)
		return false
	})
	return children
}

// isTransactionRunner reports whether the call hands a callback to a transaction runner.
func (r *MultiWriteNoTransactionRule) isTransactionRunner(call *ast.CallExpr) bool {
	name := mutationCalleeName(call.Fun)
	return name != "" && r.txRunners[name]
}

// storeMutation reports the method name when the call mutates a store.
func (r *MultiWriteNoTransactionRule) storeMutation(call *ast.CallExpr, info *types.Info) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	method := sel.Sel.Name
	if !r.mutation.MatchString(method) {
		return "", false
	}
	if info == nil {
		return "", false
	}
	recv := info.TypeOf(sel.X)
	if recv == nil {
		return "", false
	}
	if !r.storeType.MatchString(typeBaseName(recv)) {
		return "", false
	}
	return method, true
}

// functionsUnderTransaction lists functions reachable from inside a transaction callback.
//
// The wrapper rarely sits in the same function as the writes: a service opens the transaction
// and calls a helper that performs them. Without this pass every such helper would be reported
// even though its writes are atomic.
func (r *MultiWriteNoTransactionRule) functionsUnderTransaction(ctx *core.GoProjectContext) map[string]bool {
	covered := make(map[string]bool)
	callees := make(map[string][]string)

	var queue []string
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file == nil || file.GoAST == nil {
				continue
			}
			ast.Inspect(file.GoAST, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}
				owner := ""
				if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
					owner = obj.FullName()
				}
				opensTx := false
				ast.Inspect(fn.Body, func(inner ast.Node) bool {
					call, ok := inner.(*ast.CallExpr)
					if !ok {
						return true
					}
					// db.BeginTxx открывает транзакцию прямо здесь: и сама функция,
					// и всё, что она вызывает, пишет уже внутри неё.
					if r.txOpeners[mutationCalleeName(call.Fun)] {
						opensTx = true
						return true
					}
					if r.isTransactionRunner(call) {
						queue = append(queue, calledFunctions(call, info)...)
						return true
					}
					if owner != "" {
						callees[owner] = append(callees[owner], calledFunctions(call, info)...)
					}
					return true
				})
				if opensTx && owner != "" {
					queue = append(queue, owner)
				}
				return true
			})
		}
	}

	for len(queue) > 0 {
		name := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if name == "" || covered[name] {
			continue
		}
		covered[name] = true
		queue = append(queue, callees[name]...)
	}
	return covered
}

// calledFunctions lists the functions named anywhere inside the expression.
func calledFunctions(node ast.Node, info *types.Info) []string {
	var names []string
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var ident *ast.Ident
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			ident = fun
		case *ast.SelectorExpr:
			ident = fun.Sel
		}
		if ident == nil {
			return true
		}
		if fn, ok := info.Uses[ident].(*types.Func); ok {
			names = append(names, fn.FullName())
		}
		return true
	})
	return names
}

// mutationCalleeName returns the called function name without the receiver.
func mutationCalleeName(fun ast.Expr) string {
	switch v := fun.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

// typeBaseName returns the named type behind pointers and aliases.
func typeBaseName(t types.Type) string {
	for {
		switch v := t.(type) {
		case *types.Pointer:
			t = v.Elem()
		case *types.Named:
			return v.Obj().Name()
		default:
			return ""
		}
	}
}

// firstConcurrentPair returns two writes with distinct method names that can both run in one
// pass. Calls in different arms of the same if or switch are excluded: only one of them runs.
func firstConcurrentPair(writes []writeCall) ([2]writeCall, bool) {
	for i := range writes {
		for j := i + 1; j < len(writes); j++ {
			if writes[i].method == writes[j].method {
				continue
			}
			if exclusiveArms(writes[i].arms, writes[j].arms) {
				continue
			}
			return [2]writeCall{writes[i], writes[j]}, true
		}
	}
	return [2]writeCall{}, false
}

// exclusiveArms reports whether the two writes can never both run in one pass.
//
// Two shapes count. The writes sit in different arms of the same if or switch, so only one
// of them is taken. Or one of them sits in an arm the other is not in, and that arm returns
// — the classic `if updated { …; return }` followed by the create path.
func exclusiveArms(a, b []branchArm) bool {
	inA := make(map[string]branchArm, len(a))
	for _, arm := range a {
		inA[arm.node] = arm
	}
	inB := make(map[string]branchArm, len(b))
	for _, arm := range b {
		inB[arm.node] = arm
	}

	for node, armA := range inA {
		armB, shared := inB[node]
		if shared && armA.arm != armB.arm {
			return true
		}
		if !shared && armA.terminates {
			return true
		}
	}
	for node, armB := range inB {
		if _, shared := inA[node]; !shared && armB.terminates {
			return true
		}
	}
	return false
}

// blockTerminates reports whether the block always leaves the enclosing function or loop.
func blockTerminates(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	return stmtsTerminate(block.List)
}

// nodeTerminates handles the else arm, which is either a block or another if.
func nodeTerminates(node ast.Stmt) bool {
	switch v := node.(type) {
	case nil:
		return false
	case *ast.BlockStmt:
		return blockTerminates(v)
	case *ast.IfStmt:
		return blockTerminates(v.Body) && nodeTerminates(v.Else)
	}
	return false
}

// stmtsTerminate reports whether the statement list ends in an unconditional exit.
func stmtsTerminate(stmts []ast.Stmt) bool {
	if len(stmts) == 0 {
		return false
	}
	switch last := stmts[len(stmts)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return last.Tok == token.BREAK || last.Tok == token.CONTINUE || last.Tok == token.GOTO
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		return mutationCalleeName(call.Fun) == "panic" || mutationCalleeName(call.Fun) == "Fatal" ||
			mutationCalleeName(call.Fun) == "Fatalf" || mutationCalleeName(call.Fun) == "Exit"
	case *ast.BlockStmt:
		return blockTerminates(last)
	}
	return false
}
