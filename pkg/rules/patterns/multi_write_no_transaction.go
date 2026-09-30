package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"regexp"
	"slices"
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
// Real case (ProjectA). Completing a withdrawal wrote four rows in sequence: the
// transaction hash onto the request, a posting into `transactions`, the request's status to
// `completed`, and finally the ledger entries. The last step was allowed
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
//   - Writes no single control-flow path reaches together: different arms of an if,
//     switch or select, a write in an arm that returns (or calls os.Exit, log.Fatal,
//     panic) before the other one. Helpers are summarised per path too, so a helper
//     that writes one thing or the other contributes one write per path.
//   - A retry of the same call: the same method name twice is one write attempted twice.
//   - Writes inside a goroutine body: that work outlives the function and cannot share its
//     transaction. Project spawners that hide the `go` inside a helper, and telemetry that
//     must survive precisely when the business operation fails, are listed in
//     independent_calls.
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
	// independent — вызовы, чьи записи принадлежат другой единице работы: запускалки
	// фоновых задач (аргумент выполняется в чужой горутине) и телеметрия, которая обязана
	// сохраниться именно тогда, когда бизнес-операция провалилась.
	independent map[string]bool
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
		// Проектные запускалки горутин и телеметрия задаются в конфиге: в языке ни те, ни
		// другие ничем не выделены. Голый `go` разбирается без настройки.
		independent: map[string]bool{},
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
	if raw, ok := settings["independent_calls"]; ok {
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("configure multi-write-no-transaction: independent_calls must be a list, got %T", raw)
		}
		independent := make(map[string]bool, len(list))
		for i, item := range list {
			name, ok := item.(string)
			if !ok {
				return fmt.Errorf("configure multi-write-no-transaction: independent_calls item %d must be a string, got %T", i, item)
			}
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("configure multi-write-no-transaction: independent_calls item %d is empty", i)
			}
			independent[name] = true
		}
		r.independent = independent
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
	// Sorted, so that summaries cut at a recursive call come out the same on every run.
	for _, name := range slices.Sorted(maps.Keys(graph.funcs)) {
		if covered[name] {
			continue
		}
		summary := graph.summary(name)
		// Сообщаем о самом внутреннем нарушителе: если записи разъезжаются уже
		// в вызываемой функции, чинить надо её, а не каждого её вызывающего.
		if !summary.offends || summary.calleeOffends {
			continue
		}
		violations = append(violations, r.violation(ctx, graph.funcs[name], summary.pair))
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

// writeCall is one mutating call.
type writeCall struct {
	method string
	// via — цепочка хелперов от разбираемой функции до самой записи. Без неё находку
	// через два уровня вызовов невозможно проверить: в теле функции записи не видно.
	via []string
}

// where describes the write for the report: имя метода и путь до него.
func (w writeCall) where() string {
	if len(w.via) == 0 {
		return w.method
	}
	return w.method + " (через " + strings.Join(w.via, " → ") + ")"
}

// through returns the write as seen from a caller of helper.
func (w writeCall) through(helper string) writeCall {
	return writeCall{method: w.method, via: append([]string{helper}, w.via...)}
}

// writePath is the flow state of one control-flow path: the write it has
// performed so far, if any. A path never carries two distinct writes — the
// second one is the finding, recorded in the function summary, and the path
// keeps its first write — so a function has at most one path per written
// method plus the path without writes.
type writePath struct {
	write *writeCall
}

func writePathKey(path writePath) string {
	if path.write == nil {
		return ""
	}
	return path.write.method
}

func joinWritePaths(left, right []writePath) []writePath {
	return joinFlowPaths(left, right, writePathKey)
}

// funcNode is one analysed function.
type funcNode struct {
	display string
	file    string
	pos     token.Pos
	decl    *ast.FuncDecl
	info    *types.Info
}

// writeSummary is what one function contributes to the paths of its callers.
type writeSummary struct {
	// exits are the states of the paths that return to the caller.
	exits []writePath
	// writes lists every write the function may perform, one per method,
	// including those on paths that never return.
	writes []writeCall
	// offends is set when two distinct writes run on one path, directly or
	// inside a callee; pair is the first such pair found.
	offends bool
	pair    [2]writeCall
	// calleeOffends is set when a called function already offends on its own.
	calleeOffends bool
}

func (s *writeSummary) record(write writeCall) {
	for _, known := range s.writes {
		if known.method == write.method {
			return
		}
	}
	s.writes = append(s.writes, write)
}

func (s *writeSummary) offend(first, second writeCall) {
	if s.offends {
		return
	}
	s.offends = true
	s.pair = [2]writeCall{first, second}
}

// callGraph holds every project function and the summaries computed so far.
// Each function is summarised once; its callers reuse the summary.
type callGraph struct {
	rule      *MultiWriteNoTransactionRule
	funcs     map[string]*funcNode
	summaries map[string]*writeSummary
	visiting  map[string]bool
}

// summary returns the write summary of a project function, or nil for a
// function outside the graph.
func (g *callGraph) summary(name string) *writeSummary {
	if summary, ok := g.summaries[name]; ok {
		return summary
	}
	node, ok := g.funcs[name]
	if !ok {
		return nil
	}
	if g.visiting[name] {
		// A recursive call re-enters a function still being summarised: its
		// writes are already on the paths of the outer activation.
		return &writeSummary{exits: []writePath{{}}}
	}
	g.visiting[name] = true
	summary := &writeSummary{}
	analyzer := &writeFlowAnalyzer{graph: g, info: node.info, summary: summary}
	summary.exits = analyzer.walkBody(node.decl.Body, []writePath{{}})
	delete(g.visiting, name)
	g.summaries[name] = summary
	return summary
}

// buildGraph collects every project function.
func (r *MultiWriteNoTransactionRule) buildGraph(ctx *core.GoProjectContext) *callGraph {
	graph := &callGraph{
		rule:      r,
		funcs:     make(map[string]*funcNode),
		summaries: make(map[string]*writeSummary),
		visiting:  make(map[string]bool),
	}
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
				graph.funcs[obj.FullName()] = &funcNode{
					display: fn.Name.Name,
					file:    file.RelPath,
					pos:     fn.Pos(),
					decl:    fn,
					info:    info,
				}
			}
		}
	}
	return graph
}

// violation renders the report for a function whose writes are not atomic.
func (r *MultiWriteNoTransactionRule) violation(ctx *core.GoProjectContext, node *funcNode, pair [2]writeCall) *core.Violation {
	pos := ctx.FileSet.Position(node.pos)
	return &core.Violation{
		Rule:   r.Name(),
		File:   node.file,
		Line:   pos.Line,
		Column: pos.Column,
		Message: fmt.Sprintf(
			"%s changes stored state more than once without a transaction: %s and %s — a failure between them leaves the record half-applied",
			node.display, pair[0].where(), pair[1].where(),
		),
		Severity:   r.DefaultSeverity(),
		Category:   r.Category(),
		Suggestion: "Wrap the writes in one transaction so the operation either applies fully or leaves no trace",
		// Имя функции в контексте — то, по чему `function:` в конфиге исключает
		// одну осознанно разделённую пару, не глуша правило на весь файл.
		Context: map[string]any{"function": node.display},
	}
}

// writeFlowAnalyzer walks one function body with the shared flow walker. The
// state is the list of writePaths; calls of project functions splice in the
// callee's summary, closures are walked in place.
type writeFlowAnalyzer struct {
	graph   *callGraph
	info    *types.Info
	summary *writeSummary
	// exits collects the paths returning from the body being walked.
	exits []writePath
}

// walkBody walks a function or closure body and returns the states of the
// paths leaving it.
func (a *writeFlowAnalyzer) walkBody(body *ast.BlockStmt, paths []writePath) []writePath {
	outer := a.exits
	a.exits = nil
	walker := &flowWalker[[]writePath, struct{}]{rule: a}
	edges := walker.walk(body, paths, struct{}{})
	exits := joinWritePaths(a.exits, edges.next)
	a.exits = outer
	return exits
}

func (a *writeFlowAnalyzer) cloneState(paths []writePath) []writePath { return slices.Clone(paths) }

func (a *writeFlowAnalyzer) joinStates(left, right []writePath) []writePath {
	return joinWritePaths(left, right)
}

func (a *writeFlowAnalyzer) liveState(paths []writePath) bool { return len(paths) > 0 }

func (a *writeFlowAnalyzer) deadState() []writePath { return nil }

func (a *writeFlowAnalyzer) enterScope(_ flowScopeKind, _ ast.Node, parent struct{}, paths []writePath) (struct{}, []writePath) {
	return parent, paths
}

func (a *writeFlowAnalyzer) leaveScope(flowScopeKind, struct{}, *flowEdges[[]writePath]) {}

func (a *writeFlowAnalyzer) simpleStmt(stmt ast.Stmt, paths []writePath, _ struct{}) ([]writePath, bool) {
	switch node := stmt.(type) {
	case *ast.ReturnStmt:
		for _, result := range node.Results {
			paths = a.scan(result, paths)
		}
		a.exits = joinWritePaths(a.exits, paths)
		return nil, true
	case *ast.GoStmt:
		// Тело горутины — отдельная единица работы: она переживает возврат из
		// функции и физически не может делить с ней транзакцию. Аргументы вызова
		// вычисляются в текущей горутине (spec: Go statements), их смотрим.
		for _, arg := range node.Call.Args {
			paths = a.scan(arg, paths)
		}
		return paths, false
	case *ast.ExprStmt:
		paths = a.scan(node.X, paths)
		if stmtNoReturn(node, a.info, nil) != callReturns {
			return nil, true
		}
	default:
		// A deferred write is added where it is registered: it runs on every
		// exit after that point, which is the same set of paths.
		paths = a.scan(stmt, paths)
	}
	return paths, len(paths) == 0
}

func (a *writeFlowAnalyzer) ifCondition(stmt *ast.IfStmt, paths []writePath, _ struct{}) ([]writePath, []writePath) {
	paths = a.scan(stmt.Cond, paths)
	return paths, slices.Clone(paths)
}

func (a *writeFlowAnalyzer) flowExpr(expr ast.Expr, paths []writePath, _ struct{}) []writePath {
	return a.scan(expr, paths)
}

func (a *writeFlowAnalyzer) rangeVars(_ *ast.RangeStmt, paths []writePath, _ struct{}) []writePath {
	return paths
}

func (a *writeFlowAnalyzer) typeSwitchGuard(stmt ast.Stmt, paths []writePath, _ struct{}) []writePath {
	return a.scan(stmt, paths)
}

func (a *writeFlowAnalyzer) caseClause(sw ast.Stmt, clause *ast.CaseClause, paths []writePath, parent struct{}) ([]writePath, struct{}) {
	if _, isTypeSwitch := sw.(*ast.TypeSwitchStmt); !isTypeSwitch {
		for _, expr := range clause.List {
			paths = a.scan(expr, paths)
		}
	}
	return paths, parent
}

func (a *writeFlowAnalyzer) commClause(_ *ast.CommClause, paths []writePath, parent struct{}) ([]writePath, struct{}) {
	return paths, parent
}

func (a *writeFlowAnalyzer) normalize(*flowEdges[[]writePath]) {}

// scan evaluates the calls inside a node in evaluation order: operands and
// arguments before the call itself.
func (a *writeFlowAnalyzer) scan(node ast.Node, paths []writePath) []writePath {
	if node == nil || len(paths) == 0 {
		return paths
	}
	switch current := node.(type) {
	case *ast.FuncLit:
		// A closure may run here or not at all: the paths through its body
		// join the paths that skip it. Pairs inside it are found on the way.
		return joinWritePaths(paths, a.walkBody(current.Body, slices.Clone(paths)))
	case *ast.CallExpr:
		return a.call(current, paths)
	}
	for _, child := range directChildren(node) {
		paths = a.scan(child, paths)
	}
	return paths
}

// call applies one call to the paths: a store mutation adds its write, a call
// of a project function splices in that function's summary.
func (a *writeFlowAnalyzer) call(call *ast.CallExpr, paths []writePath) []writePath {
	rule := a.graph.rule
	if rule.isTransactionRunner(call) {
		// Записи внутри колбэка транзакции уже защищены — вглубь не идём.
		return paths
	}
	if rule.isIndependent(call) {
		// Запуск фоновой задачи или телеметрия: эти записи принадлежат другой
		// единице работы и в транзакцию вызывающего попасть не должны.
		return paths
	}
	paths = a.scan(call.Fun, paths)
	for _, arg := range call.Args {
		paths = a.scan(arg, paths)
	}
	// Вызов, сам являющийся записью, дальше не разворачиваем: делегирующая
	// обёртка иначе считалась бы второй записью поверх той же самой.
	if method, ok := rule.storeMutation(call, a.info); ok {
		return a.write(paths, writeCall{method: method})
	}
	name := resolvedCalleeName(call, a.info)
	if name == "" {
		return paths
	}
	callee := a.graph.summary(name)
	if callee == nil {
		return paths
	}
	return a.through(paths, callee, a.graph.funcs[name].display)
}

// write adds one write to every path.
func (a *writeFlowAnalyzer) write(paths []writePath, write writeCall) []writePath {
	a.summary.record(write)
	next := make([]writePath, 0, len(paths))
	for _, path := range paths {
		switch {
		case path.write == nil:
			written := write
			next = append(next, writePath{write: &written})
		case path.write.method != write.method:
			a.summary.offend(*path.write, write)
			next = append(next, path)
		default:
			// A retry of the same write: one write attempted twice.
			next = append(next, path)
		}
	}
	return joinWritePaths(next, nil)
}

// through continues every path through a call of a summarised function.
func (a *writeFlowAnalyzer) through(paths []writePath, callee *writeSummary, helper string) []writePath {
	if callee.offends {
		a.summary.calleeOffends = true
		a.summary.offend(callee.pair[0].through(helper), callee.pair[1].through(helper))
	}
	for _, write := range callee.writes {
		write = write.through(helper)
		a.summary.record(write)
		for _, path := range paths {
			if path.write != nil && path.write.method != write.method {
				a.summary.offend(*path.write, write)
			}
		}
	}
	next := make([]writePath, 0, len(paths)*len(callee.exits))
	for _, path := range paths {
		for _, exit := range callee.exits {
			if path.write != nil || exit.write == nil {
				// The path's own write stays; a different one from the
				// callee is already recorded as the pair.
				next = append(next, path)
				continue
			}
			written := exit.write.through(helper)
			next = append(next, writePath{write: &written})
		}
	}
	return joinWritePaths(next, nil)
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

// isIndependent reports whether the call's writes belong to another unit of work.
func (r *MultiWriteNoTransactionRule) isIndependent(call *ast.CallExpr) bool {
	name := mutationCalleeName(call.Fun)
	return name != "" && r.independent[name]
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
	// Обращение к хранилищу идёт с контекстом. Без него это настройка самого объекта
	// (repo.SetEnvironment(env), repo.SetLogger(l)) — она ничего не сохраняет и в
	// транзакции не нуждается.
	if len(call.Args) == 0 || !isContextArg(info.TypeOf(call.Args[0])) {
		return "", false
	}
	return method, true
}

// isContextArg reports whether the argument is a context.Context.
func isContextArg(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == "Context" && obj.Pkg() != nil && obj.Pkg().Path() == "context"
}

// txCallSite is one place a function is called from: either directly inside a transaction
// callback, or from the body of a named caller whose own coverage decides the site's fate.
type txCallSite struct {
	underTx bool
	caller  string
}

// functionsUnderTransaction lists functions reachable ONLY from inside a transaction callback.
//
// The wrapper rarely sits in the same function as the writes: a service opens the transaction
// and calls a helper that performs them. Without this pass every such helper would be reported
// even though its writes are atomic. A helper with even one bare call site is not covered:
// that call executes the writes without a transaction.
func (r *MultiWriteNoTransactionRule) functionsUnderTransaction(ctx *core.GoProjectContext) map[string]bool {
	covered := make(map[string]bool)
	callers := make(map[string][]txCallSite)

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
						for _, name := range calledFunctions(call, info) {
							callers[name] = append(callers[name], txCallSite{underTx: true})
						}
						// Внутрь не спускаемся: те же вызовы иначе запишутся второй раз
						// как голые call sites владельца.
						return false
					}
					// Каждый вызов классифицируется в своём собственном визите —
					// берём только непосредственного callee, вложенные вызовы
					// аргументов обойдёт сам Inspect.
					if name := resolvedCalleeName(call, info); name != "" {
						callers[name] = append(callers[name], txCallSite{caller: owner})
					}
					return true
				})
				if opensTx && owner != "" {
					covered[owner] = true
				}
				return true
			})
		}
	}

	// Неподвижная точка: функция покрыта, когда каждый её call site либо лежит в
	// колбэке транзакции, либо принадлежит уже покрытой функции.
	for changed := true; changed; {
		changed = false
		for name, sites := range callers {
			if covered[name] {
				continue
			}
			if !allSitesUnderTransaction(sites, covered) {
				continue
			}
			covered[name] = true
			changed = true
		}
	}
	return covered
}

// allSitesUnderTransaction reports whether every call site is transaction-covered.
func allSitesUnderTransaction(sites []txCallSite, covered map[string]bool) bool {
	for _, site := range sites {
		if site.underTx {
			continue
		}
		if site.caller == "" || !covered[site.caller] {
			return false
		}
	}
	return true
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
