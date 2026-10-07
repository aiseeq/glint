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
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/types/typeutil"
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
//   - Writes of handlers chained on a flag: a helper that returns true in its first bool
//     result on every path that wrote (handled, applied), with a caller that leaves on
//     that flag (`if handled || err != nil { return }`), never meets the next handler's
//     write on the same path.
//   - A write whose error sends the path away: a write that failed did not happen, and a
//     helper that wrote and then returned an error leaves a caller that returns on that
//     error without meeting the caller's next write.
//   - Writes made while a failure is handled - in the branch on `err != nil` that ends
//     the function: they record the failure, and a transaction would roll that record
//     back exactly when it is needed. The pair to fix, if any, is the writes of the
//     operation itself.
//   - Writes inside a goroutine body: that work outlives the function and cannot share its
//     transaction. Project spawners that hide the `go` inside a helper, and telemetry that
//     must survive precisely when the business operation fails, are listed in
//     independent_calls.
//   - Writes already inside a transaction runner's callback, and functions that are only
//     ever reached from inside one — the wrapper does not have to sit in the same function
//     as the writes, and requiring that would push every helper back into one long method.
//     A runner is a function named in transaction_functions, or a project function that
//     opens a transaction (BeginTx) and calls its callback parameter, or hands that
//     callback on into another runner's callback (withLedgerTx over
//     runInDBTx).
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

// multiWriteMutation matches the name of a method that changes state;
// Get/List/Find/Count do not match.
var multiWriteMutation = regexp.MustCompile(`^(Create|Insert|Update|Upsert|Delete|Remove|Save|Store|Set|Mark|Apply|Attach|Detach|Claim|Reject|Approve|Cancel|Expire|Increment|Decrement|Backfill)[A-Z]\w*$`)

// multiWriteStoreType is the default store_types: the receiver types that
// count as a store.
var multiWriteStoreType = regexp.MustCompile(`(?i)(repo|repository|store|dao)(interface|impl)?$`)

// NewMultiWriteNoTransactionRule creates the rule.
func NewMultiWriteNoTransactionRule() *MultiWriteNoTransactionRule {
	r := &MultiWriteNoTransactionRule{
		BaseRule: rules.NewBaseRule(
			"multi-write-no-transaction",
			"patterns",
			"Detects two or more persistent writes in one function that are not wrapped in a transaction",
			core.SeverityHigh,
		),
	}
	r.setDefaults()
	return r
}

// setDefaults sets the settings Configure may override, so that a setting
// left out of a configuration keeps its default rather than a value an earlier
// configuration gave.
func (r *MultiWriteNoTransactionRule) setDefaults() {
	r.mutation = multiWriteMutation
	r.storeType = multiWriteStoreType
	r.txRunners = map[string]bool{
		"RunInTx":          true,
		"RunInTransaction": true,
		"WithTransaction":  true,
		"InTransaction":    true,
		"Transact":         true,
	}
	// Функция, сама открывающая транзакцию и пишущая через её объект, а не через колбэк.
	r.txOpeners = map[string]bool{"BeginTx": true, "BeginTxx": true, "Begin": true}
	// Проектные запускалки горутин и телеметрия задаются в конфиге: в языке ни те, ни
	// другие ничем не выделены. Голый `go` разбирается без настройки.
	r.independent = map[string]bool{}
}

// Configure accepts overrides for what counts as a store and as a transaction runner.
func (r *MultiWriteNoTransactionRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return fmt.Errorf("configure multi-write-no-transaction: %w", err)
	}
	r.setDefaults()
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
	txRunners, present, err := rules.NameSetSetting(settings, r.Name(), "transaction_functions")
	if err != nil {
		return err
	}
	if present {
		r.txRunners = txRunners
	}
	independent, present, err := rules.NameSetSetting(settings, r.Name(), "independent_calls")
	if err != nil {
		return err
	}
	if present {
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

	runners := r.derivedTransactionRunners(ctx)
	covered := r.functionsUnderTransaction(ctx, runners)
	graph := r.buildGraph(ctx)
	graph.runners = runners

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
	// failing: the write runs while a failure is handled, and records it.
	failing bool
	// loop: the write is the next item of a loop that returns at the first
	// failed item.
	loop bool
}

// where describes the write for the report: имя метода и путь до него.
func (w writeCall) where() string {
	if len(w.via) == 0 {
		return w.method
	}
	return w.method + " (via " + strings.Join(w.via, " → ") + ")"
}

// through returns the write as seen from a caller of helper.
func (w writeCall) through(helper string) writeCall {
	return writeCall{method: w.method, via: append([]string{helper}, w.via...), failing: w.failing, loop: w.loop}
}

// errOutcome is what a path knows about an error value: nothing, that it is
// nil, or that it is not.
type errOutcome int

const (
	outcomeUnknown errOutcome = iota
	outcomeNil
	outcomeNonNil
)

// flagOutcome is what a path knows about a bool flag: nothing, false or true.
type flagOutcome int

const (
	flagUnknown flagOutcome = iota
	flagFalse
	flagTrue
)

// writePath is the flow state of one control-flow path: the write it has
// performed so far, if any. A path never carries two distinct writes — the
// second one is the finding, recorded in the function summary, and the path
// keeps its first write — so a function has at most one path per written
// method plus the path without writes.
//
// The path also knows what became of the errors it met, so that the branch
// on `err != nil` keeps only the paths on which the call failed: a write
// that failed did not happen, and a helper that returned an error goes on
// with its failing exits only.
type writePath struct {
	write *writeCall
	// failing: the path is inside the handling of an error, in a branch that
	// ends the function.
	failing bool
	// errVar is the error variable the path last assigned, errState what the
	// path knows about it; at a function exit errVar is nil and errState is
	// the outcome of the returned error.
	errVar   types.Object
	errState errOutcome
	// resultCall is the call just evaluated and result the outcome of its
	// error result on this path; the statement that holds the call binds it.
	resultCall *ast.CallExpr
	result     errOutcome
	// flagVar is the bool variable bound to the first bool result of a
	// project call (handled, applied), flagState what the path knows about
	// it; at a function exit flagVar is nil and flagState is the value the
	// function returns in its first bool result. resultFlag is that value
	// for the call just evaluated.
	flagVar    types.Object
	flagState  flagOutcome
	resultFlag flagOutcome
}

func writePathKey(path writePath) string {
	method := ""
	if path.write != nil {
		method = path.write.method
		if path.write.failing {
			method += "!"
		}
	}
	errVar, resultCall := "", ""
	if path.errVar != nil {
		errVar = flowPosKey(path.errVar.Pos())
	}
	if path.resultCall != nil {
		resultCall = flowPosKey(path.resultCall.Pos())
	}
	flagVar := ""
	if path.flagVar != nil {
		flagVar = flowPosKey(path.flagVar.Pos())
	}
	return flowPathKey(method, strconv.FormatBool(path.failing), errVar, strconv.Itoa(int(path.errState)), resultCall, strconv.Itoa(int(path.result)),
		flagVar, strconv.Itoa(int(path.flagState)), strconv.Itoa(int(path.resultFlag)))
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
	for i, known := range s.writes {
		if known.method == write.method {
			// A write made on the main path pairs in the callers; the same
			// method met only while handling a failure does not.
			if known.failing && !write.failing {
				s.writes[i] = write
			}
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
	rule *MultiWriteNoTransactionRule
	// runners are the project functions that run a callback in a transaction.
	runners   map[string]bool
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
	analyzer := &writeFlowAnalyzer{graph: g, info: node.info, summary: summary, aborting: loopAbortingCalls(node.decl.Body)}
	var signature *types.Signature
	if fn, ok := node.info.Defs[node.decl.Name].(*types.Func); ok {
		signature, _ = fn.Type().(*types.Signature)
	}
	summary.exits = analyzer.walkBody(node.decl.Body, signature, []writePath{{}})
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
	message := fmt.Sprintf(
		"%s changes stored state more than once without a transaction: %s and %s — a failure between them leaves the record half-applied",
		node.display, pair[0].where(), pair[1].where(),
	)
	if pair[1].loop {
		message = fmt.Sprintf(
			"%s writes %s once per item of a loop without a transaction and returns at the first failure — the items before it stay written, the rest do not",
			node.display, pair[1].where(),
		)
	}
	v := r.CreateViolation(node.file, pos.Line, message)
	v.Column = pos.Column
	v.WithSuggestion("Wrap the writes in one transaction so the operation either applies fully or leaves no trace")
	// Имя функции в контексте — то, по чему `function:` в конфиге исключает
	// одну осознанно разделённую пару, не глуша правило на весь файл.
	v.WithContext("function", node.display)
	return v
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
	// signature is the signature of the body being walked, nil when unknown.
	signature *types.Signature
	// aborting are the calls made once per item of a loop that returns at
	// the first one failing.
	aborting map[*ast.CallExpr]bool
}

// walkBody walks a function or closure body and returns the states of the
// paths leaving it.
func (a *writeFlowAnalyzer) walkBody(body *ast.BlockStmt, signature *types.Signature, paths []writePath) []writePath {
	outer, outerSignature := a.exits, a.signature
	a.exits, a.signature = nil, signature
	walker := &flowWalker[[]writePath, struct{}]{rule: a}
	edges := walker.walk(body, paths, struct{}{})
	exits := joinWritePaths(a.exits, settleWritePaths(edges.next))
	a.exits, a.signature = outer, outerSignature
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
		exits := make([]writePath, 0, len(paths))
		for _, path := range paths {
			outcome := a.returnOutcome(node, path)
			flag := a.returnFlag(node, path)
			path.errVar, path.errState = nil, outcome
			path.flagVar, path.flagState = nil, flag
			path.resultCall, path.result, path.resultFlag = nil, outcomeUnknown, flagUnknown
			exits = append(exits, path)
		}
		a.exits = joinWritePaths(a.exits, exits)
		return nil, true
	case *ast.AssignStmt:
		paths = a.bindErrors(node, a.scan(node, paths))
		return paths, len(paths) == 0
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
	paths = settleWritePaths(paths)
	return paths, len(paths) == 0
}

// settleWritePaths forgets the outcome of the last call once the statement
// holding it is done.
func settleWritePaths(paths []writePath) []writePath {
	for i := range paths {
		paths[i].resultCall, paths[i].result, paths[i].resultFlag = nil, outcomeUnknown, flagUnknown
	}
	return joinWritePaths(paths, nil)
}

func (a *writeFlowAnalyzer) ifCondition(stmt *ast.IfStmt, paths []writePath, _ struct{}) ([]writePath, []writePath) {
	paths = settleWritePaths(a.scan(stmt.Cond, paths))
	thenFacts, elseFacts := a.errorFacts(stmt.Cond)
	thenPaths := assumeErrors(slices.Clone(paths), thenFacts)
	elsePaths := assumeErrors(paths, elseFacts)
	if failureFact(thenFacts) && branchEndsFunction(stmt.Body, a.info) {
		thenPaths = markFailing(thenPaths)
	}
	if failureFact(elseFacts) && stmt.Else != nil && branchEndsFunction(stmt.Else, a.info) {
		elsePaths = markFailing(elsePaths)
	}
	return thenPaths, elsePaths
}

func (a *writeFlowAnalyzer) flowExpr(expr ast.Expr, paths []writePath, _ struct{}) []writePath {
	return settleWritePaths(a.scan(expr, paths))
}

func (a *writeFlowAnalyzer) rangeVars(_ *ast.RangeStmt, paths []writePath, _ struct{}) []writePath {
	return paths
}

func (a *writeFlowAnalyzer) typeSwitchGuard(stmt ast.Stmt, paths []writePath, _ struct{}) []writePath {
	return settleWritePaths(a.scan(stmt, paths))
}

func (a *writeFlowAnalyzer) caseClause(sw ast.Stmt, clause *ast.CaseClause, paths []writePath, parent struct{}) ([]writePath, struct{}) {
	if _, isTypeSwitch := sw.(*ast.TypeSwitchStmt); !isTypeSwitch {
		for _, expr := range clause.List {
			paths = a.scan(expr, paths)
		}
	}
	return settleWritePaths(paths), parent
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
		// What the closure returned is not an error of this function.
		signature, _ := a.info.TypeOf(current).(*types.Signature)
		closed := a.walkBody(current.Body, signature, slices.Clone(paths))
		for i := range closed {
			closed[i].errVar, closed[i].errState = nil, outcomeUnknown
			closed[i].flagVar, closed[i].flagState = nil, flagUnknown
		}
		return joinWritePaths(paths, closed)
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
	if rule.isTransactionRunner(call, a.info, a.graph.runners) {
		// Записи внутри колбэка транзакции уже защищены — вглубь не идём.
		return withResult(paths, call, outcomeUnknown)
	}
	if rule.isIndependent(call) {
		// Запуск фоновой задачи или телеметрия: эти записи принадлежат другой
		// единице работы и в транзакцию вызывающего попасть не должны.
		return withResult(paths, call, outcomeUnknown)
	}
	paths = a.scan(call.Fun, paths)
	for _, arg := range call.Args {
		paths = a.scan(arg, paths)
	}
	// Вызов, сам являющийся записью, дальше не разворачиваем: делегирующая
	// обёртка иначе считалась бы второй записью поверх той же самой.
	if method, ok := rule.storeMutation(call, a.info); ok {
		return a.write(paths, writeCall{method: method}, call)
	}
	name := resolvedCalleeName(call, a.info)
	if name == "" {
		return withResult(paths, call, outcomeUnknown)
	}
	callee := a.graph.summary(name)
	if callee == nil {
		return withResult(paths, call, outcomeUnknown)
	}
	return a.through(paths, callee, a.graph.funcs[name].display, call)
}

// withResult records the call as the one just evaluated, with the given
// outcome of its error result.
func withResult(paths []writePath, call *ast.CallExpr, outcome errOutcome) []writePath {
	for i := range paths {
		paths[i].resultCall, paths[i].result, paths[i].resultFlag = call, outcome, flagUnknown
	}
	return joinWritePaths(paths, nil)
}

// write adds one write to every path. A write that reports an error splits
// the path: it applied and returned nil, or it failed, did not happen, and
// returned an error.
func (a *writeFlowAnalyzer) write(paths []writePath, write writeCall, call *ast.CallExpr) []writePath {
	write.failing = allFailing(paths)
	a.summary.record(write)
	if a.aborting[call] && !write.failing {
		// The items written before the failing one stay written.
		next := write
		next.loop = true
		a.summary.offend(write, next)
	}
	next := make([]writePath, 0, 2*len(paths))
	for _, path := range paths {
		switch {
		case path.write == nil:
			written := write
			written.failing = path.failing
			applied := path
			applied.write = &written
			next = append(next, applied)
		case path.write.method != write.method && !path.failing:
			a.summary.offend(*path.write, write)
			next = append(next, path)
		default:
			// A retry of the same write is one write attempted twice; a
			// write while a failure is handled records the failure.
			next = append(next, path)
		}
	}
	if !returnsError(call, a.info) {
		return withResult(next, call, outcomeUnknown)
	}
	failed := withResult(slices.Clone(paths), call, outcomeNonNil)
	return joinWritePaths(withResult(next, call, outcomeNil), failed)
}

// through continues every path through a call of a summarised function.
func (a *writeFlowAnalyzer) through(paths []writePath, callee *writeSummary, helper string, call *ast.CallExpr) []writePath {
	if callee.offends {
		a.summary.calleeOffends = true
		a.summary.offend(callee.pair[0].through(helper), callee.pair[1].through(helper))
	}
	failing := allFailing(paths)
	for _, write := range callee.writes {
		write = write.through(helper)
		recorded := write
		recorded.failing = write.failing || failing
		a.summary.record(recorded)
		if write.failing {
			continue
		}
		for _, path := range paths {
			if path.write != nil && path.write.method != write.method && !path.failing {
				a.summary.offend(*path.write, write)
			}
		}
	}
	next := make([]writePath, 0, len(paths)*len(callee.exits))
	for _, path := range paths {
		for _, exit := range callee.exits {
			continued := path
			continued.resultCall, continued.result, continued.resultFlag = call, exit.errState, exit.flagState
			if path.write == nil && exit.write != nil {
				written := exit.write.through(helper)
				written.failing = written.failing || path.failing
				continued.write = &written
			}
			// Otherwise the path's own write stays; a different one from
			// the callee is already recorded as the pair.
			next = append(next, continued)
		}
	}
	return joinWritePaths(next, nil)
}

// allFailing reports whether every path is handling a failure.
func allFailing(paths []writePath) bool {
	for _, path := range paths {
		if !path.failing {
			return false
		}
	}
	return len(paths) > 0
}

// markFailing marks the paths as handling a failure.
func markFailing(paths []writePath) []writePath {
	for i := range paths {
		paths[i].failing = true
	}
	return joinWritePaths(paths, nil)
}

// returnsError reports whether the call's last result is an error.
func returnsError(call *ast.CallExpr, info *types.Info) bool {
	signature, ok := info.TypeOf(call.Fun).(*types.Signature)
	return ok && lastResultIsError(signature)
}

// lastResultIsError reports whether the signature's last result is an error.
func lastResultIsError(signature *types.Signature) bool {
	if signature == nil || signature.Results().Len() == 0 {
		return false
	}
	return isErrorType(signature.Results().At(signature.Results().Len() - 1).Type())
}

// bindErrors hands the outcome of the call just evaluated to the error
// variable the assignment stores it in; any other value assigned to an error
// variable is judged by its spelling.
func (a *writeFlowAnalyzer) bindErrors(assign *ast.AssignStmt, paths []writePath) []writePath {
	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		obj := a.info.Defs[ident]
		if obj == nil {
			obj = a.info.Uses[ident]
		}
		if obj == nil || !isErrorType(obj.Type()) {
			continue
		}
		var rhs ast.Expr
		switch {
		case len(assign.Rhs) == len(assign.Lhs):
			rhs = ast.Unparen(assign.Rhs[i])
		case len(assign.Rhs) == 1 && i == len(assign.Lhs)-1:
			rhs = ast.Unparen(assign.Rhs[0]) // the error of a call returning several values
		}
		for j := range paths {
			outcome := outcomeUnknown
			if call, isCall := rhs.(*ast.CallExpr); isCall && call == paths[j].resultCall {
				outcome = paths[j].result
			}
			if outcome == outcomeUnknown && rhs != nil && len(assign.Rhs) == len(assign.Lhs) {
				outcome = a.errorExprOutcome(rhs, paths[j])
			}
			paths[j].errVar, paths[j].errState = obj, outcome
		}
	}
	a.bindFlag(assign, paths)
	return settleWritePaths(paths)
}

// firstBoolResult returns the index of the signature's first bool result, or -1.
func firstBoolResult(signature *types.Signature) int {
	if signature == nil {
		return -1
	}
	for i := 0; i < signature.Results().Len(); i++ {
		if isBoolType(signature.Results().At(i).Type()) {
			return i
		}
	}
	return -1
}

// bindFlag binds the first bool result of the call just evaluated, when the
// path knows its value, to the variable the assignment stores it in; a later
// assignment to the tracked variable replaces what the path knows.
func (a *writeFlowAnalyzer) bindFlag(assign *ast.AssignStmt, paths []writePath) {
	var call *ast.CallExpr
	index := -1
	if len(assign.Rhs) == 1 {
		if c, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); ok {
			signature, _ := a.info.TypeOf(c.Fun).(*types.Signature)
			if signature != nil && signature.Results().Len() == len(assign.Lhs) {
				call, index = c, firstBoolResult(signature)
			}
		}
	}
	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		obj := a.info.Defs[ident]
		if obj == nil {
			obj = a.info.Uses[ident]
		}
		if obj == nil {
			continue
		}
		for j := range paths {
			switch {
			case i == index && call == paths[j].resultCall && paths[j].resultFlag != flagUnknown:
				paths[j].flagVar, paths[j].flagState = obj, paths[j].resultFlag
			case obj == paths[j].flagVar:
				state := flagUnknown
				if len(assign.Rhs) == len(assign.Lhs) {
					state = boolLiteralFlag(assign.Rhs[i])
				}
				paths[j].flagState = state
			}
		}
	}
}

// boolLiteralFlag judges true and false literals.
func boolLiteralFlag(expr ast.Expr) flagOutcome {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return flagUnknown
	}
	switch ident.Name {
	case "true":
		return flagTrue
	case "false":
		return flagFalse
	}
	return flagUnknown
}

// returnFlag judges the value a return statement hands back in the
// function's first bool result on the path.
func (a *writeFlowAnalyzer) returnFlag(ret *ast.ReturnStmt, path writePath) flagOutcome {
	index := firstBoolResult(a.signature)
	if index < 0 || len(ret.Results) != a.signature.Results().Len() {
		return flagUnknown
	}
	expr := ast.Unparen(ret.Results[index])
	if ident, ok := expr.(*ast.Ident); ok && path.flagVar != nil && a.info.Uses[ident] == path.flagVar {
		return path.flagState
	}
	return boolLiteralFlag(expr)
}

// returnOutcome judges the error a return statement hands back on the path.
func (a *writeFlowAnalyzer) returnOutcome(ret *ast.ReturnStmt, path writePath) errOutcome {
	if !lastResultIsError(a.signature) || len(ret.Results) == 0 {
		return outcomeUnknown
	}
	last := ast.Unparen(ret.Results[len(ret.Results)-1])
	if call, ok := last.(*ast.CallExpr); ok && call == path.resultCall && path.result != outcomeUnknown {
		return path.result
	}
	if len(ret.Results) != a.signature.Results().Len() {
		return outcomeUnknown // `return f()` of a call returning several values
	}
	return a.errorExprOutcome(last, path)
}

// errorExprOutcome judges an error expression by its spelling: nil, the
// error variable the path tracks, a sentinel error variable of a package, or
// a freshly built error.
func (a *writeFlowAnalyzer) errorExprOutcome(expr ast.Expr, path writePath) errOutcome {
	switch node := ast.Unparen(expr).(type) {
	case *ast.Ident:
		switch obj := a.info.Uses[node].(type) {
		case *types.Nil:
			return outcomeNil
		case *types.Var:
			if path.errVar != nil && types.Object(obj) == path.errVar {
				return path.errState
			}
			if isPackageLevelVar(obj) {
				return outcomeNonNil
			}
		}
	case *ast.SelectorExpr:
		if obj, ok := a.info.Uses[node.Sel].(*types.Var); ok && isPackageLevelVar(obj) {
			return outcomeNonNil
		}
	case *ast.CallExpr:
		if fn, ok := typeutil.Callee(a.info, node).(*types.Func); ok && fn.Pkg() != nil &&
			((fn.Pkg().Path() == "fmt" && fn.Name() == "Errorf") || (fn.Pkg().Path() == "errors" && fn.Name() == "New")) {
			return outcomeNonNil
		}
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			if _, ok := node.X.(*ast.CompositeLit); ok {
				return outcomeNonNil
			}
		}
	case *ast.CompositeLit:
		return outcomeNonNil
	}
	return outcomeUnknown
}

// isPackageLevelVar reports whether the variable is declared at package level:
// a sentinel error such as ErrNotFound.
func isPackageLevelVar(obj *types.Var) bool {
	return obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope()
}

// errorFact is what a branch condition says about an error variable.
type errorFact struct {
	variable types.Object
	nonNil   bool
	// flag: the fact is about a bool flag, nonNil meaning it is true.
	flag bool
}

// errorFacts returns what the condition says about error variables in the
// branch it holds in and in the one it does not: `err != nil` in the then
// branch, and through && and || what every conjunct or disjunct says.
func (a *writeFlowAnalyzer) errorFacts(cond ast.Expr) (thenFacts, elseFacts []errorFact) {
	switch node := ast.Unparen(cond).(type) {
	case *ast.Ident:
		if obj := a.info.Uses[node]; obj != nil && isBoolType(obj.Type()) {
			return []errorFact{{variable: obj, nonNil: true, flag: true}}, []errorFact{{variable: obj, flag: true}}
		}
		return nil, nil
	case *ast.UnaryExpr:
		if node.Op == token.NOT {
			thenFacts, elseFacts = a.errorFacts(node.X)
			return elseFacts, thenFacts
		}
		return nil, nil
	}
	binary, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok {
		return nil, nil
	}
	switch binary.Op {
	case token.LAND:
		leftThen, _ := a.errorFacts(binary.X)
		rightThen, _ := a.errorFacts(binary.Y)
		return append(leftThen, rightThen...), nil
	case token.LOR:
		_, leftElse := a.errorFacts(binary.X)
		_, rightElse := a.errorFacts(binary.Y)
		return nil, append(leftElse, rightElse...)
	case token.NEQ, token.EQL:
		operand := binary.X
		if isNilIdent(ast.Unparen(operand)) {
			operand = binary.Y
		} else if !isNilIdent(ast.Unparen(binary.Y)) {
			return nil, nil
		}
		ident, ok := ast.Unparen(operand).(*ast.Ident)
		if !ok {
			return nil, nil
		}
		obj := a.info.Uses[ident]
		if obj == nil || !isErrorType(obj.Type()) {
			return nil, nil
		}
		failed := binary.Op == token.NEQ
		return []errorFact{{variable: obj, nonNil: failed}}, []errorFact{{variable: obj, nonNil: !failed}}
	}
	return nil, nil
}

// assumeErrors keeps the paths the facts allow and refines what they know.
func assumeErrors(paths []writePath, facts []errorFact) []writePath {
	if len(facts) == 0 {
		return paths
	}
	kept := paths[:0]
	for _, path := range paths {
		possible := true
		for _, fact := range facts {
			if fact.flag {
				if !assumeFlag(&path, fact) {
					possible = false
					break
				}
				continue
			}
			if path.errVar == nil || path.errVar != fact.variable {
				continue
			}
			known := outcomeNil
			if fact.nonNil {
				known = outcomeNonNil
			}
			if path.errState != outcomeUnknown && path.errState != known {
				possible = false
				break
			}
			path.errState = known
		}
		if possible {
			kept = append(kept, path)
		}
	}
	return joinWritePaths(kept, nil)
}

// assumeFlag refines what the path knows about its flag by the fact, and
// reports false when the path cannot take the branch.
func assumeFlag(path *writePath, fact errorFact) bool {
	if path.flagVar == nil || path.flagVar != fact.variable {
		return true
	}
	known := flagFalse
	if fact.nonNil {
		known = flagTrue
	}
	if path.flagState != flagUnknown && path.flagState != known {
		return false
	}
	path.flagState = known
	return true
}

// failureFact reports whether the facts say that an error is set.
func failureFact(facts []errorFact) bool {
	for _, fact := range facts {
		if fact.nonNil && !fact.flag {
			return true
		}
	}
	return false
}

// branchEndsFunction reports whether the branch ends by leaving the function:
// its last statement returns, panics or exits.
func branchEndsFunction(branch ast.Stmt, info *types.Info) bool {
	block, ok := branch.(*ast.BlockStmt)
	if !ok || len(block.List) == 0 {
		return false
	}
	switch last := block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		return stmtNoReturn(last, info, nil) != callReturns
	}
	return false
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

// isTransactionRunner reports whether the call hands a callback to a transaction runner:
// one named in transaction_functions or a project function derived as one.
func (r *MultiWriteNoTransactionRule) isTransactionRunner(call *ast.CallExpr, info *types.Info, derived map[string]bool) bool {
	name := mutationCalleeName(call.Fun)
	if name != "" && r.txRunners[name] {
		return true
	}
	return len(derived) > 0 && derived[resolvedCalleeName(call, info)]
}

// derivedTransactionRunners lists the project functions that run a callback parameter in
// a transaction: they open one (BeginTx) and call the callback, or hand the callback on
// into the callback of another runner. Computed to a fixed point, so a wrapper over a
// wrapper is a runner too.
func (r *MultiWriteNoTransactionRule) derivedTransactionRunners(ctx *core.GoProjectContext) map[string]bool {
	type candidate struct {
		body      *ast.BlockStmt
		info      *types.Info
		callbacks map[types.Object]bool
	}
	candidates := map[string]candidate{}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file == nil || file.GoAST == nil {
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
				callbacks := callbackParams(fn.Type, info)
				if len(callbacks) > 0 {
					candidates[obj.FullName()] = candidate{body: fn.Body, info: info, callbacks: callbacks}
				}
			}
		}
	}
	runners := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for name, c := range candidates {
			if runners[name] {
				continue
			}
			if r.runsCallbackInTransaction(c.body, c.info, c.callbacks, runners) {
				runners[name] = true
				changed = true
			}
		}
	}
	return runners
}

// callbackParams returns the parameters of function type.
func callbackParams(ftype *ast.FuncType, info *types.Info) map[types.Object]bool {
	callbacks := map[types.Object]bool{}
	for _, field := range ftype.Params.List {
		for _, name := range field.Names {
			obj := info.Defs[name]
			if obj == nil {
				continue
			}
			if _, ok := obj.Type().Underlying().(*types.Signature); ok {
				callbacks[obj] = true
			}
		}
	}
	return callbacks
}

// runsCallbackInTransaction reports whether the body opens a transaction and calls one of
// the callbacks, or passes one of them (directly or called from a closure) to a runner.
func (r *MultiWriteNoTransactionRule) runsCallbackInTransaction(body *ast.BlockStmt, info *types.Info, callbacks map[types.Object]bool, runners map[string]bool) bool {
	opens, calls, handsOn := false, false, false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if r.txOpeners[mutationCalleeName(call.Fun)] {
			opens = true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && callbacks[info.Uses[ident]] {
			calls = true
		}
		if r.isTransactionRunner(call, info, runners) {
			for _, arg := range call.Args {
				if usesCallback(arg, info, callbacks) {
					handsOn = true
				}
			}
		}
		return true
	})
	return handsOn || (opens && calls)
}

// usesCallback reports whether the expression names one of the callbacks.
func usesCallback(expr ast.Expr, info *types.Info, callbacks map[types.Object]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && callbacks[info.Uses[ident]] {
			found = true
		}
		return !found
	})
	return found
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
func (r *MultiWriteNoTransactionRule) functionsUnderTransaction(ctx *core.GoProjectContext, runners map[string]bool) map[string]bool {
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
					if r.isTransactionRunner(call, info, runners) {
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

// loopAbortingCalls returns the calls a loop makes once per item and whose
// failure returns from the function:
//
//	for _, item := range items {
//	    if err := repo.UpdateItem(ctx, item); err != nil {
//	        return err
//	    }
//	}
//
// A failing item ends the function with the items before it written.
// Closures are left out: they run on their own schedule.
func loopAbortingCalls(body *ast.BlockStmt) map[*ast.CallExpr]bool {
	aborting := make(map[*ast.CallExpr]bool)
	var walk func(n ast.Node, inLoop bool)
	walk = func(n ast.Node, inLoop bool) {
		ast.Inspect(n, func(child ast.Node) bool {
			switch node := child.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ForStmt:
				if child != n {
					walk(node.Body, !advancesCursor(node.Body))
					return false
				}
			case *ast.RangeStmt:
				if child != n {
					walk(node.Body, !advancesCursor(node.Body))
					return false
				}
			case *ast.BlockStmt:
				if inLoop {
					markAbortingCalls(node.List, aborting)
				}
			case *ast.CaseClause:
				if inLoop {
					markAbortingCalls(node.Body, aborting)
				}
			}
			return true
		})
	}
	walk(body, false)
	return aborting
}

// cursorName names the position a page walk resumes from.
var cursorName = regexp.MustCompile(`(?i)cursor|offset|after|since|next|token|checkpoint`)

// advancesCursor reports a loop body moving a cursor on: a page walk whose
// every write is progress kept, and the next run resumes after it.
func advancesCursor(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && assign.Tok == token.ASSIGN {
			for _, lhs := range assign.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && cursorName.MatchString(id.Name) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// markAbortingCalls marks the calls of a statement list whose error the next
// check returns: if err := call(); err != nil { return }, or err := call()
// followed by that check.
func markAbortingCalls(list []ast.Stmt, aborting map[*ast.CallExpr]bool) {
	for i, stmt := range list {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok && ifStmt.Init != nil {
			if call, errName := errorCallAssign(ifStmt.Init); call != nil && returnsOnError(ifStmt, errName) {
				aborting[call] = true
			}
			continue
		}
		if i+1 >= len(list) {
			continue
		}
		next, ok := list[i+1].(*ast.IfStmt)
		if !ok || next.Init != nil {
			continue
		}
		if call, errName := errorCallAssign(stmt); call != nil && returnsOnError(next, errName) {
			aborting[call] = true
		}
	}
}

// errorCallAssign returns the call an assignment takes its last result,
// named as an error variable, from.
func errorCallAssign(stmt ast.Stmt) (*ast.CallExpr, string) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
		return nil, ""
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return nil, ""
	}
	last, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	if !ok || last.Name == "_" {
		return nil, ""
	}
	return call, last.Name
}

// returnsOnError reports an if on `name != nil` whose body ends in a return.
func returnsOnError(stmt *ast.IfStmt, name string) bool {
	cond, ok := ast.Unparen(stmt.Cond).(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return false
	}
	id, ok := ast.Unparen(cond.X).(*ast.Ident)
	if !ok || id.Name != name {
		return false
	}
	if nilIdent, ok := ast.Unparen(cond.Y).(*ast.Ident); !ok || nilIdent.Name != "nil" {
		return false
	}
	if len(stmt.Body.List) == 0 {
		return false
	}
	_, returns := stmt.Body.List[len(stmt.Body.List)-1].(*ast.ReturnStmt)
	return returns
}
