package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTestWaitPassesOnExhaustionRule())
	rules.Register(NewTestFixedSleepBeforeAssertRule())
	rules.Register(NewTestAcceptsServerErrorRule())
	rules.Register(NewTestCleanupRegisteredLateRule())
	rules.Register(NewTestDeletesSharedDataRule())
	rules.Register(NewTestChannelReceiveWithoutTimeoutRule())
}

// testingBody is a function body that holds a testing handle: a test, a
// subtest literal, a helper taking *testing.T.
type testingBody struct {
	body    *ast.BlockStmt
	results *ast.FieldList
	handles map[string]bool
}

// testingBodies returns the bodies of a Go file that have a testing handle in
// scope, each with the handles it sees. A literal without a handle of its own
// (a goroutine) is a body of the function around it.
func testingBodies(file *ast.File) []testingBody {
	testingPkgs := testingImportNames(file)
	if len(testingPkgs) == 0 {
		return nil
	}
	var bodies []testingBody
	var walk func(body *ast.BlockStmt, results *ast.FieldList, handles map[string]bool)
	walk = func(body *ast.BlockStmt, results *ast.FieldList, handles map[string]bool) {
		if len(handles) > 0 {
			bodies = append(bodies, testingBody{body: body, results: results, handles: handles})
		}
		ast.Inspect(body, func(n ast.Node) bool {
			lit, ok := n.(*ast.FuncLit)
			if !ok {
				return true
			}
			walk(lit.Body, lit.Type.Results, scopeTestingHandles(handles, lit.Type.Params, testingPkgs))
			return false
		})
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		walk(fn.Body, fn.Type.Results, scopeTestingHandles(nil, fn.Type.Params, testingPkgs))
	}
	return bodies
}

// ownNodes visits the nodes of a body without entering function literals.
func ownNodes(body ast.Node, visit func(ast.Node) bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		return visit(n)
	})
}

// failsTest reports a node holding a call that can fail the test.
func failsTest(node ast.Node, handles map[string]bool) bool {
	found := false
	ownNodes(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && (callIsFailing(call, handles) || isSkipCall(call, handles)) {
			found = true
		}
		return !found
	})
	return found
}

func isSkipCall(call *ast.CallExpr, handles map[string]bool) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := sel.X.(*ast.Ident)
	return ok && handles[receiver.Name] && strings.HasPrefix(sel.Sel.Name, "Skip")
}

func testReport(rule *rules.BaseRule, ctx *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := rule.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	return v
}

// goTestFile reports a Go file of a test tree with its syntax.
func goTestFile(ctx *core.FileContext) bool {
	return ctx.IsGoFile() && ctx.HasGoAST() && ctx.IsTestFile()
}

// --- test-wait-passes-on-exhaustion ---------------------------------------

// TestWaitPassesOnExhaustionRule detects a test wait that gives up silently:
//
//	for {
//	    if confirmed(hash) { return }
//	    retryCount++
//	    if retryCount >= maxRetries {
//	        t.Logf("assuming confirmed")
//	        return
//	    }
//	}
//
// When the attempts run out the helper returns as if the awaited state had
// come, and the test goes on to pass whatever happened. The same holds for a
// loop bounded by its attempts that just ends.
type TestWaitPassesOnExhaustionRule struct{ *rules.BaseRule }

// NewTestWaitPassesOnExhaustionRule creates the rule
func NewTestWaitPassesOnExhaustionRule() *TestWaitPassesOnExhaustionRule {
	return &TestWaitPassesOnExhaustionRule{rules.NewBaseRule(
		"test-wait-passes-on-exhaustion",
		"patterns",
		"Detects a test wait that returns as if the awaited state came when its attempts or time run out",
		core.SeverityHigh,
	)}
}

var (
	attemptCounter = regexp.MustCompile(`(?i)retr|attempt|tries|^try|poll`)
	attemptBound   = regexp.MustCompile(`(?i)max|limit|total|budget`)
)

// AnalyzeFile reports the waits of a test tree that pass on exhaustion.
func (r *TestWaitPassesOnExhaustionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !goTestFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, tb := range testingBodies(ctx.GoAST) {
		if tb.results != nil && len(tb.results.List) > 0 {
			continue
		}
		forEachOwnStatementList(tb.body, func(list []ast.Stmt) {
			for i, stmt := range list {
				loop, ok := stmt.(*ast.ForStmt)
				if !ok {
					continue
				}
				for _, node := range r.silentGiveUps(loop, list[i+1:], tb.handles) {
					line := ctx.LineFor(node)
					if !ctx.IsSuppressed(line, r.Name()) {
						violations = append(violations, testReport(r.BaseRule, ctx, line,
							"Test wait gives up silently — when the attempts run out it returns as if the awaited state had come, and the test passes whatever happened",
							"Fail the test on exhaustion (t.Fatalf with what was last seen), or wait with require.Eventually"))
					}
				}
			}
		})
	}
	return violations
}

// silentGiveUps returns the exhaustion branches of the loop that return
// without failing, or the loop itself when it is bounded by its attempts,
// returns on success and nothing after it fails.
func (r *TestWaitPassesOnExhaustionRule) silentGiveUps(loop *ast.ForStmt, after []ast.Stmt, handles map[string]bool) []ast.Node {
	var found []ast.Node
	ownNodes(loop.Body, func(n ast.Node) bool {
		branch, ok := n.(*ast.IfStmt)
		if ok && exhausted(branch.Cond) && !failsTest(branch.Body, handles) && endsInBareReturn(branch.Body) {
			found = append(found, branch)
		}
		return true
	})
	if len(found) > 0 || loop.Cond == nil || !withinAttempts(loop.Cond) || !returnsInside(loop.Body) {
		return found
	}
	for _, stmt := range after {
		if failsTest(stmt, handles) {
			return nil
		}
	}
	return []ast.Node{loop}
}

// exhausted reports a condition true once the attempts or the time are used
// up: retries >= maxRetries, time.Since(start) > timeout, time.Now().After(deadline).
func exhausted(cond ast.Expr) bool {
	switch c := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		switch c.Op {
		case token.LOR, token.LAND:
			return exhausted(c.X) || exhausted(c.Y)
		case token.GEQ, token.GTR, token.EQL:
			return attemptExpr(c.X) && boundExpr(c.Y) || sinceCall(c.X)
		}
	case *ast.CallExpr:
		return timeNowMethod(c, "After")
	}
	return false
}

// withinAttempts reports a loop condition that holds while attempts or time
// remain: attempt < maxAttempts, time.Since(start) < timeout, time.Now().Before(deadline).
func withinAttempts(cond ast.Expr) bool {
	switch c := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		switch c.Op {
		case token.LAND:
			return withinAttempts(c.X) || withinAttempts(c.Y)
		case token.LSS, token.LEQ:
			return attemptExpr(c.X) && boundExpr(c.Y) || sinceCall(c.X)
		}
	case *ast.CallExpr:
		return timeNowMethod(c, "Before")
	}
	return false
}

func attemptExpr(expr ast.Expr) bool {
	name := lastName(expr)
	return name != "" && attemptCounter.MatchString(name)
}

func boundExpr(expr ast.Expr) bool {
	if lit, ok := ast.Unparen(expr).(*ast.BasicLit); ok {
		return lit.Kind == token.INT
	}
	name := lastName(expr)
	return name != "" && (attemptBound.MatchString(name) || attemptCounter.MatchString(name))
}

// lastName is the name of x, a.b.x or a.x().
func lastName(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.CallExpr:
		return lastName(e.Fun)
	}
	return ""
}

func sinceCall(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	return ok && isSelectorCall(call, "time", "Since")
}

// timeNowMethod reports time.Now().<method>(...).
func timeNowMethod(call *ast.CallExpr, method string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return false
	}
	now, ok := sel.X.(*ast.CallExpr)
	return ok && isSelectorCall(now, "time", "Now")
}

func endsInBareReturn(block *ast.BlockStmt) bool {
	if len(block.List) == 0 {
		return false
	}
	ret, ok := block.List[len(block.List)-1].(*ast.ReturnStmt)
	return ok && len(ret.Results) == 0
}

func returnsInside(block *ast.BlockStmt) bool {
	found := false
	ownNodes(block, func(n ast.Node) bool {
		if _, ok := n.(*ast.ReturnStmt); ok {
			found = true
		}
		return !found
	})
	return found
}

// --- test-fixed-sleep-before-assert ---------------------------------------

// TestFixedSleepBeforeAssertRule detects a test that sleeps a fixed time and
// then checks once:
//
//	time.Sleep(500 * time.Millisecond)
//	balance := getBalance(t, user)
//	require.True(t, balance.GreaterThan(min))
//
// The pause is a guess at how long the asynchronous work takes: on a loaded
// machine the check runs first and the test fails, on a fast one the test
// waits for nothing. Poll for the state with a deadline instead.
type TestFixedSleepBeforeAssertRule struct{ *rules.BaseRule }

// NewTestFixedSleepBeforeAssertRule creates the rule
func NewTestFixedSleepBeforeAssertRule() *TestFixedSleepBeforeAssertRule {
	return &TestFixedSleepBeforeAssertRule{rules.NewBaseRule(
		"test-fixed-sleep-before-assert",
		"patterns",
		"Detects a Go test that sleeps a fixed time and then asserts once — a guess at how long asynchronous work takes",
		core.SeverityMedium,
	)}
}

// minAwaitSleep is the shortest pause taken for waiting on asynchronous work;
// a shorter one only separates timestamps.
const minAwaitSleep = 100 // milliseconds

// sleepLookahead is how many statements after the pause may hold the check.
const sleepLookahead = 4

// AnalyzeFile reports the fixed pauses followed by an assertion.
func (r *TestFixedSleepBeforeAssertRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !goTestFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, tb := range testingBodies(ctx.GoAST) {
		inLoop := loopStatements(tb.body)
		forEachOwnStatementList(tb.body, func(list []ast.Stmt) {
			for i, stmt := range list {
				if inLoop[stmt] || !longSleep(stmt) {
					continue
				}
				end := min(len(list), i+1+sleepLookahead)
				if waitsForExpiry(list[max(0, i-1):end]) {
					continue
				}
				for _, next := range list[i+1 : end] {
					if !failsTest(next, tb.handles) {
						continue
					}
					line := ctx.LineFor(stmt)
					if !ctx.IsSuppressed(line, r.Name()) {
						violations = append(violations, testReport(r.BaseRule, ctx, line,
							"Test sleeps a fixed time and then checks once — the pause guesses how long the work takes: too short on a loaded machine, wasted on a fast one",
							"Poll for the expected state with a deadline (require.Eventually, or a loop that fails with the last value seen)"))
					}
					break
				}
			}
		})
	}
	return violations
}

var expiryName = regexp.MustCompile(`(?i)expir|ttl|shortlived|stale`)

// waitsForExpiry reports statements around a pause that name an expiry
// (expiredClient, shortLivedToken): the pause lets time pass on purpose,
// it does not wait for work.
func waitsForExpiry(stmts []ast.Stmt) bool {
	for _, stmt := range stmts {
		found := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && expiryName.MatchString(ident.Name) {
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// longSleep reports time.Sleep(d) with a constant d of at least minAwaitSleep.
func longSleep(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !isSelectorCall(call, "time", "Sleep") {
		return false
	}
	ms, ok := constantMillis(call.Args[0])
	return ok && ms >= minAwaitSleep
}

var durationUnits = map[string]float64{
	"Nanosecond": 1e-6, "Microsecond": 1e-3, "Millisecond": 1, "Second": 1e3, "Minute": 60e3, "Hour": 3600e3,
}

// constantMillis evaluates N * time.Unit, time.Unit and time.Duration(N) * time.Unit.
func constantMillis(expr ast.Expr) (float64, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		if isIdentNamed(e.X, "time") {
			unit, ok := durationUnits[e.Sel.Name]
			return unit, ok
		}
	case *ast.BinaryExpr:
		if e.Op != token.MUL {
			return 0, false
		}
		left, lok := constantNumber(e.X)
		right, rok := constantMillis(e.Y)
		if lok && rok {
			return left * right, true
		}
		left, lok = constantMillis(e.X)
		right, rok = constantNumber(e.Y)
		return left * right, lok && rok
	}
	return 0, false
}

// constantNumber evaluates a number literal or time.Duration(<literal>).
func constantNumber(expr ast.Expr) (float64, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		if e.Kind != token.INT && e.Kind != token.FLOAT {
			return 0, false
		}
		value, err := strconv.ParseFloat(e.Value, 64)
		return value, err == nil
	case *ast.CallExpr:
		if len(e.Args) == 1 {
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Duration" && isIdentNamed(sel.X, "time") {
				return constantNumber(e.Args[0])
			}
		}
	}
	return 0, false
}

// --- test-accepts-server-error-status --------------------------------------

// TestAcceptsServerErrorRule detects an assertion on a response status whose
// accepted range reaches the server errors:
//
//	assert.True(t, resp.StatusCode >= 200 && resp.StatusCode <= 503)
//
// The check passes when the endpoint is down or panics, so the test covers
// nothing it names. Assert the status the scenario produces.
type TestAcceptsServerErrorRule struct{ *rules.BaseRule }

// NewTestAcceptsServerErrorRule creates the rule
func NewTestAcceptsServerErrorRule() *TestAcceptsServerErrorRule {
	return &TestAcceptsServerErrorRule{rules.NewBaseRule(
		"test-accepts-server-error-status",
		"patterns",
		"Detects a test assertion whose accepted response statuses reach 5xx — it passes when the server fails",
		core.SeverityHigh,
	)}
}

// firstServerError is the lowest 5xx status.
const firstServerError = 500

var responseStatusName = regexp.MustCompile(`(?i)status|^code$`)

// AnalyzeFile reports the status assertions accepting server errors.
func (r *TestAcceptsServerErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !goTestFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	report := func(node ast.Node) {
		line := ctx.LineFor(node)
		if !ctx.IsSuppressed(line, r.Name()) {
			violations = append(violations, testReport(r.BaseRule, ctx, line,
				"Status assertion accepts server errors — the test passes when the endpoint fails with 5xx",
				"Assert the status the scenario produces (require.Equal(t, http.StatusOK, resp.StatusCode)); a test that tolerates an unavailable dependency should skip, not pass"))
		}
	}
	for _, tb := range testingBodies(ctx.GoAST) {
		ownNodes(tb.body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if callIsFailing(node, tb.handles) && assertsUpToServerError(node) {
					report(node)
				}
			case *ast.IfStmt:
				if failsTest(node.Body, tb.handles) && rejectsOnlyAbove(node.Cond) {
					report(node)
				}
			}
			return true
		})
	}
	return violations
}

// assertsUpToServerError reports an assertion admitting a status of 500 or above:
// a status <= 503 inside it, or assert.Less(t, status, 600).
func assertsUpToServerError(call *ast.CallExpr) bool {
	if name := callName(call); (name == "Less" || name == "LessOrEqual") && len(call.Args) >= 3 {
		bound, ok := statusBound(call.Args[2])
		return ok && responseStatusExpr(call.Args[1]) && (bound > firstServerError || name == "LessOrEqual" && bound >= firstServerError)
	}
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if cmp, ok := n.(*ast.BinaryExpr); ok && upperBoundOnStatus(cmp, token.LEQ, token.LSS) {
				found = true
			}
			return !found
		})
	}
	return found
}

// rejectsOnlyAbove reports a failing branch taken only for a status above a
// 5xx bound: if resp.StatusCode > 503 { t.Fatal(...) }.
func rejectsOnlyAbove(cond ast.Expr) bool {
	cmp, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	return ok && upperBoundOnStatus(cmp, token.GTR, token.GEQ)
}

// upperBoundOnStatus reports status <inclusive> N with N >= 500, or status
// <exclusive> N with N > 500.
func upperBoundOnStatus(cmp *ast.BinaryExpr, inclusive, exclusive token.Token) bool {
	if cmp.Op != inclusive && cmp.Op != exclusive || !responseStatusExpr(cmp.X) {
		return false
	}
	bound, ok := statusBound(cmp.Y)
	if !ok {
		return false
	}
	if cmp.Op == inclusive {
		return bound >= firstServerError
	}
	return bound > firstServerError
}

func responseStatusExpr(expr ast.Expr) bool {
	name := lastName(expr)
	return name != "" && responseStatusName.MatchString(name)
}

// statusBound evaluates a status literal or http.StatusXxx of the 5xx range.
func statusBound(expr ast.Expr) (int, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		if e.Kind != token.INT {
			return 0, false
		}
		value, err := strconv.Atoi(e.Value)
		return value, err == nil
	case *ast.SelectorExpr:
		if isIdentNamed(e.X, "http") {
			code, ok := httpServerErrors[e.Sel.Name]
			return code, ok
		}
	}
	return 0, false
}

var httpServerErrors = map[string]int{
	"StatusInternalServerError": 500, "StatusNotImplemented": 501, "StatusBadGateway": 502,
	"StatusServiceUnavailable": 503, "StatusGatewayTimeout": 504,
}

// --- test-cleanup-registered-late ------------------------------------------

// TestCleanupRegisteredLateRule detects a test that creates a resource and
// registers its cleanup only after another step that can stop the test:
//
//	err = client.AppendRange(ctx, sheet, row)   // the row exists from here
//	if err != nil { t.Fatalf(...) }
//	rowIndex, err := client.GetLastRowIndex(ctx, sheet)
//	if err != nil { t.Fatalf(...) }             // stops the test, the row stays
//	defer deleteRow(rowIndex)
//
// Register the cleanup right after the creation succeeds.
type TestCleanupRegisteredLateRule struct{ *rules.BaseRule }

// NewTestCleanupRegisteredLateRule creates the rule
func NewTestCleanupRegisteredLateRule() *TestCleanupRegisteredLateRule {
	return &TestCleanupRegisteredLateRule{rules.NewBaseRule(
		"test-cleanup-registered-late",
		"patterns",
		"Detects a test step that can stop the test between creating a resource and registering its cleanup — the resource leaks",
		core.SeverityMedium,
	)}
}

var creatingCall = regexp.MustCompile(`^(?:Create|Insert|Append|Register|Upload|Add|Put|Post|Save|Seed|Provision)`)

// AnalyzeFile reports the failing steps between a creation and its cleanup.
func (r *TestCleanupRegisteredLateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !goTestFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, tb := range testingBodies(ctx.GoAST) {
		list := tb.body.List
		for d, stmt := range list {
			if !cleanupRegistration(stmt, tb.handles) {
				continue
			}
			c, created := lastCreation(list[:d], tb.handles)
			if c < 0 || !created.cleanedBy(stmt) {
				continue
			}
			j := c + 1
			for j < d && nodeMentions(list[j], created.assigned) && failsTest(list[j], tb.handles) {
				j++ // checks of what the creation returned
			}
			for ; j < d; j++ {
				if !failsTest(list[j], tb.handles) {
					continue
				}
				line := ctx.LineFor(list[j])
				if !ctx.IsSuppressed(line, r.Name()) {
					violations = append(violations, testReport(r.BaseRule, ctx, line,
						"Test can stop here before the cleanup of what it created at line "+strconv.Itoa(ctx.LineFor(list[c]))+" is registered — the resource stays behind",
						"Register the cleanup (defer or t.Cleanup) right after the creation succeeds, before any other step that can fail"))
				}
				break
			}
		}
	}
	return violations
}

// cleanupRegistration reports a defer or <handle>.Cleanup; a deferred
// Unlock releases a lock, it cleans nothing up.
func cleanupRegistration(stmt ast.Stmt, handles map[string]bool) bool {
	switch s := stmt.(type) {
	case *ast.DeferStmt:
		name := callName(s.Call)
		return name != "Unlock" && name != "RUnlock"
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Cleanup" {
			return false
		}
		receiver, ok := sel.X.(*ast.Ident)
		return ok && handles[receiver.Name]
	}
	return false
}

// creation names what a creating statement touches: the object it called
// (client in client.AppendRange), every variable it assigned, and those of
// them that are not its error.
type creation struct {
	receiver string
	assigned map[string]bool
	values   map[string]bool
}

// cleanedBy reports a cleanup of this creation: one that reads what it
// returned or, when it returned only an error, the object it called.
func (c creation) cleanedBy(cleanup ast.Stmt) bool {
	if len(c.values) > 0 {
		return nodeMentions(cleanup, c.values)
	}
	return nodeMentions(cleanup, map[string]bool{c.receiver: true})
}

// lastCreation returns the index of the last statement that creates something
// through a call (CreateUser, AppendRange, ...), -1 when there is none.
func lastCreation(list []ast.Stmt, handles map[string]bool) (int, creation) {
	for i := len(list) - 1; i >= 0; i-- {
		if cleanupRegistration(list[i], handles) {
			return -1, creation{}
		}
		receiver := ""
		for _, call := range statementCalls(list[i]) {
			if receiver = creatingReceiver(call, handles); receiver != "" {
				break
			}
		}
		if receiver == "" {
			continue
		}
		created := creation{receiver: receiver, assigned: make(map[string]bool), values: make(map[string]bool)}
		if assign, ok := list[i].(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || ident.Name == "_" {
					continue
				}
				created.assigned[ident.Name] = true
				if !strings.HasPrefix(ident.Name, "err") {
					created.values[ident.Name] = true
				}
			}
		}
		return i, created
	}
	return -1, creation{}
}

// statementCalls returns the calls a statement makes itself: x.Create(...),
// v := x.Create(...), and the calls require/assert are handed.
func statementCalls(stmt ast.Stmt) []*ast.CallExpr {
	var call *ast.CallExpr
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		call, _ = s.X.(*ast.CallExpr)
	case *ast.AssignStmt:
		if len(s.Rhs) == 1 {
			call, _ = s.Rhs[0].(*ast.CallExpr)
		}
	}
	if call == nil {
		return nil
	}
	calls := []*ast.CallExpr{call}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (isIdentNamed(sel.X, "require") || isIdentNamed(sel.X, "assert")) {
		for _, arg := range call.Args {
			if inner, ok := arg.(*ast.CallExpr); ok {
				calls = append(calls, inner)
			}
		}
	}
	return calls
}

// creatingReceiver returns the object a creating method is called on. A
// helper handed the testing handle registers its own cleanup and is not one.
func creatingReceiver(call *ast.CallExpr, handles map[string]bool) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !creatingCall.MatchString(sel.Sel.Name) || callForwardsTestingT(call, handles) {
		return ""
	}
	ident := rootIdent(sel.X)
	if ident == nil {
		return ""
	}
	root := ident.Name
	if handles[root] || root == "require" || root == "assert" {
		return ""
	}
	return root
}

// nodeMentions reports a node reading one of the names.
func nodeMentions(node ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && names[ident.Name] {
			found = true
		}
		return !found
	})
	return found
}

// --- test-deletes-shared-data ----------------------------------------------

// TestDeletesSharedDataRule detects a test that deletes or rewrites rows
// picked by a production constant:
//
//	strategy := models.DefaultStrategyID
//	db.ExecContext(ctx, "DELETE FROM vault_snapshots WHERE strategy = $1", strategy)
//
// The rows the test clears are the ones the application itself uses: on a
// shared database the test wipes real data, and parallel tests wipe each
// other's. Scope test data by a value the test made.
type TestDeletesSharedDataRule struct{ *rules.BaseRule }

// NewTestDeletesSharedDataRule creates the rule
func NewTestDeletesSharedDataRule() *TestDeletesSharedDataRule {
	return &TestDeletesSharedDataRule{rules.NewBaseRule(
		"test-deletes-shared-data",
		"patterns",
		"Detects a test DELETE/UPDATE/TRUNCATE scoped by a production constant — it wipes the rows the application uses",
		core.SeverityHigh,
	)}
}

var destructiveSQL = regexp.MustCompile(`(?is)^\s*(?:DELETE\s+FROM|UPDATE\s+\w|TRUNCATE)`)

// AnalyzeFile reports destructive statements bound to production constants.
func (r *TestDeletesSharedDataRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !goTestFile(ctx) {
		return nil
	}
	imports := productionImports(ctx.GoAST)
	if len(imports) == 0 || makesIsolatedDatabase(ctx.GoAST) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		aliases := constantAliases(fn.Body, imports)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, arg := range rowSelectingArgs(call) {
				if !productionConstant(arg, imports) && !aliases[lastName(arg)] {
					continue
				}
				line := ctx.LineFor(call)
				if !ctx.IsSuppressed(line, r.Name()) {
					violations = append(violations, testReport(r.BaseRule, ctx, line,
						"Test deletes or rewrites rows chosen by the production value "+exprLabel(arg)+" — on a shared database it wipes the application's own data",
						"Scope test data by a value the test created (a unique id, a test-only strategy) and clean up only that"))
				}
				break
			}
			return true
		})
	}
	return violations
}

func exprLabel(expr ast.Expr) string {
	if sel, ok := ast.Unparen(expr).(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok {
			return pkg.Name + "." + sel.Sel.Name
		}
	}
	return lastName(expr)
}

var (
	sqlWhere       = regexp.MustCompile(`(?i)\bWHERE\b`)
	sqlPlaceholder = regexp.MustCompile(`\$(\d+)|\?`)
)

// rowSelectingArgs returns the arguments of a DELETE, UPDATE or TRUNCATE
// call that bind a placeholder after WHERE: the values that pick the rows,
// not the values written into them.
func rowSelectingArgs(call *ast.CallExpr) []ast.Expr {
	for i, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		text, ok := goStringLiteral(lit)
		if !ok || !destructiveSQL.MatchString(text) {
			continue
		}
		where := sqlWhere.FindStringIndex(text)
		if where == nil {
			return nil
		}
		var selecting []ast.Expr
		positional := 0
		for _, m := range sqlPlaceholder.FindAllStringSubmatchIndex(text, -1) {
			n := positional + 1
			if m[2] >= 0 {
				n = 0
				for _, digit := range text[m[2]:m[3]] {
					n = n*10 + int(digit-'0')
				}
			} else {
				positional++
			}
			if m[0] > where[0] && i+n < len(call.Args) {
				selecting = append(selecting, call.Args[i+n])
			}
		}
		return selecting
	}
	return nil
}

// makesIsolatedDatabase reports a file that creates an isolated database for
// its tests (CreateIsolatedTestDB): its rows are not the application's.
func makesIsolatedDatabase(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && strings.Contains(strings.ToLower(callName(call)), "isolated") {
			found = true
		}
		return !found
	})
	return found
}

// productionImports returns the names of the imported packages of the
// project or its dependencies that are not test helpers.
func productionImports(file *ast.File) map[string]bool {
	names := make(map[string]bool)
	for _, spec := range file.Imports {
		path, ok := goStringLiteral(spec.Path)
		if !ok {
			continue
		}
		first, _, _ := strings.Cut(path, "/")
		if !strings.Contains(first, ".") || strings.Contains(strings.ToLower(path), "test") {
			continue
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		names[name] = true
	}
	return names
}

// productionConstant reports pkg.Name of a production import, a value the
// application defines.
func productionConstant(expr ast.Expr, imports map[string]bool) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || !sel.Sel.IsExported() {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && imports[pkg.Name]
}

// constantAliases returns the locals of a body assigned a production constant.
func constantAliases(body *ast.BlockStmt, imports map[string]bool) map[string]bool {
	aliases := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			if ident, ok := assign.Lhs[i].(*ast.Ident); ok && productionConstant(rhs, imports) {
				aliases[ident.Name] = true
			}
		}
		return true
	})
	return aliases
}

// --- test-channel-receive-without-timeout ----------------------------------

// TestChannelReceiveWithoutTimeoutRule detects a test that waits on a channel
// of the code under test with a bare receive:
//
//	manager.Broadcast(event)
//	received := <-subscriber.Channel
//
// If the event never comes the test blocks until the whole run times out,
// and the report names no test. Receive in a select with a time.After case.
type TestChannelReceiveWithoutTimeoutRule struct{ *rules.BaseRule }

// NewTestChannelReceiveWithoutTimeoutRule creates the rule
func NewTestChannelReceiveWithoutTimeoutRule() *TestChannelReceiveWithoutTimeoutRule {
	return &TestChannelReceiveWithoutTimeoutRule{rules.NewBaseRule(
		"test-channel-receive-without-timeout",
		"patterns",
		"Detects a bare receive in a test from a channel of the code under test — a missing event hangs the whole run",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the bare receives of tests.
func (r *TestChannelReceiveWithoutTimeoutRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !goTestFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, tb := range testingBodies(ctx.GoAST) {
		guarded := selectReceives(tb.body)
		counted := countedChannels(tb.body)
		ownNodes(tb.body, func(n ast.Node) bool {
			recv, ok := n.(*ast.UnaryExpr)
			if !ok || recv.Op != token.ARROW || guarded[recv] || !foreignChannel(recv.X) {
				return true
			}
			if pos, ok := counted[exprLabel(recv.X)]; ok && pos < recv.Pos() {
				return true
			}
			line := ctx.LineFor(recv)
			if !ctx.IsSuppressed(line, r.Name()) {
				violations = append(violations, testReport(r.BaseRule, ctx, line,
					"Test receives from "+exprLabel(recv.X)+" with no timeout — if the event never comes, the run hangs until the global timeout and names no test",
					"Receive in a select with a time.After case that fails the test"))
			}
			return true
		})
	}
	return violations
}

// selectReceives returns the receives that are a select case.
func selectReceives(body *ast.BlockStmt) map[*ast.UnaryExpr]bool {
	guarded := make(map[*ast.UnaryExpr]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		clause, ok := n.(*ast.CommClause)
		if !ok || clause.Comm == nil {
			return true
		}
		ast.Inspect(clause.Comm, func(m ast.Node) bool {
			if recv, ok := m.(*ast.UnaryExpr); ok && recv.Op == token.ARROW {
				guarded[recv] = true
			}
			return true
		})
		return true
	})
	return guarded
}

// countedChannels returns the channels a body measures with len, with the
// first place it does: a receive after the test checked what is buffered
// does not block.
func countedChannels(body *ast.BlockStmt) map[string]token.Pos {
	counted := make(map[string]token.Pos)
	ownNodes(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isIdentNamed(call.Fun, "len") || len(call.Args) != 1 {
			return true
		}
		label := exprLabel(call.Args[0])
		if _, seen := counted[label]; !seen {
			counted[label] = call.Pos()
		}
		return true
	})
	return counted
}

// foreignChannel reports a channel the code under test owns: a field
// (subscriber.Channel) or a method result (sub.Events()). A context's Done,
// a timer and a ticker always deliver, and a local channel is the test's own.
func foreignChannel(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name != "C"
	case *ast.CallExpr:
		switch callName(e) {
		case "Done", "After", "Tick", "Err":
			return false
		}
		_, isMethod := e.Fun.(*ast.SelectorExpr)
		return isMethod
	}
	return false
}
