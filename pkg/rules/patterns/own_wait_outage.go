package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewOwnWaitReportedAsOutageRule())
}

// OwnWaitReportedAsOutageRule detects a failure of our own time budget marked
// as an outage of the provider:
//
//	budget, cancel := context.WithTimeout(ctx, 8*time.Second)
//	records, err := s.client.Search(budget, wallet) // waits on the client's own rate limiter
//	if err != nil {
//	    mark(groups, wallet, "provider_unavailable")
//
// The callee queues on a limiter of ours (a select on ctx.Done() and a gate
// or a timer) before it asks the provider; when the queue does not fit the
// budget the call ends with our deadline, and the mark blames a service that
// was never asked - and comes back on every request that queues the same way.
// Reported: the error branch of such a call, made with a context the function
// derived by WithTimeout or WithDeadline, passes an outage marker (a string
// constant with "unavailable", "outage", "down"), and the function never
// tells the deadline apart (context.DeadlineExceeded, context.Canceled,
// ctx.Err()).
type OwnWaitReportedAsOutageRule struct {
	*rules.BaseRule
}

// NewOwnWaitReportedAsOutageRule creates the rule
func NewOwnWaitReportedAsOutageRule() *OwnWaitReportedAsOutageRule {
	return &OwnWaitReportedAsOutageRule{BaseRule: rules.NewBaseRule(
		"own-wait-reported-as-outage",
		"patterns",
		"Detects a call that waits on our own limiter within our own deadline whose failure is marked as the provider's outage — our exhausted budget blames a service that was never asked",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: whether the callee waits is in another file.
func (r *OwnWaitReportedAsOutageRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *OwnWaitReportedAsOutageRule) RequiresSSA() bool { return false }

type localWaitersKey struct{}

// outageMarker is a marker naming the provider's failure.
var outageMarker = regexp.MustCompile(`(?i)unavailable|outage|(^|[^a-z])down($|[^a-z])`)

// AnalyzeGoProject reports the outage marks set on our own deadline.
func (r *OwnWaitReportedAsOutageRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	waiters, err := core.SharedLoad(ctx, localWaitersKey{}, func() (map[*types.Func]int, error) {
		return collectLocalWaiters(ctx)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return analyzeGoFunctions(fileCtx, func(fn *ast.FuncDecl) []*core.Violation {
			return r.checkFunction(fileCtx, info, fn, waiters)
		})
	})
}

func (r *OwnWaitReportedAsOutageRule) checkFunction(ctx *core.FileContext, info *types.Info, fn *ast.FuncDecl, waiters map[*types.Func]int) []*core.Violation {
	budgets := budgetContexts(info, fn.Body)
	if len(budgets) == 0 || looksAtContextError(info, fn.Body) {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		index, waits := waiters[staticFunc(info, call)]
		if !waits || index >= len(call.Args) {
			return true
		}
		arg, ok := ast.Unparen(call.Args[index]).(*ast.Ident)
		if !ok || !budgets[info.Uses[arg]] {
			return true
		}
		errObj := assignedError(info, assign)
		if errObj == nil {
			return true
		}
		branch := errorBranchAfter(info, fn.Body, assign, errObj)
		if branch == nil || !passesOutageMarker(info, branch) {
			return true
		}
		line := ctx.LineFor(branch)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line, "The call waits on our own limiter within our own deadline, and its failure is marked as the provider's outage — our exhausted budget blames a service that was never asked")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Tell context.DeadlineExceeded (our budget, our queue) from the provider's failure and mark it as stale or pending")
		violations = append(violations, v)
		return true
	})
	return violations
}

// collectLocalWaiters indexes the project functions that wait on a limiter of
// their own: a select with a ctx.Done() case beside another case, the
// ctx.Done() case returning the context's error. The value is the index of
// the context parameter.
func collectLocalWaiters(ctx *core.GoProjectContext) (map[*types.Func]int, error) {
	waiters := make(map[*types.Func]int)
	err := forEachTypedFuncDecl(ctx, func(info *types.Info, fn *ast.FuncDecl, obj *types.Func) {
		if obj == nil {
			return
		}
		for index := range fn.Type.Params.NumFields() {
			param := info.Defs[paramIdentAt(fn.Type, index)]
			if param != nil && types.TypeString(param.Type(), nil) == "context.Context" {
				if waitsLocally(info, fn.Body, param) {
					waiters[obj] = index
				}
				return
			}
		}
	})
	return waiters, err
}

// waitsLocally reports a body with a select that waits on param.Done()
// beside another channel and answers the Done case with param.Err().
func waitsLocally(info *types.Info, body *ast.BlockStmt, param types.Object) bool {
	if param == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectStmt)
		if !ok || found || len(sel.Body.List) < 2 {
			return !found
		}
		for _, stmt := range sel.Body.List {
			clause, ok := stmt.(*ast.CommClause)
			if ok && receivesDone(info, clause.Comm, param) && returnsContextError(info, clause.Body, param) {
				found = true
			}
		}
		return !found
	})
	return found
}

// receivesDone reports `<-ctx.Done()` of the parameter.
func receivesDone(info *types.Info, comm ast.Stmt, param types.Object) bool {
	expr, ok := comm.(*ast.ExprStmt)
	if !ok {
		return false
	}
	recv, ok := ast.Unparen(expr.X).(*ast.UnaryExpr)
	if !ok || recv.Op != token.ARROW {
		return false
	}
	call, ok := ast.Unparen(recv.X).(*ast.CallExpr)
	if !ok {
		return false
	}
	done, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || done.Sel.Name != "Done" {
		return false
	}
	ident, ok := ast.Unparen(done.X).(*ast.Ident)
	return ok && info.Uses[ident] == param
}

// returnsContextError reports statements returning param.Err(), as is or wrapped.
func returnsContextError(info *types.Info, stmts []ast.Stmt, param types.Object) bool {
	found := false
	for _, stmt := range stmts {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok {
			continue
		}
		ast.Inspect(ret, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Err" {
				if ident, ok := ast.Unparen(sel.X).(*ast.Ident); ok && info.Uses[ident] == param {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// budgetContexts returns the contexts a body derives with a deadline of its
// own: budget, cancel := context.WithTimeout(ctx, d).
func budgetContexts(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	budgets := map[types.Object]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !isIdentNamed(sel.X, "context") || (sel.Sel.Name != "WithTimeout" && sel.Sel.Name != "WithDeadline") {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
			if obj := info.ObjectOf(ident); obj != nil {
				budgets[obj] = true
			}
		}
		return true
	})
	return budgets
}

// assignedError returns the error variable a call's results are assigned to.
func assignedError(info *types.Info, assign *ast.AssignStmt) types.Object {
	for i := len(assign.Lhs) - 1; i >= 0; i-- {
		ident, ok := assign.Lhs[i].(*ast.Ident)
		if !ok {
			continue
		}
		if obj := info.ObjectOf(ident); obj != nil && implementsError(obj.Type()) {
			return obj
		}
	}
	return nil
}

// errorBranchAfter returns the first `if err != nil` (or `case err != nil:`)
// after the assignment, the node carrying the branch's statements.
func errorBranchAfter(info *types.Info, body *ast.BlockStmt, assign *ast.AssignStmt, errObj types.Object) ast.Node {
	isErrCheck := func(cond ast.Expr) bool {
		bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
		if !ok || bin.Op != token.NEQ || !isNilIdent(ast.Unparen(bin.Y)) {
			return false
		}
		ident, ok := ast.Unparen(bin.X).(*ast.Ident)
		return ok && info.Uses[ident] == errObj
	}
	var branch ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if branch != nil || n == nil {
			return false
		}
		if n.Pos() < assign.End() && n.End() < assign.End() {
			return false
		}
		switch node := n.(type) {
		case *ast.IfStmt:
			if node.Pos() > assign.Pos() && isErrCheck(node.Cond) {
				branch = node
			}
		case *ast.CaseClause:
			if node.Pos() > assign.Pos() {
				for _, cond := range node.List {
					if isErrCheck(cond) {
						branch = node
					}
				}
			}
		}
		return branch == nil
	})
	return branch
}

// passesOutageMarker reports a branch handing a call a string constant that
// names an outage.
func passesOutageMarker(info *types.Info, branch ast.Node) bool {
	var stmts []ast.Stmt
	switch b := branch.(type) {
	case *ast.IfStmt:
		stmts = b.Body.List
	case *ast.CaseClause:
		stmts = b.Body
	}
	found := false
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			// A log line saying "unavailable" marks nothing the user sees.
			if helpers.IsLoggerCall(call) {
				return false
			}
			for _, arg := range call.Args {
				if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.String && outageMarker.MatchString(constant.StringVal(tv.Value)) {
					found = true
				}
			}
			return !found
		})
	}
	return found
}
