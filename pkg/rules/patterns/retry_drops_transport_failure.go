package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRetryDropsTransportFailureRule())
}

// RetryDropsTransportFailureRule detects a retry loop that decides whether to
// try again from the response status alone.
//
// A connection that was reset, a TLS handshake that timed out and a DNS answer
// that never came produce no response and no status: the status variable holds
// its zero value, the status branch treats it as "not the code we retry", and
// the loop returns on the one failure a retry would have fixed. What is left is
// a client that survives the provider asking it to slow down and gives up on a
// blip in the network.
//
// Real case (projectA, 2026-09): a monitor polled a vendor every seven minutes
// through such a loop. A TLS handshake timeout ended the whole tick and raised
// an operational alert, while the same request one second later succeeded.
//
// A switch over helpers that only read the status out of the error
// (errors.As to a status error, then StatusCode >= 500) with a default that
// returns is the same decision: a reset connection carries no status error
// and falls to the default.
//
// Not flagged: a loop that also asks the error itself whether to retry
// (errors.Is, a retriable predicate) — the decision is then not the status
// alone; and a loop that does not repeat a request at all (no attempt
// counter, no pause, no continue), such as a pagination walk.
type RetryDropsTransportFailureRule struct {
	*rules.BaseRule
}

// NewRetryDropsTransportFailureRule creates the rule.
func NewRetryDropsTransportFailureRule() *RetryDropsTransportFailureRule {
	return &RetryDropsTransportFailureRule{
		BaseRule: rules.NewBaseRule(
			"retry-drops-transport-failure",
			"patterns",
			"Detects a retry loop that decides by response status only — a transport failure has no status and ends the loop",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: which result of a send is the status code, and
// which is the error, is a question about types.
func (r *RetryDropsTransportFailureRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *RetryDropsTransportFailureRule) RequiresSSA() bool { return false }

type statusPredicatesKey struct{}

// AnalyzeGoProject reports retry loops whose only retry decision is the status code.
func (r *RetryDropsTransportFailureRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	predicates, err := core.SharedLoad(ctx, statusPredicatesKey{}, func() (map[*types.Func]bool, error) {
		return collectStatusPredicates(ctx)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return analyzeGoFunctions(fileCtx, func(fn *ast.FuncDecl) []*core.Violation {
			return r.checkFunction(fileCtx, info, fn, predicates)
		})
	})
}

// collectStatusPredicates indexes the functions that answer about an error
// by the status it carries and nothing else:
//
//	func isServerError(err error) bool {
//	    var statusErr *StatusError
//	    return errors.As(err, &statusErr) && statusErr.StatusCode >= 500
//	}
func collectStatusPredicates(ctx *core.GoProjectContext) (map[*types.Func]bool, error) {
	predicates := make(map[*types.Func]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, fmt.Errorf("package has no typed syntax")
		}
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || !readsOnlyStatus(fn.Body) {
					continue
				}
				if f, ok := pkg.Package.TypesInfo.Defs[fn.Name].(*types.Func); ok {
					predicates[f] = true
				}
			}
		}
	}
	return predicates, nil
}

// readsOnlyStatus reports a body ending in `return errors.As(err, &v) &&
// v.StatusCode <op> N`: every operand after the As compares a status field.
func readsOnlyStatus(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	parts := flattenAnd(ret.Results[0])
	if len(parts) < 2 {
		return false
	}
	as, ok := ast.Unparen(parts[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	if sel, ok := as.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "As" || !isIdentNamed(sel.X, "errors") {
		return false
	}
	for _, part := range parts[1:] {
		cmp, ok := ast.Unparen(part).(*ast.BinaryExpr)
		if !ok {
			return false
		}
		field, ok := cmp.X.(*ast.SelectorExpr)
		if !ok || (field.Sel.Name != "StatusCode" && field.Sel.Name != "Status" && field.Sel.Name != "Code") {
			return false
		}
	}
	return true
}

// checkFunction inspects the loops of one function.
func (r *RetryDropsTransportFailureRule) checkFunction(ctx *core.FileContext, info *types.Info, fn *ast.FuncDecl, predicates map[*types.Func]bool) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		loop, ok := n.(*ast.ForStmt)
		if !ok || loop.Body == nil {
			return true
		}
		var exit ast.Node
		if statusExit := r.statusOnlyExit(ctx.GoAST, info, loop); statusExit != nil {
			exit = statusExit
		} else if predicateExit := statusPredicateExit(ctx.GoAST, info, loop, predicates); predicateExit != nil {
			exit = predicateExit
		}
		if exit == nil {
			return true
		}
		line := lineFromNode(ctx, exit)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line,
			"the retry loop gives up by status code only — a transport failure carries no status, so the connection error the retry exists for ends the loop")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Decide on the error too: retry when the send itself failed, and keep the status branch for the answers the provider did give")
		v.WithContext("pattern", "retry_drops_transport_failure")
		violations = append(violations, v)
		return true
	})
	return violations
}

// statusOnlyExit returns the branch that ends the loop by status code, when the
// loop repeats a request, sends it once per iteration, returns its error under
// a status condition and never asks the error whether it is worth another
// attempt.
func (r *RetryDropsTransportFailureRule) statusOnlyExit(file *ast.File, info *types.Info, loop *ast.ForStmt) *ast.IfStmt {
	body := loop.Body
	status, errName := sendResultNames(info, body)
	if status == "" || errName == "" || !loopRepeatsRequest(file, info, loop) {
		return nil
	}
	if endsWithReturn(body) || errorConsulted(body, errName) || errorPathMayLoop(body, errName) {
		return nil
	}
	return statusGuardedReturn(body, status, errName)
}

// statusPredicateExit returns the switch of a retry loop whose cases ask
// the send error only for its status (isServerError(err), isTooManyRequests(err))
// and whose default returns the error: a failure without a status falls to
// the default and ends the loop.
func statusPredicateExit(file *ast.File, info *types.Info, loop *ast.ForStmt, predicates map[*types.Func]bool) *ast.SwitchStmt {
	if len(predicates) == 0 || !loopRepeatsRequest(file, info, loop) {
		return nil
	}
	var found *ast.SwitchStmt
	ast.Inspect(loop.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || found != nil || sw.Tag != nil {
			return found == nil
		}
		errName, asked := "", 0
		var def *ast.CaseClause
		for _, stmt := range sw.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				return true
			}
			if clause.List == nil {
				def = clause
				continue
			}
			for _, expr := range clause.List {
				call, ok := ast.Unparen(expr).(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				arg, ok := call.Args[0].(*ast.Ident)
				callee, isFunc := typeutil.Callee(info, call).(*types.Func)
				if !ok || !isFunc || !predicates[callee] || errName != "" && arg.Name != errName {
					return true
				}
				errName = arg.Name
				asked++
			}
		}
		if def == nil || asked == 0 || len(def.Body) == 0 {
			return true
		}
		if ret, ok := def.Body[len(def.Body)-1].(*ast.ReturnStmt); ok && returnsIdent(ret, errName) {
			found = sw
		}
		return found == nil
	})
	return found
}

// sendResultNames returns the status and error variables of a send made once
// per iteration: body, statusCode, err := c.doGetRaw(...). The status is the
// one integer result, the error the one of type error; a send with no integer
// result, or with several, has no status to decide by.
func sendResultNames(info *types.Info, body *ast.BlockStmt) (status, errName string) {
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) < 2 {
			continue
		}
		if _, ok := assign.Rhs[0].(*ast.CallExpr); !ok {
			continue
		}
		var statuses []string
		var foundErr string
		for _, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || ident.Name == "_" {
				continue
			}
			variable := info.ObjectOf(ident)
			if variable == nil {
				continue
			}
			switch {
			case isIntType(variable.Type()):
				statuses = append(statuses, ident.Name)
			case isErrorType(variable.Type()):
				foundErr = ident.Name
			}
		}
		if len(statuses) == 1 && foundErr != "" {
			return statuses[0], foundErr
		}
	}
	return "", ""
}

// loopRepeatsRequest reports whether the loop is a retry at all: it counts
// attempts (for i := 0; i < n; i++), waits between iterations (time.Sleep,
// time.After, a sleep or backoff helper) or jumps back with continue. A loop
// with none of these — a pagination walk — asks for something new each time,
// and an error ending it is the right answer.
func loopRepeatsRequest(file *ast.File, info *types.Info, loop *ast.ForStmt) bool {
	if loop.Init != nil && loop.Cond != nil {
		if _, counted := loop.Post.(*ast.IncDecStmt); counted {
			return true
		}
	}
	if containsContinue(loop.Body) {
		return true
	}
	waits := false
	ast.Inspect(loop.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || waits {
			return !waits
		}
		if isPackageFuncCall(file, info, call, "time", "Sleep", "After", "NewTimer", "Tick") {
			waits = true
			return false
		}
		if fn, ok := typeutil.Callee(info, call).(*types.Func); ok && isWaitHelperName(fn.Name()) {
			waits = true
			return false
		}
		return true
	})
	return waits
}

// isWaitHelperName reports whether a function's declared name says it pauses
// between attempts: sleep, sleepWithContext, backoff.Wait.
func isWaitHelperName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "sleep") || strings.Contains(lower, "backoff") || lower == "wait"
}

// statusGuardedReturn returns the if that ends the loop on a status condition
// while handing the caller the send error.
func statusGuardedReturn(body *ast.BlockStmt, status, errName string) *ast.IfStmt {
	var found *ast.IfStmt
	ast.Inspect(body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		branch, ok := n.(*ast.IfStmt)
		if !ok || !mentionsIdent(branch.Cond, status) {
			return true
		}
		ret := trailingReturn(branch.Body)
		if ret == nil || !returnsIdent(ret, errName) {
			return true
		}
		found = branch
		return false
	})
	return found
}

// errorPathMayLoop reports whether a non-nil error already reaches the next
// attempt: a branch on err != nil that continues, or one that falls through to
// the end of the loop body instead of returning.
func errorPathMayLoop(body *ast.BlockStmt, errName string) bool {
	mayLoop := false
	ast.Inspect(body, func(n ast.Node) bool {
		branch, ok := n.(*ast.IfStmt)
		if !ok || !comparesToNil(branch.Cond, errName, token.NEQ) {
			return true
		}
		if containsContinue(branch.Body) || trailingReturn(branch.Body) == nil {
			mayLoop = true
			return false
		}
		return true
	})
	return mayLoop
}

// comparesToNil reports whether the condition compares the named value to nil
// with the given operator.
func comparesToNil(cond ast.Expr, name string, op token.Token) bool {
	binary, ok := cond.(*ast.BinaryExpr)
	if !ok || binary.Op != op {
		return false
	}
	left, leftOK := binary.X.(*ast.Ident)
	right, rightOK := binary.Y.(*ast.Ident)
	return leftOK && rightOK && left.Name == name && right.Name == "nil"
}

// containsContinue reports whether the block jumps to the next attempt.
func containsContinue(block *ast.BlockStmt) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		if branch, ok := n.(*ast.BranchStmt); ok && branch.Tok == token.CONTINUE {
			found = true
			return false
		}
		return true
	})
	return found
}

// errorConsulted reports whether the loop asks the error itself anything
// beyond "is it nil": a condition built on errors.Is, on a retriable predicate
// or on a type switch is a decision made from the error, not from the status.
func errorConsulted(body *ast.BlockStmt, errName string) bool {
	consulted := false
	ast.Inspect(body, func(n ast.Node) bool {
		for _, cond := range decisionExpressions(n) {
			if callTakesIdent(cond, errName) {
				consulted = true
				return false
			}
		}
		return true
	})
	return consulted || typeSwitchesOn(body, errName)
}

// decisionExpressions returns the expressions a statement decides by.
func decisionExpressions(n ast.Node) []ast.Expr {
	switch current := n.(type) {
	case *ast.IfStmt:
		return []ast.Expr{current.Cond}
	case *ast.SwitchStmt:
		if current.Tag != nil {
			return []ast.Expr{current.Tag}
		}
	case *ast.CaseClause:
		return current.List
	}
	return nil
}

// callTakesIdent reports whether the expression passes the named value to a
// call: errors.Is(err, io.EOF), retriable(err).
func callTakesIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if mentionsIdent(arg, name) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// typeSwitchesOn reports whether the loop dispatches on the error's type.
func typeSwitchesOn(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switchStmt, ok := n.(*ast.TypeSwitchStmt)
		if !ok || switchStmt.Assign == nil {
			return true
		}
		if mentionsIdent(exprOfStmt(switchStmt.Assign), name) {
			found = true
			return false
		}
		return true
	})
	return found
}

// exprOfStmt returns the expression a simple statement is built around.
func exprOfStmt(stmt ast.Stmt) ast.Expr {
	switch current := stmt.(type) {
	case *ast.ExprStmt:
		return current.X
	case *ast.AssignStmt:
		if len(current.Rhs) == 1 {
			return current.Rhs[0]
		}
	}
	return &ast.BadExpr{}
}

// endsWithReturn reports whether the loop body cannot reach a next iteration.
func endsWithReturn(body *ast.BlockStmt) bool {
	return trailingReturn(body) != nil
}

// trailingReturn returns the return statement a block ends with, if any.
func trailingReturn(block *ast.BlockStmt) *ast.ReturnStmt {
	if block == nil || len(block.List) == 0 {
		return nil
	}
	ret, _ := block.List[len(block.List)-1].(*ast.ReturnStmt)
	return ret
}

// returnsIdent reports whether the return hands the named value to the caller,
// either directly or inside a wrapping call.
func returnsIdent(ret *ast.ReturnStmt, name string) bool {
	for _, result := range ret.Results {
		if mentionsIdent(result, name) {
			return true
		}
	}
	return false
}

// mentionsIdent reports whether the expression reads the named variable.
func mentionsIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}
