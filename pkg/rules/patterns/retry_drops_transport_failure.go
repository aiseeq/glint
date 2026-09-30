package patterns

import (
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

// AnalyzeGoProject reports retry loops whose only retry decision is the status code.
func (r *RetryDropsTransportFailureRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return analyzeGoFunctions(fileCtx, func(fn *ast.FuncDecl) []*core.Violation {
			return r.checkFunction(fileCtx, info, fn)
		})
	})
}

// checkFunction inspects the loops of one function.
func (r *RetryDropsTransportFailureRule) checkFunction(ctx *core.FileContext, info *types.Info, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		loop, ok := n.(*ast.ForStmt)
		if !ok || loop.Body == nil {
			return true
		}
		exit := r.statusOnlyExit(ctx.GoAST, info, loop)
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
