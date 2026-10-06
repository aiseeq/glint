package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUpstreamFailureAnsweredAsBadRequestRule())
}

// UpstreamFailureAnsweredAsBadRequestRule detects an HTTP handler that answers
// 400 for every error of a call that reads the request and then fetches:
//
//	report, err := r.assembleSummary(req) // parses the period, then asks a source with ctx
//	if err != nil {
//		sendValidationError(w, req, "report failed", err.Error())
//	}
//
// The call fails for two reasons: the client sent a bad period, or the source
// behind it did not answer. Both go out as the client's mistake, so an outage
// reads as "fix your request", the client does not retry, and monitoring of
// 5xx answers never sees it. Tell the client's errors apart (errors.Is on a
// validation sentinel) and answer the rest as 502 or 500. The callee must be
// declared in the file and pass a context to a call of its own, or be handed
// the request's context directly (r.verifier.Verify(req.Context(), token)).
//
// A 401 for every error of such a call is the same trap: a token check that
// fetches the signing keys answers an outage with "log in again".
type UpstreamFailureAnsweredAsBadRequestRule struct {
	*rules.BaseRule
}

// NewUpstreamFailureAnsweredAsBadRequestRule creates the rule
func NewUpstreamFailureAnsweredAsBadRequestRule() *UpstreamFailureAnsweredAsBadRequestRule {
	return &UpstreamFailureAnsweredAsBadRequestRule{BaseRule: rules.NewBaseRule(
		"upstream-failure-answered-as-bad-request",
		"patterns",
		"Detects a handler answering 400 or 401 for every error of a call that also fetches with a context — an unavailable source reads as the client's mistake",
		core.SeverityMedium,
	)}
}

var (
	// badRequestResponder names a helper that answers 400.
	badRequestResponder = regexp.MustCompile(`(?i)validation|badrequest|invalidrequest`)
	// contextValueRead names a call reading a value the context carries.
	contextValueRead = regexp.MustCompile(`(?i)from(?:ctx|context)$`)
	// answerVerb starts the name of a helper that writes an answer.
	answerVerb = regexp.MustCompile(`(?i)^(?:send|respond|write|reply)`)
)

// AnalyzeFile reports the 400 answers of a file's handlers to errors of
// calls that fetch.
func (r *UpstreamFailureAnsweredAsBadRequestRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range ctx.GoAST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			funcs[fn.Name.Name] = fn
		}
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !isHTTPHandlerDecl(fn) {
			continue
		}
		forEachStmtPair(fn.Body, func(first, second ast.Stmt) {
			call := errAssignedCall(first)
			ifStmt, ok := second.(*ast.IfStmt)
			if call == nil || !ok || ifStmt.Init != nil || !isErrNotNil(ifStmt.Cond) {
				return
			}
			callee := callName(call)
			if !fetches(call, funcs[callee]) {
				return
			}
			answer, status := clientErrorAnswer(ifStmt.Body)
			if answer == nil {
				return
			}
			line := ctx.LineFor(answer)
			if ctx.IsSuppressed(line, r.Name()) {
				return
			}
			v := r.CreateViolation(ctx.RelPath, line, "Every error of "+callee+" is answered as "+status+", though it also fails when what it fetches does not answer")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Mark the request's own errors (errors.Is on a validation sentinel) and answer the rest as 502 or 500")
			violations = append(violations, v)
		})
	}
	return violations
}

// isHTTPHandlerDecl reports a function taking an http.ResponseWriter.
func isHTTPHandlerDecl(fn *ast.FuncDecl) bool {
	for _, field := range fn.Type.Params.List {
		if sel, ok := field.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "ResponseWriter" && isIdentNamed(sel.X, "http") {
			return true
		}
	}
	return false
}

// forEachStmtPair calls visit for every two statements in a row of every
// block under body.
func forEachStmtPair(body *ast.BlockStmt, visit func(first, second ast.Stmt)) {
	ast.Inspect(body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i := 0; i+1 < len(block.List); i++ {
			visit(block.List[i], block.List[i+1])
		}
		return true
	})
}

// errAssignedCall returns the call of an assignment whose last target is
// err: x, err := r.build(req).
func errAssignedCall(stmt ast.Stmt) *ast.CallExpr {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 || !isIdentNamed(assign.Lhs[len(assign.Lhs)-1], "err") {
		return nil
	}
	call, _ := assign.Rhs[0].(*ast.CallExpr)
	return call
}

// fetches reports a call that can fail on what it fetches: a function of the
// file (target) that hands a context on, or any call handed the request's
// context (req.Context()) or ctx itself. A read of a context value
// (UserIDFromContext) fetches nothing.
func fetches(call *ast.CallExpr, target *ast.FuncDecl) bool {
	if contextValueRead.MatchString(callName(call)) {
		return false
	}
	if target != nil {
		return !isHTTPHandlerDecl(target) && handsContextOn(target.Body)
	}
	for _, arg := range call.Args {
		if isIdentNamed(arg, "ctx") {
			return true
		}
		if inner, ok := ast.Unparen(arg).(*ast.CallExpr); ok && len(inner.Args) == 0 {
			if sel, ok := inner.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Context" {
				return true
			}
		}
	}
	return false
}

// handsContextOn reports a body that hands a context to a call: ctx, or
// X.Context().
func handsContextOn(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if isSelectorCall(call, "context", "WithTimeout") || isSelectorCall(call, "context", "WithCancel") || isSelectorCall(call, "context", "WithDeadline") {
			return true
		}
		for _, arg := range call.Args {
			if isIdentNamed(arg, "ctx") {
				found = true
			}
		}
		return !found
	})
	return found
}

// clientErrorAnswer returns the call of an error branch that answers 400 or
// 401, and how it answers, when the branch does not tell errors apart.
func clientErrorAnswer(body *ast.BlockStmt) (*ast.CallExpr, string) {
	var answer *ast.CallExpr
	status := ""
	split := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isSelectorCall(call, "errors", "Is") || isSelectorCall(call, "errors", "As") {
			split = true
		}
		if answer == nil {
			switch {
			case answersBadRequest(call):
				answer, status = call, "a bad request"
			case answersUnauthorized(call):
				answer, status = call, "unauthorized"
			}
		}
		return true
	})
	if split {
		return nil, ""
	}
	return answer, status
}

// answersUnauthorized reports a call of a 401 helper or one given
// http.StatusUnauthorized.
func answersUnauthorized(call *ast.CallExpr) bool {
	if name := callName(call); answerVerb.MatchString(name) && strings.Contains(strings.ToLower(name), "unauthorized") {
		return true
	}
	for _, arg := range call.Args {
		if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == "StatusUnauthorized" && isIdentNamed(sel.X, "http") {
			return true
		}
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "401" {
			return true
		}
	}
	return false
}

// answersBadRequest reports a call of a 400 helper or one given
// http.StatusBadRequest.
func answersBadRequest(call *ast.CallExpr) bool {
	name := ""
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	}
	if badRequestResponder.MatchString(name) && answerVerb.MatchString(name) {
		return true
	}
	for _, arg := range call.Args {
		if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == "StatusBadRequest" && isIdentNamed(sel.X, "http") {
			return true
		}
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "400" {
			return true
		}
	}
	return false
}
