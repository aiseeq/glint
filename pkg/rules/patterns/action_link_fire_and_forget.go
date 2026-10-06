package patterns

import (
	"go/ast"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewActionLinkSentFireAndForgetRule())
}

// actionLinkDepth bounds how deep the goroutine's calls are followed to the
// send whose failure is only logged.
const actionLinkDepth = 3

// NewActionLinkSentFireAndForgetRule creates action-link-sent-fire-and-forget:
// a message carrying a one-time action token (a cancel or confirm link) sent
// from a goroutine nobody waits for, with the send's failure only logged, is
// lost on the first mail outage - the user never gets the link, and nothing
// sends it again:
//
//	go func() {
//		r.sendCancelEmail(ctx, request, cancelToken) // inside: if err := mail.Send(...); err != nil { log }
//	}()
//
// The token was issued and stored for the user to act on; its delivery needs
// a persisted retry (an outbox) or a failure the caller sees.
func NewActionLinkSentFireAndForgetRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"action-link-sent-fire-and-forget",
			"patterns",
			"Detects a message carrying an action token (a cancel or confirm link) sent from a goroutine with the send's failure only logged — on a mail outage the user never gets the link and nothing sends it again",
			core.SeverityMedium,
		),
		suggestion: "Queue the message in a persisted outbox with retries (and an operator alert when they run out), or send it in the request and fail the request when it cannot go",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			body, start := detachedGoroutine(n)
			if body == nil {
				return true
			}
			ast.Inspect(body, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok || !handsToken(call) {
					return true
				}
				if send := loggedOnlySend(scope, call, actionLinkDepth); send != "" {
					findings = append(findings, funcFinding{node: start, message: "A message carrying an action token is sent from a goroutine and a failure of " + send + " is only logged — on a mail outage the user never gets the link and nothing sends it again"})
					return false
				}
				return true
			})
			return true
		})
		return findings
	}
	return r
}

// detachedGoroutine returns the code a node starts in a goroutine nobody waits
// for - the function literal of go func(){...}() or of a starter called with
// one (safego.Go("name", nil, func(){...})), or the call of go f(x) - and the
// node to report.
func detachedGoroutine(n ast.Node) (ast.Node, ast.Node) {
	switch node := n.(type) {
	case *ast.GoStmt:
		if lit, ok := node.Call.Fun.(*ast.FuncLit); ok {
			return lit.Body, node
		}
		return node.Call, node
	case *ast.CallExpr:
		if callName(node) != "Go" || len(node.Args) == 0 {
			return nil, nil
		}
		if lit, ok := node.Args[len(node.Args)-1].(*ast.FuncLit); ok {
			return lit.Body, node
		}
	}
	return nil, nil
}

// handsToken reports a call handed a value named for a token (cancelToken,
// created.ConfirmToken).
func handsToken(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		name := ""
		switch a := ast.Unparen(arg).(type) {
		case *ast.Ident:
			name = a.Name
		case *ast.SelectorExpr:
			name = a.Sel.Name
		}
		if slices.Contains(helpers.IdentifierWords(name), "token") {
			return true
		}
	}
	return false
}

// loggedOnlySend returns the name of a send (Send...) that call reaches,
// within depth calls, whose error is only logged: `if err := m.Send(...);
// err != nil { log }` with nothing returned; "" for none.
func loggedOnlySend(scope funcScope, call *ast.CallExpr, depth int) string {
	decl, ok := scope.callee(call)
	if !ok || depth == 0 {
		return ""
	}
	found := ""
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			send := sendIn(node.Init)
			if send != "" && isErrNotNil(node.Cond) && onlyLogs(node.Body) {
				found = send
			}
		case *ast.CallExpr:
			inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
			if name := loggedOnlySend(inner, node, depth-1); name != "" {
				found = name
			}
		}
		return found == ""
	})
	return found
}

// sendIn returns the name of the Send... call an if's init assigns the
// error of; "" for none.
func sendIn(init ast.Stmt) string {
	assign, ok := init.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return ""
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return ""
	}
	name := callName(call)
	if !helpers.HasLeadingWord(name, "Send") || strings.Contains(strings.ToLower(name), "alert") {
		return ""
	}
	return name
}
