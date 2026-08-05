package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSleepWithoutContextRule())
}

// SleepWithoutContextRule detects time.Sleep inside a function that has a
// context.Context available (as a parameter or captured from the enclosing
// function). Cancelling the context does not interrupt the pause: a sync loop
// sleeping 250ms per item keeps running long after the caller gave up, and a
// graceful shutdown waits out every pending sleep.
//
// Real case (backoffice, 2026-08-05): wallet sync slept 200ms between provider
// APIs and 250ms per Solana transaction with a live ctx in scope; stopping the
// sync had to wait for the whole backlog of pauses.
type SleepWithoutContextRule struct {
	*rules.BaseRule
}

// NewSleepWithoutContextRule creates the rule.
func NewSleepWithoutContextRule() *SleepWithoutContextRule {
	return &SleepWithoutContextRule{
		BaseRule: rules.NewBaseRule(
			"sleep-without-context",
			"patterns",
			"Detects time.Sleep in functions that have a context.Context — cancellation does not interrupt the pause",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile flags time.Sleep calls that ignore an available context.
func (r *SleepWithoutContextRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		violations = append(violations, r.checkBody(ctx, fn.Body, funcHasLiveContextParam(fn.Type))...)
	}
	return violations
}

// checkBody walks one function body. ctxAvailable carries whether a live
// context is reachable at this nesting level; a closure inherits the enclosing
// function's context and may also introduce its own parameter.
func (r *SleepWithoutContextRule) checkBody(ctx *core.FileContext, body *ast.BlockStmt, ctxAvailable bool) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			nested := ctxAvailable || funcHasLiveContextParam(node.Type)
			violations = append(violations, r.checkBody(ctx, node.Body, nested)...)
			return false
		case *ast.CallExpr:
			if !ctxAvailable || !isTimeSleepCall(node) {
				return true
			}
			line := lineFromNode(ctx, node)
			if ctx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"time.Sleep in a function with context.Context — cancellation does not interrupt the pause")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Wait in a ctx-aware way: select { case <-ctx.Done(): return ctx.Err(); case <-time.After(d): } or a shared sleepWithContext helper")
			violations = append(violations, v)
		}
		return true
	})
	return violations
}

// funcHasLiveContextParam reports whether the signature has a context.Context
// parameter that is actually bound to a name. `_ context.Context` deliberately
// discards the caller's context, so a sleep there has nothing to select on.
func funcHasLiveContextParam(funcType *ast.FuncType) bool {
	if funcType == nil || funcType.Params == nil {
		return false
	}
	for _, param := range funcType.Params.List {
		if !isContextType(param.Type) {
			continue
		}
		if len(param.Names) > 0 && allUnderscore(param.Names) {
			continue
		}
		return true
	}
	return false
}

// isTimeSleepCall reports whether the call is time.Sleep(...).
func isTimeSleepCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "time" && sel.Sel.Name == "Sleep"
}
