package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewBackgroundGoroutineWithoutRecoverRule())
}

// NewBackgroundGoroutineWithoutRecoverRule creates
// background-goroutine-without-recover: a panic in a goroutine ends the
// process, and nothing recovers it outside the request the HTTP middleware
// guards. Two goroutines are left to themselves: a polling loop that lives
// as long as the server, and a goroutine a handler leaves running after it
// answered:
//
//	go func() {
//		for range s.ticker.C {
//			s.refreshBalances()      // one malformed provider reply kills the server
//		}
//	}()
//
// A goroutine is guarded by a deferred recover in its body, directly or in a
// helper the defer calls, or by a call of a helper that recovers around the
// work it runs.
func NewBackgroundGoroutineWithoutRecoverRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"background-goroutine-without-recover",
			"patterns",
			"Detects a long-lived polling goroutine, or one an HTTP handler leaves running, with no recover — a panic in it ends the whole server",
			core.SeverityMedium,
		),
		suggestion: "Defer a recover that logs the panic at the top of the goroutine (and per iteration of a polling loop, so the schedule survives)",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if obj, ok := scope.info.Defs[fn.Name].(*types.Func); !ok || obj.Pkg() == nil || obj.Pkg().Name() == "main" {
			return nil
		}
		handler := handlerRequestParam(typedFunc{info: scope.info, decl: fn}) != nil
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			stmt, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			body, info := goroutineBodyOf(scope, stmt.Call)
			if body == nil || guardsPanics(scope, info, body) {
				return true
			}
			switch {
			case hasPollingLoop(body):
				findings = append(findings, funcFinding{node: stmt, message: "A polling goroutine runs with no recover — a panic in one iteration ends the whole server"})
			case handler:
				findings = append(findings, funcFinding{node: stmt, message: "A goroutine the handler leaves running has no recover — outside the request the middleware guards, a panic in it ends the whole server"})
			}
			return true
		})
		return findings
	}
	return r
}

// goroutineBodyOf returns the body a go statement runs and the types it is
// read with: the function literal, or the declaration of a static callee.
func goroutineBodyOf(scope funcScope, call *ast.CallExpr) (*ast.BlockStmt, *types.Info) {
	if lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		return lit.Body, scope.info
	}
	decl, ok := scope.callee(call)
	if !ok {
		return nil, nil
	}
	return decl.decl.Body, decl.info
}

// guardsPanics reports a body that recovers: a deferred recover, directly or
// in a helper the defer calls, or a call of a helper that defers one around
// the work it runs (guard.Run("tick", s.refresh)).
func guardsPanics(scope funcScope, info *types.Info, body *ast.BlockStmt) bool {
	guarded := false
	ast.Inspect(body, func(n ast.Node) bool {
		if guarded {
			return false
		}
		switch node := n.(type) {
		case *ast.DeferStmt:
			guarded = deferredRecover(scope, info, node.Call)
		case *ast.CallExpr:
			if decl, ok := (funcScope{info: info, decls: scope.decls}).callee(node); ok {
				guarded = defersRecover(scope, decl)
			}
		}
		return !guarded
	})
	return guarded
}

// deferredRecover reports a deferred call that recovers: a literal calling
// recover, or a function whose body calls it.
func deferredRecover(scope funcScope, info *types.Info, call *ast.CallExpr) bool {
	if lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		return callsRecover(info, lit.Body)
	}
	decl, ok := (funcScope{info: info, decls: scope.decls}).callee(call)
	return ok && callsRecover(decl.info, decl.decl.Body)
}

// defersRecover reports a function whose own body defers a recover.
func defersRecover(scope funcScope, decl typedFuncDecl) bool {
	for _, stmt := range decl.decl.Body.List {
		if d, ok := stmt.(*ast.DeferStmt); ok && deferredRecover(scope, decl.info, d.Call) {
			return true
		}
	}
	return false
}

// callsRecover reports a call of the builtin recover in a body.
func callsRecover(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
				if _, builtin := info.Uses[ident].(*types.Builtin); builtin && ident.Name == "recover" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// hasPollingLoop reports a loop that lives as long as the goroutine: a bare
// for, or a range over a ticker channel.
func hasPollingLoop(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch loop := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ForStmt:
			found = found || loop.Cond == nil
		case *ast.RangeStmt:
			found = found || tickerChannel(loop.X)
		}
		return !found
	})
	return found
}
