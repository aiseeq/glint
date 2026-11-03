package concurrencyrules

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
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
//			s.refreshItems()      // one malformed provider reply kills the server
//		}
//	}()
//
// A goroutine is guarded by a deferred recover in its body, directly or in a
// helper the defer calls, or by a call of a helper that recovers around the
// work it runs.
func NewBackgroundGoroutineWithoutRecoverRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"background-goroutine-without-recover",
			"patterns",
			"Detects a long-lived polling goroutine, or one an HTTP handler leaves running, with no recover — a panic in it ends the whole server",
			core.SeverityMedium,
		),
		Suggestion: "Defer a recover that logs the panic at the top of the goroutine (and per iteration of a polling loop, so the schedule survives)",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		if obj, ok := scope.Info.Defs[fn.Name].(*types.Func); !ok || obj.Pkg() == nil || obj.Pkg().Name() == "main" {
			return nil
		}
		handler := patternkit.HandlerRequestParam(patternkit.TypedFunc{Info: scope.Info, Decl: fn}) != nil
		var findings []patternkit.FuncFinding
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
				findings = append(findings, patternkit.FuncFinding{Node: stmt, Message: "A polling goroutine runs with no recover — a panic in one iteration ends the whole server"})
			case handler:
				findings = append(findings, patternkit.FuncFinding{Node: stmt, Message: "A goroutine the handler leaves running has no recover — outside the request the middleware guards, a panic in it ends the whole server"})
			}
			return true
		})
		return findings
	}
	return r
}

// goroutineBodyOf returns the body a go statement runs and the types it is
// read with: the function literal, or the declaration of a static callee.
func goroutineBodyOf(scope patternkit.FuncScope, call *ast.CallExpr) (*ast.BlockStmt, *types.Info) {
	if lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		return lit.Body, scope.Info
	}
	decl, ok := scope.Callee(call)
	if !ok {
		return nil, nil
	}
	return decl.Decl.Body, decl.Info
}

// guardsPanics reports a body that recovers: a deferred recover, directly or
// in a helper the defer calls, or a call of a helper that defers one around
// the work it runs (guard.Run("tick", s.refresh)). A helper of another
// module counts too: its body is read from the module's source. A function
// of the standard library does not, called or deferred: its recover sits in
// a literal around a call of its own (parser.ParseFile, slog.Value.Resolve,
// sync.OnceFunc), not around the work the goroutine goes on to do.
func guardsPanics(scope patternkit.FuncScope, info *types.Info, body *ast.BlockStmt) bool {
	guarded := false
	ast.Inspect(body, func(n ast.Node) bool {
		if guarded {
			return false
		}
		switch node := n.(type) {
		case *ast.DeferStmt:
			guarded = deferredRecover(scope, info, node.Call)
		case *ast.CallExpr:
			if decl, ok := scope.WithInfo(info).Callee(node); ok {
				guarded = defersRecover(scope, decl)
			} else if fn := patternkit.StaticFunc(info, node); fn != nil {
				guarded = dependencyDefersRecover(scope.Sources, fn)
			}
		}
		return !guarded
	})
	return guarded
}

// deferredRecover reports a deferred call that recovers: a literal calling
// recover, or a function whose body calls it.
func deferredRecover(scope patternkit.FuncScope, info *types.Info, call *ast.CallExpr) bool {
	if lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		return callsRecover(info, lit.Body)
	}
	if decl, ok := scope.WithInfo(info).Callee(call); ok {
		return callsRecover(decl.Info, decl.Decl.Body)
	}
	return dependencyCallsRecover(scope.Sources, patternkit.StaticFunc(info, call))
}

// dependencyCallsRecover reports a library function whose body calls
// recover.
func dependencyCallsRecover(sources *patternkit.DependencySources, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || sources.Standard(fn.Pkg()) || fn.Pkg().Scope().Lookup("recover") != nil {
		// A package of its own recover: the name is not the builtin.
		return false
	}
	decl := sources.FuncDecl(fn)
	return decl != nil && decl.Body != nil && callsRecover(nil, decl.Body)
}

// dependencyDefersRecover reports a library function whose own body defers a
// recover: in a literal or in a function of the same package.
func dependencyDefersRecover(sources *patternkit.DependencySources, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || sources.Standard(fn.Pkg()) {
		return false
	}
	decl := sources.FuncDecl(fn)
	if decl == nil || decl.Body == nil {
		return false
	}
	for _, stmt := range decl.Body.List {
		d, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		switch callee := ast.Unparen(d.Call.Fun).(type) {
		case *ast.FuncLit:
			if callsRecover(nil, callee.Body) {
				return true
			}
		case *ast.Ident:
			// A name the file resolves is a parameter or local, not the package function.
			if callee.Obj != nil && callee.Obj.Kind != ast.Fun { //nolint:staticcheck // the parser's resolution is all an untyped library body has
				continue
			}
			if helper, ok := fn.Pkg().Scope().Lookup(callee.Name).(*types.Func); ok && dependencyCallsRecover(sources, helper) {
				return true
			}
		}
	}
	return false
}

// defersRecover reports a function whose own body defers a recover.
func defersRecover(scope patternkit.FuncScope, decl patternkit.TypedFuncDecl) bool {
	for _, stmt := range decl.Decl.Body.List {
		if d, ok := stmt.(*ast.DeferStmt); ok && deferredRecover(scope, decl.Info, d.Call) {
			return true
		}
	}
	return false
}

// callsRecover reports a call of the builtin recover in a body. Without types
// (a body parsed from a library's source) recover is the builtin unless the
// file declares the name: the parser resolves only names the file declares.
func callsRecover(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && ident.Name == "recover" {
				if info == nil {
					found = ident.Obj == nil //nolint:staticcheck // the parser's resolution is all an untyped library body has
				} else {
					_, found = info.Uses[ident].(*types.Builtin)
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
