package concurrencyrules

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewLazyGlobalInitWithoutSyncRule())
}

// NewLazyGlobalInitWithoutSyncRule creates lazy-global-init-without-sync: a
// getter that builds a package-level value on first use checks and sets it
// without synchronization, so concurrent first callers race on it:
//
//	func Default() *Logger {
//		if global == nil {
//			global = newLogger()   // two goroutines build two loggers
//		}
//		return global
//	}
//
// A function that locks a mutex, runs a sync.Once or goes through
// sync/atomic is synchronized; init runs before any goroutine.
func NewLazyGlobalInitWithoutSyncRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"lazy-global-init-without-sync",
			"patterns",
			"Detects a package-level value built on first use by `if v == nil { v = ... }` with no mutex, sync.Once or atomic — concurrent first callers race on it",
			core.SeverityMedium,
		),
		Suggestion: "Build the value with sync.Once (or in init, or behind a mutex)",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		if fn.Recv == nil && fn.Name.Name == "init" || synchronizes(scope.Info, fn.Body) {
			return nil
		}
		var findings []patternkit.FuncFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false
			}
			check, ok := n.(*ast.IfStmt)
			if !ok || check.Else != nil {
				return true
			}
			if v := nilCheckedGlobal(scope.Info, check.Cond); v != nil && patternkit.AssignsVar(scope.Info, check.Body, v) {
				findings = append(findings, patternkit.FuncFinding{Node: check, Message: "The package-level " + v.Name() + " is built on first use with no synchronization — concurrent first callers race on it"})
			}
			return true
		})
		return findings
	}
	return r
}

// nilCheckedGlobal returns the package-level variable of `v == nil`.
func nilCheckedGlobal(info *types.Info, cond ast.Expr) *types.Var {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL || !helpers.IsNilIdent(bin.Y) {
		return nil
	}
	ident, ok := ast.Unparen(bin.X).(*ast.Ident)
	if !ok {
		return nil
	}
	v, ok := info.Uses[ident].(*types.Var)
	if !ok || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
		return nil
	}
	return v
}

// synchronizes reports a body that locks a mutex, runs a sync.Once or calls
// sync/atomic.
func synchronizes(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		obj, ok := info.Uses[sel.Sel].(*types.Func)
		if !ok || obj.Pkg() == nil {
			return true
		}
		switch obj.Pkg().Path() {
		case "sync":
			found = obj.Name() == "Lock" || obj.Name() == "RLock" || obj.Name() == "Do"
		case "sync/atomic":
			found = true
		}
		return !found
	})
	return found
}
