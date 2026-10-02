package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewCacheStoresCancelledErrorRule())
}

// CacheStoresCancelledErrorRule detects a shared cache that stores the error
// of a load made with the caller's context and serves it to later callers:
//
//	func (c *cache) get(ctx context.Context, load func(context.Context) (*Report, error)) (*Report, error) {
//	    if c.expiresAt.After(now()) {
//	        return c.report, c.err
//	    }
//	    c.report, c.err = load(ctx)
//
// A caller that closes the tab or hits its own deadline cancels the load,
// and its "context canceled" stays in the cache for the TTL: every other
// reader gets a failure nobody had. Reported: an error from a call handed the
// function's context parameter is stored in a field (or package variable)
// that the function also returns, with no look at the context's own error
// (ctx.Err(), context.Canceled, context.DeadlineExceeded) in the function.
type CacheStoresCancelledErrorRule struct {
	*rules.BaseRule
}

// NewCacheStoresCancelledErrorRule creates the rule
func NewCacheStoresCancelledErrorRule() *CacheStoresCancelledErrorRule {
	return &CacheStoresCancelledErrorRule{BaseRule: rules.NewBaseRule(
		"cache-stores-cancelled-error",
		"patterns",
		"Detects a cache storing the error of a load made with the caller's context — one caller's cancellation is served to every later reader",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: which value is a context is a question about types.
func (r *CacheStoresCancelledErrorRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *CacheStoresCancelledErrorRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the cached errors of loads made with the caller's context.
func (r *CacheStoresCancelledErrorRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return analyzeGoFunctions(fileCtx, func(fn *ast.FuncDecl) []*core.Violation {
			return r.checkFunction(fileCtx, info, fn)
		})
	})
}

func (r *CacheStoresCancelledErrorRule) checkFunction(ctx *core.FileContext, info *types.Info, fn *ast.FuncDecl) []*core.Violation {
	ctxParam := contextParam(info, fn)
	if ctxParam == nil || looksAtContextError(info, fn.Body) {
		return nil
	}
	returned := returnedStores(info, fn.Body)
	if len(returned) == 0 {
		return nil
	}
	// fromContext holds the locals assigned the error of a call handed ctx.
	fromContext := map[types.Object]bool{}
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			if !implementsError(info.TypeOf(lhs)) {
				continue
			}
			if !errorFromContextCall(info, assign, i, ctxParam, fromContext) {
				continue
			}
			if ident, ok := lhs.(*ast.Ident); ok {
				if obj := info.ObjectOf(ident); obj != nil && !isPackageLevelObj(obj) {
					fromContext[obj] = true
					continue
				}
			}
			if store := storedObject(info, lhs); store != nil && returned[store] {
				line := ctx.LineFor(assign)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line, "The error of a load made with the caller's context is cached and served to later callers — one caller's cancellation becomes everyone's answer")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Do not store the result when ctx.Err() != nil, or load with a context of the cache's own")
				violations = append(violations, v)
			}
		}
		return true
	})
	return violations
}

// contextParam returns the context.Context parameter of a function.
func contextParam(info *types.Info, fn *ast.FuncDecl) types.Object {
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if obj := info.ObjectOf(name); obj != nil && types.TypeString(obj.Type(), nil) == "context.Context" {
				return obj
			}
		}
	}
	return nil
}

// looksAtContextError reports a function that reads the context's own error:
// ctx.Err(), context.Canceled, context.DeadlineExceeded.
func looksAtContextError(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return !found
		}
		switch sel.Sel.Name {
		case "Err":
			found = types.TypeString(info.TypeOf(sel.X), nil) == "context.Context"
		case "Canceled", "DeadlineExceeded":
			found = isIdentNamed(sel.X, "context")
		}
		return !found
	})
	return found
}

// returnedStores returns the fields and package variables a function returns
// as they are: return c.report, c.err.
func returnedStores(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	stores := map[types.Object]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok {
			for _, result := range ret.Results {
				if store := storedObject(info, result); store != nil {
					stores[store] = true
				}
			}
		}
		return true
	})
	return stores
}

// storedObject returns the field of a selector or the package variable an
// expression names, nil for a local.
func storedObject(info *types.Info, expr ast.Expr) types.Object {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		if v, ok := info.ObjectOf(e.Sel).(*types.Var); ok && v.IsField() {
			return v
		}
	case *ast.Ident:
		if obj := info.ObjectOf(e); obj != nil && isPackageLevelObj(obj) {
			return obj
		}
	}
	return nil
}

func isPackageLevelObj(obj types.Object) bool {
	return obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope()
}

// errorFromContextCall reports the value assigned at index being the error of
// a call handed the context parameter, directly or through a local holding it.
func errorFromContextCall(info *types.Info, assign *ast.AssignStmt, index int, ctxParam types.Object, fromContext map[types.Object]bool) bool {
	var value ast.Expr
	switch {
	case len(assign.Rhs) == len(assign.Lhs):
		value = assign.Rhs[index]
	case len(assign.Rhs) == 1:
		value = assign.Rhs[0]
	default:
		return false
	}
	switch v := ast.Unparen(value).(type) {
	case *ast.Ident:
		return fromContext[info.ObjectOf(v)]
	case *ast.CallExpr:
		for _, arg := range v.Args {
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && info.ObjectOf(ident) == ctxParam {
				return true
			}
		}
	}
	return false
}
