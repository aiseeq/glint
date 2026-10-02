package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewContextBackgroundRule())
}

// ContextBackgroundRule detects context.Background/TODO usage in functions that
// receive a context, and context.WithoutCancel(ctx) whose context only feeds
// reads the function waits for — the same detachment under another name.
//
// Also reported: context.Background/TODO inside a goroutine that stops on a
// channel - the stop reaches the loop, not the work it runs.
//
// Not flagged: a context created after the function has waited for its ctx to
// end (<-ctx.Done()) — the graceful-shutdown shape, where the cancelled ctx
// would abort the cleanup at once; a context parameter declared `_`, which the
// function deliberately discards; test files.
type ContextBackgroundRule struct {
	*rules.BaseRule
}

// NewContextBackgroundRule creates the rule
func NewContextBackgroundRule() *ContextBackgroundRule {
	return &ContextBackgroundRule{
		BaseRule: rules.NewBaseRule(
			"context-background",
			"patterns",
			"Detects context.Background/TODO usage where a passed context should be used, and context.WithoutCancel(ctx) detaching a read the function waits for",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: context.Context and
// context.Background are known through the file's import of "context".
func (r *ContextBackgroundRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ContextBackgroundRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, with type information where the package
// has it.
func (r *ContextBackgroundRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports context.Background/TODO in functions with a live context
// parameter.
func (r *ContextBackgroundRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation
	launched := launchedFunctions(ctx.GoAST)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if _, live := contextParams(ctx.GoAST, info, fn.Type); !live {
			violations = append(violations, r.stoppableLoopDetachedWork(ctx, info, fn)...)
			continue
		}
		doneAt := firstDoneWait(ctx.GoAST, info, fn)

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := packageFuncName(ctx.GoAST, info, call, "context")
			if !ok || (name != "Background" && name != "TODO") {
				return true
			}
			// After the caller's ctx has ended, a fresh context is the only
			// one left for the cleanup.
			if doneAt.IsValid() && call.Pos() > doneAt {
				return true
			}
			line := ctx.LineFor(call)
			v := r.CreateViolation(ctx.RelPath, line,
				"Using context."+name+"() in a function that receives context parameter")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Use the context parameter passed to the function; work that must outlive its cancellation can derive from it with context.WithoutCancel(ctx)")
			violations = append(violations, v)
			return true
		})
		violations = append(violations, r.detachedReads(ctx, info, fn, doneAt, launched)...)
	}
	return violations
}

// stoppableLoopDetachedWork reports context.Background/TODO inside a
// goroutine that stops on a channel (case <-s.stop: return): the loop can be
// stopped, the work it runs cannot be cancelled, so stopping waits for the
// work in flight or a shutdown cuts it mid-write.
func (r *ContextBackgroundRule) stoppableLoopDetachedWork(ctx *core.FileContext, info *types.Info, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		lit, ok := goStmt.Call.Fun.(*ast.FuncLit)
		if !ok || !selectsStopAndReturns(lit.Body) {
			return false
		}
		ast.Inspect(lit.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := packageFuncName(ctx.GoAST, info, call, "context")
			if !ok || (name != "Background" && name != "TODO") {
				return true
			}
			line := ctx.LineFor(call)
			if ctx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"The goroutine stops on its stop channel, but its work runs under context."+name+"() - stopping cannot cancel the work in flight, and a shutdown cuts it mid-write")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Run the loop under a root context that the stop cancels, and pass that context to the work")
			violations = append(violations, v)
			return true
		})
		return false
	})
	return violations
}

// selectsStopAndReturns reports a select with a case receiving from a
// channel that returns: the goroutine's way to stop.
func selectsStopAndReturns(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		clause, ok := n.(*ast.CommClause)
		if !ok || found || clause.Comm == nil {
			return !found
		}
		expr, ok := clause.Comm.(*ast.ExprStmt)
		if !ok {
			return true
		}
		recv, ok := expr.X.(*ast.UnaryExpr)
		if !ok || recv.Op != token.ARROW {
			return true
		}
		if sel, ok := recv.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "C" {
			return true // a ticker's tick, not a stop
		}
		for _, stmt := range clause.Body {
			if _, ok := stmt.(*ast.ReturnStmt); ok {
				found = true
			}
		}
		return !found
	})
	return found
}

// firstDoneWait returns the position of the first receive from the Done
// channel of one of the function's context parameters, or token.NoPos.
func firstDoneWait(file *ast.File, info *types.Info, fn *ast.FuncDecl) token.Pos {
	params := contextParamNames(file, info, fn.Type)
	first := token.NoPos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		recv, ok := n.(*ast.UnaryExpr)
		if !ok || recv.Op != token.ARROW {
			return true
		}
		call, ok := ast.Unparen(recv.X).(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Done" {
			return true
		}
		if ident, ok := ast.Unparen(sel.X).(*ast.Ident); ok && params[ident.Name] {
			if !first.IsValid() || recv.Pos() < first {
				first = recv.Pos()
			}
		}
		return true
	})
	return first
}
