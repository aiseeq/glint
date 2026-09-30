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
// receive a context.
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
			"Detects context.Background/TODO usage where a passed context should be used",
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
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if _, live := contextParams(ctx.GoAST, info, fn.Type); !live {
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
	}
	return violations
}

// firstDoneWait returns the position of the first receive from the Done
// channel of one of the function's context parameters, or token.NoPos.
func firstDoneWait(file *ast.File, info *types.Info, fn *ast.FuncDecl) token.Pos {
	params := map[string]bool{}
	for _, field := range fn.Type.Params.List {
		if !isContextTypeExpr(file, info, field.Type) {
			continue
		}
		for _, name := range field.Names {
			params[name.Name] = true
		}
	}
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
