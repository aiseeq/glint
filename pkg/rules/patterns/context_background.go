package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewContextBackgroundRule())
}

// ContextBackgroundRule detects context.Background/TODO usage in functions that receive context
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

// AnalyzeFile checks for context.Background/TODO misuse
func (r *ContextBackgroundRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	// Track functions that have context.Context parameter
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Check if function has context.Context parameter
		hasCtxParam := r.hasContextParam(fn)
		if !hasCtxParam {
			return true
		}

		// Look for context.Background() or context.TODO() calls inside
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}

			if r.isContextBackgroundOrTodo(call) {
				pos := ctx.PositionFor(call)
				message := r.getMessage(call)
				v := r.CreateViolation(ctx.RelPath, pos.Line, message)
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Use the context parameter passed to the function")
				violations = append(violations, v)
			}

			return true
		})

		return true
	})

	return violations
}

func (r *ContextBackgroundRule) hasContextParam(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}

	for _, param := range fn.Type.Params.List {
		if r.isContextType(param.Type) {
			return true
		}
	}

	return false
}

func (r *ContextBackgroundRule) isContextType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	return ident.Name == "context" && sel.Sel.Name == "Context"
}

func (r *ContextBackgroundRule) isContextBackgroundOrTodo(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	if ident.Name != "context" {
		return false
	}

	return sel.Sel.Name == "Background" || sel.Sel.Name == "TODO"
}

func (r *ContextBackgroundRule) getMessage(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "Using context.Background()/TODO() in a function that receives context parameter"
	}
	name := sel.Sel.Name

	if strings.ToLower(name) == "todo" {
		return "Using context.TODO() in a function that receives context parameter"
	}
	return "Using context.Background() in a function that receives context parameter"
}
