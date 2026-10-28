package httprules

import (
	"fmt"
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"golang.org/x/tools/go/types/typeutil"
)

func init() {
	rules.Register(NewHTTPBodyCloseRule())
}

// HTTPBodyCloseRule detects HTTP response body not being closed
type HTTPBodyCloseRule struct {
	*rules.BaseRule
}

// NewHTTPBodyCloseRule creates the rule
func NewHTTPBodyCloseRule() *HTTPBodyCloseRule {
	return &HTTPBodyCloseRule{
		BaseRule: rules.NewBaseRule(
			"http-body-close",
			"patterns",
			"Detects HTTP response body not being closed (resource leak)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile is a no-op: whether a call yields an *http.Response is a
// question about its type, which one file without type information cannot
// answer.
func (r *HTTPBodyCloseRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *HTTPBodyCloseRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports responses whose body no path closes.
func (r *HTTPBodyCloseRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	closers := bodyClosingHelpers(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyzeFile(fileCtx, info, closers)
	})
}

// bodyClosingHelpers returns the project functions that hand back an
// *http.Response whose body they have already closed: a client helper that
// reads the body, closes it and returns the response for its status and
// headers. Their callers have nothing left to close.
func bodyClosingHelpers(ctx *core.GoProjectContext) map[*types.Func]bool {
	closers := map[*types.Func]bool{}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		info := pkgCtx.Package.TypesInfo
		for _, file := range pkgCtx.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				obj, ok := info.Defs[fn.Name].(*types.Func)
				if ok && closesReturnedBody(fn, info) {
					closers[obj] = true
				}
			}
		}
	}
	return closers
}

// closesReturnedBody reports whether every response the function returns is
// a variable whose body the function closes somewhere, deferred closures
// included. A response returned straight from a call, or one never closed,
// is the caller's to close.
func closesReturnedBody(fn *ast.FuncDecl, info *types.Info) bool {
	signature, ok := info.Defs[fn.Name].Type().(*types.Signature)
	if !ok {
		return false
	}
	position := -1
	for i := range signature.Results().Len() {
		if patternkit.IsPointerToNamedType(signature.Results().At(i).Type(), "net/http", "Response") {
			position = i
			break
		}
	}
	if position < 0 {
		return false
	}
	closed := map[types.Object]bool{}
	var returned []ast.Expr
	allClosed := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
				if response := httpResponseOfBody(info, sel.X); response != nil {
					closed[response] = true
				}
			}
		case *ast.FuncLit:
			// A closure's returns are its own; its Close calls still count.
			ast.Inspect(node.Body, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
						if response := httpResponseOfBody(info, sel.X); response != nil {
							closed[response] = true
						}
					}
				}
				return true
			})
			return false
		case *ast.ReturnStmt:
			if len(node.Results) != signature.Results().Len() {
				allClosed = false // bare return or `return f()`
				return true
			}
			returned = append(returned, node.Results[position])
		}
		return true
	})
	if !allClosed {
		return false
	}
	closesAny := false
	for _, expr := range returned {
		if helpers.IsNilIdent(ast.Unparen(expr)) {
			continue
		}
		variable := patternkit.VariableOf(info, ast.Unparen(expr))
		if variable == nil || !closed[variable] {
			return false
		}
		closesAny = true
	}
	return closesAny
}

// analyzeFile checks every function of the file, function literals included:
// a response is any value of type *net/http.Response a call returns, however
// the client was reached, except from a project helper that already closed
// its body.
func (r *HTTPBodyCloseRule) analyzeFile(ctx *core.FileContext, info *types.Info, closers map[*types.Func]bool) []*core.Violation {
	check := &patternkit.ResourceLeakCheck{
		File: ctx.GoAST,
		Info: info,
		Opens: func(expr ast.Expr) bool {
			call, isCall := ast.Unparen(expr).(*ast.CallExpr)
			if !isCall || !patternkit.IsPointerToNamedType(patternkit.FirstResultType(info, expr), "net/http", "Response") {
				return false
			}
			if callee, ok := typeutil.Callee(info, call).(*types.Func); ok && closers[callee.Origin()] {
				return false
			}
			return true
		},
		Releases: func(call *ast.CallExpr) types.Object {
			// resp.Body.Close()
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Close" {
				return nil
			}
			return httpResponseOfBody(info, sel.X)
		},
		Carries: func(expr ast.Expr) types.Object {
			if variable := patternkit.VariableOf(info, expr); variable != nil {
				return variable
			}
			return httpResponseOfBody(info, expr)
		},
	}

	var violations []*core.Violation
	for _, leak := range check.Leaks() {
		line := ctx.LineFor(leak.At)
		v := r.CreateViolation(ctx.RelPath, line, "HTTP response body not closed - resource leak")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Add defer " + leak.Name + ".Body.Close() after nil check")
		v.WithContext("pattern", "http_body_leak")
		v.WithContext("variable", leak.Name)
		violations = append(violations, v)
	}
	return violations
}

// httpResponseOfBody returns the response variable of a resp.Body expression.
func httpResponseOfBody(info *types.Info, expr ast.Expr) types.Object {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Body" {
		return nil
	}
	variable := patternkit.VariableOf(info, ast.Unparen(sel.X))
	if variable == nil || !patternkit.IsPointerToNamedType(variable.Type(), "net/http", "Response") {
		return nil
	}
	return variable
}
