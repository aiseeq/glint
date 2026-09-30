package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRetryRequestReuseRule())
}

// RetryRequestReuseRule detects one *http.Request built once and sent again
// inside a retry loop.
//
// An *http.Request is single use: the transport reads and closes its body, so
// the second Do sends nothing and fails on ContentLength before the request
// ever leaves the process. Anything the first attempt carried per attempt — a
// signature with a timestamp, an idempotency key, a deadline header — is stale
// too. The loop looks like a retry and never retries.
//
// Real case (projectA, 2026-09): a payment client retried the same request and
// every second attempt died with "ContentLength=82 with Body length 0"; the
// provider never saw it, and the failure text named the body, not the outage.
//
// Not flagged: a request built inside the loop (rebuilt per attempt), a loop
// that builds its own request per item, and a request built without a body
// (nil or http.NoBody) — a GET poll resends nothing that could be drained.
type RetryRequestReuseRule struct {
	*rules.BaseRule
}

// NewRetryRequestReuseRule creates the rule.
func NewRetryRequestReuseRule() *RetryRequestReuseRule {
	return &RetryRequestReuseRule{
		BaseRule: rules.NewBaseRule(
			"retry-request-reuse",
			"patterns",
			"Detects one *http.Request sent again inside a retry loop — its body is already drained, so the retry never reaches the server",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks one file without type information: the request builder
// and the request type are known through the file's import of net/http.
func (r *RetryRequestReuseRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *RetryRequestReuseRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, with type information where the package
// has it.
func (r *RetryRequestReuseRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports send calls that reuse a request built outside their loop.
func (r *RetryRequestReuseRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		outer := requestNamesBuiltOutsideLoops(ctx.GoAST, info, fn)
		for name := range requestParameterNames(ctx.GoAST, info, fn.Type) {
			outer[name] = true
		}
		if len(outer) == 0 {
			continue
		}
		violations = append(violations, r.checkLoops(ctx, info, fn.Body, outer)...)
	}
	return violations
}

// checkLoops reports a send of an outer request inside any loop of the body.
func (r *RetryRequestReuseRule) checkLoops(ctx *core.FileContext, info *types.Info, body *ast.BlockStmt, outer map[string]bool) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(body, func(n ast.Node) bool {
		var loopBody *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.ForStmt:
			loopBody = loop.Body
		case *ast.RangeStmt:
			loopBody = loop.Body
		default:
			return true
		}

		// A request rebuilt inside the loop is a fresh one on every attempt,
		// even when a variable of the same name exists outside.
		rebuilt := requestNamesBuiltIn(ctx.GoAST, info, loopBody)
		ast.Inspect(loopBody, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := httpSendArgument(call)
			if !ok || rebuilt[name] || !outer[name] {
				return true
			}
			line := lineFromNode(ctx, call)
			if ctx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"the same *http.Request is sent again inside a loop — its body is drained after the first send, and the retry fails before reaching the server")
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Build the request (and anything signed or timestamped in it) inside the loop, once per attempt")
			v.WithContext("pattern", "retry_request_reuse")
			violations = append(violations, v)
			return true
		})
		return true
	})
	return violations
}

// httpSendArgument returns the identifier passed to a Do-style send call.
func httpSendArgument(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Do" || len(call.Args) != 1 {
		return "", false
	}
	ident, ok := call.Args[0].(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// requestNamesBuiltOutsideLoops collects request variables created in the
// function body but outside any loop.
func requestNamesBuiltOutsideLoops(file *ast.File, info *types.Info, fn *ast.FuncDecl) map[string]bool {
	names := make(map[string]bool)
	var walk func(node ast.Node, inLoop bool)
	walk = func(node ast.Node, inLoop bool) {
		ast.Inspect(node, func(n ast.Node) bool {
			switch current := n.(type) {
			case *ast.ForStmt:
				walk(current.Body, true)
				return false
			case *ast.RangeStmt:
				walk(current.Body, true)
				return false
			case *ast.FuncLit:
				return false
			case *ast.AssignStmt:
				if inLoop {
					return true
				}
				for _, name := range requestTargets(file, info, current, true) {
					names[name] = true
				}
			}
			return true
		})
	}
	walk(fn.Body, false)
	return names
}

// requestNamesBuiltIn collects request variables created inside one block.
func requestNamesBuiltIn(file *ast.File, info *types.Info, block *ast.BlockStmt) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(block, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, name := range requestTargets(file, info, assign, false) {
			names[name] = true
		}
		return true
	})
	return names
}

// requestTargets returns the names assigned from http.NewRequest* calls. With
// withBodyOnly a request built without a body (nil or http.NoBody) is left
// out: nothing in it is drained by a send, so sending it again is fine.
func requestTargets(file *ast.File, info *types.Info, assign *ast.AssignStmt, withBodyOnly bool) []string {
	for _, rhs := range assign.Rhs {
		call, ok := rhs.(*ast.CallExpr)
		if !ok {
			continue
		}
		name, ok := packageFuncName(file, info, call, "net/http")
		if !ok || (name != "NewRequest" && name != "NewRequestWithContext") {
			continue
		}
		if withBodyOnly && requestHasNoBody(file, info, call, name) {
			return nil
		}
		var names []string
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
				names = append(names, ident.Name)
				break
			}
		}
		return names
	}
	return nil
}

// requestHasNoBody reports whether the request builder gets nil or
// http.NoBody as the body.
func requestHasNoBody(file *ast.File, info *types.Info, call *ast.CallExpr, builder string) bool {
	bodyIndex := 2
	if builder == "NewRequestWithContext" {
		bodyIndex = 3
	}
	if len(call.Args) <= bodyIndex {
		return false
	}
	body := ast.Unparen(call.Args[bodyIndex])
	if info != nil {
		if tv, ok := info.Types[body]; ok && tv.IsNil() {
			return true
		}
	} else if isNilIdent(body) {
		return true
	}
	sel, ok := body.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "NoBody" {
		return false
	}
	if info != nil {
		variable, ok := info.Uses[sel.Sel].(*types.Var)
		return ok && variable.Pkg() != nil && variable.Pkg().Path() == "net/http"
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && importAliases(file)[pkg.Name] == "net/http"
}

// requestParameterNames collects *http.Request parameters: the caller built
// them, so the loop cannot rebuild them either.
func requestParameterNames(file *ast.File, info *types.Info, funcType *ast.FuncType) map[string]bool {
	names := make(map[string]bool)
	if funcType == nil || funcType.Params == nil {
		return names
	}
	for _, param := range funcType.Params.List {
		if !isHTTPRequestPointerType(file, info, param.Type) {
			continue
		}
		for _, name := range param.Names {
			if name.Name != "_" {
				names[name.Name] = true
			}
		}
	}
	return names
}

// isHTTPRequestPointerType reports whether a type expression is *http.Request:
// by type when info is available, otherwise by the file's import of net/http.
func isHTTPRequestPointerType(file *ast.File, info *types.Info, expr ast.Expr) bool {
	if info != nil {
		return isPointerToNamedType(info.TypeOf(expr), "net/http", "Request")
	}
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Request" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && importAliases(file)[pkg.Name] == "net/http"
}
