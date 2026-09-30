package patterns

import (
	"fmt"
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
		if isPointerToNamedType(signature.Results().At(i).Type(), "net/http", "Response") {
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
		if isNilIdent(ast.Unparen(expr)) {
			continue
		}
		variable := variableOf(info, ast.Unparen(expr))
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
	check := &resourceLeakCheck{
		file: ctx.GoAST,
		info: info,
		opens: func(expr ast.Expr) bool {
			call, isCall := ast.Unparen(expr).(*ast.CallExpr)
			if !isCall || !isPointerToNamedType(firstResultType(info, expr), "net/http", "Response") {
				return false
			}
			if callee, ok := typeutil.Callee(info, call).(*types.Func); ok && closers[callee.Origin()] {
				return false
			}
			return true
		},
		releases: func(call *ast.CallExpr) types.Object {
			// resp.Body.Close()
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Close" {
				return nil
			}
			return httpResponseOfBody(info, sel.X)
		},
		carries: func(expr ast.Expr) types.Object {
			if variable := variableOf(info, expr); variable != nil {
				return variable
			}
			return httpResponseOfBody(info, expr)
		},
	}

	var violations []*core.Violation
	for _, leak := range check.leaks() {
		line := ctx.LineFor(leak.at)
		v := r.CreateViolation(ctx.RelPath, line, "HTTP response body not closed - resource leak")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Add defer " + leak.name + ".Body.Close() after nil check")
		v.WithContext("pattern", "http_body_leak")
		v.WithContext("variable", leak.name)
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
	variable := variableOf(info, ast.Unparen(sel.X))
	if variable == nil || !isPointerToNamedType(variable.Type(), "net/http", "Response") {
		return nil
	}
	return variable
}

// httpBodyReachRule adapts the shared flow walker into a plain reachability
// walk: the state is a single "reachable" flag and every visited node is
// handed to the visit callback.
type httpBodyReachRule struct {
	info  *types.Info
	file  *ast.File
	visit func(ast.Node)
}

// walkReachableStatements hands visit every statement a path reaches; a call
// that never returns (panic, os.Exit, log.Fatal) ends the path. info and file
// may be nil.
func walkReachableStatements(statements []ast.Stmt, info *types.Info, file *ast.File, visit func(ast.Node)) {
	walker := &flowWalker[bool, struct{}]{rule: &httpBodyReachRule{info: info, file: file, visit: visit}}
	walker.stmtList(statements, true, struct{}{})
}

func (r *httpBodyReachRule) cloneState(state bool) bool { return state }

func (r *httpBodyReachRule) joinStates(bool, bool) bool { return true }

func (r *httpBodyReachRule) liveState(state bool) bool { return state }

func (r *httpBodyReachRule) deadState() bool { return false }

func (r *httpBodyReachRule) enterScope(_ flowScopeKind, _ ast.Node, parent struct{}, state bool) (struct{}, bool) {
	return parent, state
}

func (r *httpBodyReachRule) leaveScope(flowScopeKind, struct{}, *flowEdges[bool]) {}

func (r *httpBodyReachRule) simpleStmt(stmt ast.Stmt, state bool, _ struct{}) (bool, bool) {
	r.visit(stmt)
	if _, isReturn := stmt.(*ast.ReturnStmt); isReturn {
		return false, true
	}
	return state, stmtNoReturn(stmt, r.info, r.file) != callReturns
}

func (r *httpBodyReachRule) ifCondition(stmt *ast.IfStmt, state bool, _ struct{}) (bool, bool) {
	r.visit(stmt.Cond)
	return state, state
}

func (r *httpBodyReachRule) flowExpr(expr ast.Expr, state bool, _ struct{}) bool {
	r.visit(expr)
	return state
}

func (r *httpBodyReachRule) rangeVars(_ *ast.RangeStmt, state bool, _ struct{}) bool {
	return state
}

func (r *httpBodyReachRule) typeSwitchGuard(stmt ast.Stmt, state bool, scope struct{}) bool {
	next, _ := r.simpleStmt(stmt, state, scope)
	return next
}

func (r *httpBodyReachRule) caseClause(_ ast.Stmt, clause *ast.CaseClause, state bool, parent struct{}) (bool, struct{}) {
	for _, expression := range clause.List {
		r.visit(expression)
	}
	return state, parent
}

func (r *httpBodyReachRule) commClause(_ *ast.CommClause, state bool, parent struct{}) (bool, struct{}) {
	return state, parent
}

func (r *httpBodyReachRule) normalize(*flowEdges[bool]) {}
