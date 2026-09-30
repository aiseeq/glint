package patterns

import (
	"go/ast"
	"go/types"

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
	return rules.AnalyzeTypedFiles(ctx, r.Name(), r.analyzeFile)
}

// analyzeFile checks every function of the file, function literals included:
// a response is any value of type *net/http.Response a call returns, however
// the client was reached.
func (r *HTTPBodyCloseRule) analyzeFile(ctx *core.FileContext, info *types.Info) []*core.Violation {
	check := &resourceLeakCheck{
		file: ctx.GoAST,
		info: info,
		opens: func(expr ast.Expr) bool {
			_, isCall := ast.Unparen(expr).(*ast.CallExpr)
			return isCall && isPointerToNamedType(firstResultType(info, expr), "net/http", "Response")
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
	visit func(ast.Node)
}

func walkReachableStatements(statements []ast.Stmt, visit func(ast.Node)) {
	walker := &flowWalker[bool, struct{}]{rule: &httpBodyReachRule{visit: visit}}
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
	return state, isPanicStatement(stmt)
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
