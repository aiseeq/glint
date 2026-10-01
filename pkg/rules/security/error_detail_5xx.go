package security

import (
	"go/ast"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorDetailIn5xxResponseRule())
}

// ErrorDetailIn5xxResponseRule detects the text of an internal error sent to
// the client with a server-error status:
//
//	SendError(w, http.StatusInternalServerError, "Failed to get balance", "BALANCE_FAILED", err.Error())
//	http.Error(w, err.Error(), http.StatusInternalServerError)
//	writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("upstream: %v", err)})
//
// A 5xx error comes from inside: a driver message with table and constraint
// names, a file path, an upstream URL with its query, a stack of wrapped
// causes. The client cannot act on it, and whoever probes the API learns the
// internals. Log the error and send a fixed message with a code; a 4xx
// validation error is the client's own and is left alone. A call counts as a
// 5xx response by a 5xx status argument, or by a callee named for one
// (SendInternalServerError, writeServerError). A project helper taking the
// text is followed through its chain of helpers: if the parameter reaches the
// response writer only under a condition (details shown outside production or
// below 500), or goes only to logs and alerts, the call is fine.
type ErrorDetailIn5xxResponseRule struct {
	*rules.BaseRule
	// leaks maps a project function name to whether each of its parameters
	// can reach the response.
	leaks map[string][]bool
}

// NewErrorDetailIn5xxResponseRule creates the rule
func NewErrorDetailIn5xxResponseRule() *ErrorDetailIn5xxResponseRule {
	return &ErrorDetailIn5xxResponseRule{BaseRule: rules.NewBaseRule(
		"error-detail-in-5xx-response",
		"security",
		"Detects an internal error's text (err.Error(), %v of err) sent to the client in a 5xx response",
		core.SeverityMedium,
	)}
}

var (
	serverErrorStatus = map[string]bool{
		"StatusInternalServerError": true, "StatusNotImplemented": true, "StatusBadGateway": true,
		"StatusServiceUnavailable": true, "StatusGatewayTimeout": true,
	}
	serverErrorCallee = regexp.MustCompile(`(?:InternalServerError|InternalError|ServerError)`)
	errorValueName    = regexp.MustCompile(`^(?:err|e|[a-z]\w*Err|\w*Error)$`)
)

// AnalyzeFile reports 5xx responses that carry an error's text.
func (r *ErrorDetailIn5xxResponseRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !writesResponse(call) || !serverErrorCall(call) {
			return true
		}
		leaks, known := r.leaks[callName(call)]
		for i, arg := range call.Args {
			if known && (i >= len(leaks) || !leaks[i]) {
				continue
			}
			if carriesErrorText(arg) {
				lr.report(arg, "5xx response carries the internal error's text — the client gets driver messages, paths and upstream details it cannot act on",
					"Log the error with the request's trace id and send a fixed message and code", "error_detail_5xx")
				break
			}
		}
		return true
	})
	return lr.violations
}

// UseProjectFiles indexes which parameters of the project's functions can
// reach a response. A helper passing a parameter on to another helper leaks
// it if that one does, so the index is recomputed until it stops changing.
func (r *ErrorDetailIn5xxResponseRule) UseProjectFiles(files []*core.FileContext) {
	var funcs []*ast.FuncDecl
	for _, ctx := range files {
		if !ctx.HasGoAST() || ctx.IsTestFile() {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			// Only functions taking the writer can write the response; one
			// without it sharing a name with a writer call (Encode on
			// json.NewEncoder(w)) says nothing about that call.
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && writerParameter(fn) != "" {
				funcs = append(funcs, fn)
			}
		}
	}
	r.leaks = make(map[string][]bool)
	for _, fn := range funcs {
		if n := fn.Type.Params.NumFields(); n > len(r.leaks[fn.Name.Name]) {
			r.leaks[fn.Name.Name] = make([]bool, n)
		}
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range funcs {
			writer := writerParameter(fn)
			var params []bool
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					params = append(params, r.parameterLeaks(fn.Body, name.Name, writer))
				}
			}
			// Functions of the same name in other packages: any that leaks
			// a parameter makes the call reportable.
			prev := r.leaks[fn.Name.Name]
			for i := range params {
				leaked := i < len(prev) && prev[i]
				if params[i] && !leaked {
					changed = true
				}
				params[i] = params[i] || leaked
			}
			r.leaks[fn.Name.Name] = append(params, prev[len(params):]...)
		}
	}
}

// ResetState drops the index of the previous root.
func (r *ErrorDetailIn5xxResponseRule) ResetState() { r.leaks = nil }

// writerParameter returns the name of a function's response writer parameter,
// or "" when it has none.
func writerParameter(fn *ast.FuncDecl) string {
	for _, field := range fn.Type.Params.List {
		sel, ok := field.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ResponseWriter" {
			continue
		}
		for _, name := range field.Names {
			return name.Name
		}
	}
	return ""
}

// parameterLeaks reports a parameter that reaches a call involving the
// response writer (w.Write, json.NewEncoder(w).Encode, a helper given w that
// leaks it), directly or through variables assigned from it. An assignment
// inside an if (details shown only in development, only below 500) does not
// carry it; calls without the writer (logging, alerts) do not leak it.
func (r *ErrorDetailIn5xxResponseRule) parameterLeaks(body *ast.BlockStmt, name, writer string) bool {
	tainted := map[string]bool{name: true}
	carries := func(expr ast.Expr) bool {
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && tainted[ident.Name] {
				found = true
			}
			return !found
		})
		return found
	}
	guarded := guardedAssignments(body, name)
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || guarded[assign] || len(assign.Lhs) != len(assign.Rhs) {
				return true
			}
			for i, lhs := range assign.Lhs {
				root := rootIdent(lhs)
				if root != nil && !tainted[root.Name] && carries(assign.Rhs[i]) {
					tainted[root.Name] = true
					changed = true
				}
			}
			return true
		})
	}
	leaks := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || leaks || !mentions(call, writer) {
			return !leaks
		}
		calleeLeaks, known := r.leaks[callName(call)]
		for i, arg := range call.Args {
			if carries(arg) && (!known || (i < len(calleeLeaks) && calleeLeaks[i])) {
				leaks = true
			}
		}
		return !leaks
	})
	return leaks
}

// guardedAssignments returns the assignments inside the body of an if that
// also decides by something else than the parameter: if !production or if
// status < 500 is a policy, if details != "" alone only skips an empty value.
func guardedAssignments(body *ast.BlockStmt, name string) map[*ast.AssignStmt]bool {
	guarded := make(map[*ast.AssignStmt]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || !slices.ContainsFunc(conjuncts(ifStmt.Cond), func(c ast.Expr) bool { return !mentions(c, name) }) {
			return true
		}
		ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
			if assign, ok := m.(*ast.AssignStmt); ok {
				guarded[assign] = true
			}
			return true
		})
		return true
	})
	return guarded
}

// conjuncts splits a && b && c into its operands.
func conjuncts(expr ast.Expr) []ast.Expr {
	and, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || and.Op != token.LAND {
		return []ast.Expr{expr}
	}
	return append(conjuncts(and.X), conjuncts(and.Y)...)
}

// rootIdent returns x for x, x.f and x[i].
func rootIdent(expr ast.Expr) *ast.Ident {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			return e
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		default:
			return nil
		}
	}
}

// mentions reports a node naming the identifier: a call in its function or
// arguments, a condition anywhere.
func mentions(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// writesResponse reports a call handed the response writer: its first
// argument is named w, rw, res or writer.
func writesResponse(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	ident, ok := call.Args[0].(*ast.Ident)
	return ok && (ident.Name == "w" || ident.Name == "rw" || ident.Name == "res" || ident.Name == "writer")
}

// serverErrorCall reports a call with a 5xx status argument or named for one.
func serverErrorCall(call *ast.CallExpr) bool {
	if serverErrorCallee.MatchString(callName(call)) {
		return true
	}
	for _, arg := range call.Args {
		switch a := arg.(type) {
		case *ast.SelectorExpr:
			if serverErrorStatus[a.Sel.Name] {
				return true
			}
		case *ast.BasicLit:
			if a.Kind == token.INT {
				if code, err := strconv.Atoi(a.Value); err == nil && code >= 500 && code <= 599 {
					return true
				}
			}
		}
	}
	return false
}

// carriesErrorText reports err.Error(), or a fmt.Sprintf/Errorf whose
// arguments hold an error value, possibly inside a composite literal.
func carriesErrorText(arg ast.Expr) bool {
	found := false
	ast.Inspect(arg, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" && len(call.Args) == 0 {
			if ident, ok := sel.X.(*ast.Ident); ok && errorValueName.MatchString(ident.Name) {
				found = true
			}
		}
		if pkg, ok := callPackage(call); ok && pkg == "fmt" && strings.HasPrefix(callName(call), "Sprint") && len(call.Args) > 0 {
			for _, a := range call.Args[1:] {
				if ident, ok := a.(*ast.Ident); ok && errorValueName.MatchString(ident.Name) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
