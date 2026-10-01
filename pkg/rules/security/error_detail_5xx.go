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
	rules.Register(NewErrorDetailInAuthFailureResponseRule())
}

// ErrorDetailResponseRule detects the text of an error sent to the client in
// a response of a status class the client must not learn internals from.
// error-detail-in-5xx-response covers server errors:
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
//
// error-detail-in-auth-failure-response covers 401 and 403: the error that
// rejected the request comes from a token parser, a signature check or the
// identity provider, and its text names the expected key, the claims and the
// upstream, sent to a caller who is not authenticated:
//
//	http.Error(w, err.Error(), http.StatusUnauthorized)
//	SendError(w, http.StatusUnauthorized, "Invalid cookie", "UNAUTHORIZED", err.Error())
//
// An access check of the project that returns only fixed texts ("access
// denied: project not assigned") writes its errors for the caller, and its
// error in a 403 is the designed answer.
type ErrorDetailResponseRule struct {
	*rules.BaseRule
	// leaks maps a project function name to whether each of its parameters
	// can reach the response.
	leaks map[string][]bool
	// fixedTexts maps a project function name to whether every error it
	// returns is a fixed text; filled when allowFixedTexts is set.
	fixedTexts      map[string]bool
	allowFixedTexts bool
	// statusCall reports a call answering with the rule's status class.
	statusCall func(call *ast.CallExpr) bool
	message    string
	suggestion string
	pattern    string
}

// NewErrorDetailIn5xxResponseRule creates the rule for server errors.
func NewErrorDetailIn5xxResponseRule() *ErrorDetailResponseRule {
	return &ErrorDetailResponseRule{
		BaseRule: rules.NewBaseRule(
			"error-detail-in-5xx-response",
			"security",
			"Detects an internal error's text (err.Error(), %v of err) sent to the client in a 5xx response",
			core.SeverityMedium,
		),
		statusCall: func(call *ast.CallExpr) bool {
			return statusCall(call, serverErrorCallee, func(code int) bool { return code >= 500 && code <= 599 }, serverErrorStatus)
		},
		message:    "5xx response carries the internal error's text — the client gets driver messages, paths and upstream details it cannot act on",
		suggestion: "Log the error with the request's trace id and send a fixed message and code",
		pattern:    "error_detail_5xx",
	}
}

// NewErrorDetailInAuthFailureResponseRule creates the rule for 401 and 403.
func NewErrorDetailInAuthFailureResponseRule() *ErrorDetailResponseRule {
	return &ErrorDetailResponseRule{
		BaseRule: rules.NewBaseRule(
			"error-detail-in-auth-failure-response",
			"security",
			"Detects the text of the error that rejected a request (err.Error(), %v of err) sent to the caller in a 401 or 403 response",
			core.SeverityMedium,
		),
		statusCall: func(call *ast.CallExpr) bool {
			return statusCall(call, authFailureCallee, func(code int) bool { return code == 401 || code == 403 }, authFailureStatus)
		},
		message:         "401/403 response carries the text of the error that rejected the request — an unauthenticated caller learns the expected key, the claims and the identity provider's answer",
		suggestion:      "Log the error and answer with a fixed text such as Unauthorized",
		pattern:         "error_detail_auth_failure",
		allowFixedTexts: true,
	}
}

var (
	serverErrorStatus = map[string]bool{
		"StatusInternalServerError": true, "StatusNotImplemented": true, "StatusBadGateway": true,
		"StatusServiceUnavailable": true, "StatusGatewayTimeout": true,
	}
	serverErrorCallee = regexp.MustCompile(`(?:InternalServerError|InternalError|ServerError)`)
	authFailureStatus = map[string]bool{"StatusUnauthorized": true, "StatusForbidden": true}
	authFailureCallee = regexp.MustCompile(`(?:Unauthori[sz]ed|Forbidden)`)
	errorValueName    = regexp.MustCompile(`^(?:err|e|[a-z]\w*Err|\w*Error)$`)
)

// AnalyzeFile reports responses of the rule's status class that carry an
// error's text.
func (r *ErrorDetailResponseRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		origins := errorOrigins(fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !writesResponse(call) || !r.statusCall(call) {
				return true
			}
			leaks, known := r.leaks[callName(call)]
			for i, arg := range call.Args {
				if known && (i >= len(leaks) || !leaks[i]) {
					continue
				}
				if carriesErrorText(arg) && !r.fixedText(arg, origins) {
					lr.report(arg, r.message, r.suggestion, r.pattern)
					break
				}
			}
			return true
		})
	}
	return lr.violations
}

// errorOrigin is an assignment of a call's result to an error variable.
type errorOrigin struct {
	pos    token.Pos
	name   string
	callee string
}

// errorOrigins returns the assignments of call results in a body, in order.
func errorOrigins(body *ast.BlockStmt) []errorOrigin {
	var origins []errorOrigin
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok {
				origins = append(origins, errorOrigin{pos: assign.Pos(), name: ident.Name, callee: callName(call)})
			}
		}
		return true
	})
	return origins
}

// fixedText reports an argument whose error values all come from project
// functions that return only fixed texts.
func (r *ErrorDetailResponseRule) fixedText(arg ast.Expr, origins []errorOrigin) bool {
	if !r.allowFixedTexts {
		return false
	}
	names := errorTextValues(arg)
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		callee := ""
		for _, origin := range origins {
			if origin.name == name && origin.pos < arg.Pos() {
				callee = origin.callee
			}
		}
		if callee == "" || !r.fixedTexts[callee] {
			return false
		}
	}
	return true
}

// errorTextValues returns the names of the error values whose text the
// argument carries: x in x.Error(), and the error arguments of fmt.Sprint*.
func errorTextValues(arg ast.Expr) []string {
	var names []string
	ast.Inspect(arg, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" && len(call.Args) == 0 {
			if ident, ok := sel.X.(*ast.Ident); ok && errorValueName.MatchString(ident.Name) {
				names = append(names, ident.Name)
			}
		}
		if pkg, ok := callPackage(call); ok && pkg == "fmt" && strings.HasPrefix(callName(call), "Sprint") && len(call.Args) > 0 {
			for _, a := range call.Args[1:] {
				if ident, ok := a.(*ast.Ident); ok && errorValueName.MatchString(ident.Name) {
					names = append(names, ident.Name)
				}
			}
		}
		return true
	})
	return names
}

// returnsOnlyFixedTexts reports a function returning an error whose every
// return gives nil, a sentinel variable, errors.New or a fmt.Errorf that
// wraps no other error.
func returnsOnlyFixedTexts(fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil || len(results.List) == 0 {
		return false
	}
	if ident, ok := results.List[len(results.List)-1].Type.(*ast.Ident); !ok || ident.Name != "error" {
		return false
	}
	fixed := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return fixed
		}
		fixed = fixed && fixedErrorValue(ret.Results[len(ret.Results)-1])
		return fixed
	})
	return fixed
}

func fixedErrorValue(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		// nil, or a sentinel: errNotFound, ErrDenied; err itself is
		// whatever a call returned.
		return e.Name == "nil" || (!errorValueName.MatchString(e.Name) && strings.HasPrefix(strings.ToLower(e.Name), "err"))
	case *ast.CallExpr:
		pkg, ok := callPackage(e)
		if !ok || len(e.Args) == 0 {
			return false
		}
		switch {
		case pkg == "errors" && callName(e) == "New":
			return true
		case pkg == "fmt" && callName(e) == "Errorf":
			if strings.Contains(stringLiteral(e.Args[0]), "%w") {
				return false
			}
			for _, a := range e.Args[1:] {
				if ident, ok := a.(*ast.Ident); ok && errorValueName.MatchString(ident.Name) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// UseProjectFiles indexes which parameters of the project's functions can
// reach a response. A helper passing a parameter on to another helper leaks
// it if that one does, so the index is recomputed until it stops changing.
func (r *ErrorDetailResponseRule) UseProjectFiles(files []*core.FileContext) {
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
	if r.allowFixedTexts {
		r.fixedTexts = fixedTextFunctions(files)
	}
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

// fixedTextFunctions indexes the project's functions by name: true when every
// function of that name returns only fixed texts.
func fixedTextFunctions(files []*core.FileContext) map[string]bool {
	fixed := make(map[string]bool)
	for _, ctx := range files {
		if !ctx.HasGoAST() || ctx.IsTestFile() {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			only := returnsOnlyFixedTexts(fn)
			if prev, seen := fixed[fn.Name.Name]; seen {
				only = only && prev
			}
			fixed[fn.Name.Name] = only
		}
	}
	return fixed
}

// ResetState drops the indexes of the previous root.
func (r *ErrorDetailResponseRule) ResetState() { r.leaks, r.fixedTexts = nil, nil }

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
func (r *ErrorDetailResponseRule) parameterLeaks(body *ast.BlockStmt, name, writer string) bool {
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

// statusCall reports a call named for the status class (callee), or with a
// status argument of it: a net/http constant in statuses or a literal code
// inClass accepts.
func statusCall(call *ast.CallExpr, callee *regexp.Regexp, inClass func(code int) bool, statuses map[string]bool) bool {
	if callee.MatchString(callName(call)) {
		return true
	}
	for _, arg := range call.Args {
		switch a := arg.(type) {
		case *ast.SelectorExpr:
			if statuses[a.Sel.Name] {
				return true
			}
		case *ast.BasicLit:
			if a.Kind == token.INT {
				if code, err := strconv.Atoi(a.Value); err == nil && inClass(code) {
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
