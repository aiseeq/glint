package patterns

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewNotFoundAnsweredAsServerErrorRule())
}

// NotFoundAnsweredAsServerErrorRule detects an HTTP handler that answers every
// error of a call with a 5xx while the call can return the project's
// not-found sentinel:
//
//	report, err := r.service.Report(req.Context(), id) // wraps ErrRecordNotFound for an unknown id
//	if err != nil {
//	    sendInternalServerError(w, "report failed")
//	    return
//	}
//
// A client's unknown id is answered as a server failure: the client cannot
// tell its own mistake from an outage, and the server's error log and alerts
// fill with requests nothing on the server can fix.
//
// What the call can return is followed through the project's code as
// errors-is-target-unreachable follows it. The branch counts as answering
// every error when it sends a 5xx (a responder named for a server error, or a
// 5xx status) and neither compares the error nor hands it to a function that
// does (a mapper with errors.Is inside).
type NotFoundAnsweredAsServerErrorRule struct {
	*rules.BaseRule
}

// NewNotFoundAnsweredAsServerErrorRule creates the rule
func NewNotFoundAnsweredAsServerErrorRule() *NotFoundAnsweredAsServerErrorRule {
	return &NotFoundAnsweredAsServerErrorRule{BaseRule: rules.NewBaseRule(
		"not-found-answered-as-server-error",
		"patterns",
		"Detects an HTTP handler answering every error of a call with a 5xx while the call can return a not-found sentinel — a client's unknown id is reported as a server failure",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: what a call returns is found in other files.
func (r *NotFoundAnsweredAsServerErrorRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NotFoundAnsweredAsServerErrorRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the 5xx answers to errors that can be a not-found.
func (r *NotFoundAnsweredAsServerErrorRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("not found answered as server error: nil Go project context")
	}
	flow := newErrorFlow(ctx)
	var violations []*core.Violation
	for _, fn := range flow.order {
		request := handlerRequestParam(fn)
		if request == nil {
			continue
		}
		fromRequest := requestValues(flow, fn, request)
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false
			}
			check, ok := n.(*ast.IfStmt)
			if !ok || len(check.Body.List) == 0 {
				return true
			}
			errIdent := errNotNilIdent(fn.info, check.Cond)
			if errIdent == nil {
				return true
			}
			answer := serverErrorAnswer(fn.info, check.Body)
			if answer == nil || comparesError(check.Body) || r.mapsError(flow, fn, check.Body, errIdent) {
				return true
			}
			call := flow.originCall(fn, errIdent, check.Body.List[0])
			if call == nil || !takesRequestValue(flow, fn, call, request, fromRequest) {
				return true
			}
			sentinel := notFoundSentinel(flow.exprErrors(fn, errIdent, check.Body.List[0], 0))
			if sentinel == nil {
				return true
			}
			line := fn.file.LineFor(answer)
			if fn.file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(fn.file.RelPath, line, "Every error of this call is answered with a 5xx, and the call can return "+sentinel.Name()+
				" — a client's unknown id is reported as a server failure")
			v.WithCode(strings.TrimSpace(fn.file.GetLine(line)))
			v.WithSuggestion("Answer " + sentinel.Name() + " with 404 (errors.Is) before the generic 5xx, or pass the error to the package's not-found-aware responder")
			violations = append(violations, v)
			return true
		})
	}
	return violations, nil
}

// handlerRequestParam returns the *http.Request parameter of a function that
// also takes an http.ResponseWriter, nil for anything else.
func handlerRequestParam(fn typedFunc) *types.Var {
	obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
	if !ok {
		return nil
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok {
		return nil
	}
	writer := false
	var request *types.Var
	for i := range sig.Params().Len() {
		switch types.TypeString(sig.Params().At(i).Type(), nil) {
		case "net/http.ResponseWriter":
			writer = true
		case "*net/http.Request":
			request = sig.Params().At(i)
		}
	}
	if !writer {
		return nil
	}
	return request
}

// requestDataField is what an *http.Request carries from the client.
var requestDataField = map[string]bool{
	"URL": true, "Body": true, "Form": true, "PostForm": true, "MultipartForm": true, "Header": true,
	"PathValue": true, "FormValue": true, "PostFormValue": true, "FormFile": true, "Cookie": true, "Cookies": true,
	"ParseForm": true, "ParseMultipartForm": true, "MultipartReader": true,
}

// responderName is a library function handed the request only to answer it.
var responderName = regexp.MustCompile(`^(?:Send|send|Write|write|Respond|respond|Render|render|Log|log|Error|error)`)

// mentionsRequestData reports an expression reading what the client sent: a
// path, query, form or body read off the request, a library helper handed
// the request to read it (mux.Vars), a project helper that reads it, or a
// variable holding such a value. The request's context carries what
// middleware put there, not the client's data.
func mentionsRequestData(flow *errorFlow, fn typedFunc, expr ast.Node, request *types.Var, values map[types.Object]bool, depth int) bool {
	info := fn.info
	isRequest := func(e ast.Expr) bool {
		ident, ok := ast.Unparen(e).(*ast.Ident)
		return ok && info.Uses[ident] == request
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if isRequest(node.X) && requestDataField[node.Sel.Name] {
				found = true
			}
		case *ast.CallExpr:
			handed := false
			for _, arg := range node.Args {
				handed = handed || isRequest(arg)
			}
			if handed {
				found = depth < maxRequestHelperDepth && helperReadsRequest(flow, fn, node, request, depth+1)
			}
		case *ast.Ident:
			if obj := info.Uses[node]; obj != nil && values[obj] {
				found = true
			}
		}
		return !found
	})
	return found
}

// maxRequestHelperDepth bounds how deep helpers handed the request are read.
const maxRequestHelperDepth = 3

// helperReadsRequest reports a call handed the request that reads what the
// client sent: a project function reading it (queryUUID(w, req, "id")), or a
// library function (mux.Vars(req)). A responder (sendError(w, req, ...)) and
// a helper reading only the request's context (currentStaff(w, req)) do not.
func helperReadsRequest(flow *errorFlow, fn typedFunc, call *ast.CallExpr, request *types.Var, depth int) bool {
	callee, ok := typeutil.Callee(fn.info, call).(*types.Func)
	if !ok {
		return false
	}
	// A responder reads the request's path for its trace, not as input.
	if responderName.MatchString(callee.Name()) {
		return false
	}
	target, ok := flow.funcs[callee.Origin()]
	if !ok {
		return true
	}
	for i, arg := range call.Args {
		ident, ok := ast.Unparen(arg).(*ast.Ident)
		if !ok || fn.info.Uses[ident] != request {
			continue
		}
		param, ok := target.info.Defs[paramIdentAt(target.decl.Type, i)].(*types.Var)
		if ok && mentionsRequestData(flow, target, target.decl.Body, param, map[types.Object]bool{}, depth) {
			return true
		}
	}
	return false
}

// requestValues returns the variables of a handler holding what the client
// sent: a path or query value, a decoded body, and what is computed from them.
func requestValues(flow *errorFlow, fn typedFunc, request *types.Var) map[types.Object]bool {
	values := map[types.Object]bool{}
	for changed := true; changed; {
		changed = false
		mark := func(expr ast.Expr) {
			if ident, ok := ast.Unparen(expr).(*ast.Ident); ok {
				if obj := fn.info.ObjectOf(ident); obj != nil && !values[obj] {
					values[obj] = true
					changed = true
				}
			}
		}
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, rhs := range node.Rhs {
					if mentionsRequestData(flow, fn, rhs, request, values, 0) {
						for _, lhs := range node.Lhs {
							mark(lhs)
						}
					}
				}
			case *ast.CallExpr:
				// json.NewDecoder(req.Body).Decode(&body) fills body.
				if mentionsRequestData(flow, fn, node.Fun, request, values, 0) {
					for _, arg := range node.Args {
						if unary, ok := ast.Unparen(arg).(*ast.UnaryExpr); ok && unary.Op == token.AND {
							mark(unary.X)
						}
					}
				}
			}
			return true
		})
	}
	return values
}

// takesRequestValue reports a call handed what the client sent, other than
// a number.
func takesRequestValue(flow *errorFlow, fn typedFunc, call *ast.CallExpr, request *types.Var, values map[types.Object]bool) bool {
	written := writtenBefore(fn, call)
	for _, arg := range call.Args {
		// A number the client sent (a page size, a limit) names no record.
		if basic, ok := fn.info.TypeOf(arg).Underlying().(*types.Basic); ok && basic.Info()&(types.IsNumeric|types.IsBoolean) != 0 {
			continue
		}
		// The id of a record the handler has just written was given by the
		// server: a miss reading it back is the server's inconsistency.
		if root := rootIdent(arg); root != nil && written[fn.info.ObjectOf(root)] {
			continue
		}
		if mentionsRequestData(flow, fn, arg, request, values, 0) {
			return true
		}
	}
	return false
}

// writtenBefore returns the variables a handler hands to a write call
// (RecordEntry(ctx, entry), Create(&row)) before call.
func writtenBefore(fn typedFunc, call *ast.CallExpr) map[types.Object]bool {
	written := map[types.Object]bool{}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		write, ok := n.(*ast.CallExpr)
		if !ok || write.Pos() >= call.Pos() {
			return true
		}
		name := ""
		switch fun := write.Fun.(type) {
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		case *ast.Ident:
			name = fun.Name
		}
		if !helpers.IsWriteName(name) {
			return true
		}
		for _, arg := range write.Args {
			if unary, ok := ast.Unparen(arg).(*ast.UnaryExpr); ok && unary.Op == token.AND {
				arg = unary.X
			}
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok {
				if obj := fn.info.ObjectOf(ident); obj != nil {
					written[obj] = true
				}
			}
		}
		return true
	})
	return written
}

// errNotNilIdent returns err of a condition `err != nil`.
func errNotNilIdent(info *types.Info, cond ast.Expr) *ast.Ident {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ || !isNilIdent(ast.Unparen(bin.Y)) {
		return nil
	}
	ident, ok := ast.Unparen(bin.X).(*ast.Ident)
	if !ok || !implementsError(info.TypeOf(ident)) {
		return nil
	}
	return ident
}

// serverErrorResponder is the name of a function answering a server error.
var serverErrorResponder = regexp.MustCompile(`(?i)internal_?server_?error|internalerror|servererror|serviceunavailable|badgateway`)

// serverErrorAnswer returns the call of a branch that answers with a 5xx: a
// responder named for a server error, or a call handed a 5xx status.
func serverErrorAnswer(info *types.Info, body *ast.BlockStmt) *ast.CallExpr {
	var answer *ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if answer != nil {
			return false
		}
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if serverErrorResponder.MatchString(callName(call)) {
			answer = call
			return false
		}
		for _, arg := range call.Args {
			if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int {
				if status, exact := constant.Int64Val(tv.Value); exact && status >= 500 && status <= 599 && isStatusExpr(arg) {
					answer = call
					return false
				}
			}
		}
		return true
	})
	return answer
}

// isStatusExpr reports an http.Status* constant or a bare integer literal.
func isStatusExpr(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		return strings.HasPrefix(e.Sel.Name, "Status")
	case *ast.BasicLit:
		return e.Kind == token.INT
	}
	return false
}

// comparesError reports a branch that tells errors apart: errors.Is or
// errors.As, or a comparison with a sentinel.
func comparesError(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && isIdentNamed(sel.X, "errors") && (sel.Sel.Name == "Is" || sel.Sel.Name == "As") {
				found = true
			}
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				if ident, ok := ast.Unparen(node.Y).(*ast.Ident); ok && sentinelName(ident.Name) {
					found = true
				}
				if sel, ok := ast.Unparen(node.Y).(*ast.SelectorExpr); ok && sentinelName(sel.Sel.Name) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// mapsError reports a branch handing the error to a project function that
// tells it apart: a mapper choosing the status by errors.Is on the parameter
// the error arrives in. A logger that only checks the request's context does
// not count.
func (r *NotFoundAnsweredAsServerErrorRule) mapsError(flow *errorFlow, fn typedFunc, body *ast.BlockStmt, errIdent *ast.Ident) bool {
	errVar := fn.info.Uses[errIdent]
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		callee, ok := typeutil.Callee(fn.info, call).(*types.Func)
		if !ok {
			return true
		}
		target, ok := flow.funcs[callee.Origin()]
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && fn.info.Uses[ident] == errVar && comparesParam(target, i) {
				found = true
			}
		}
		return !found
	})
	return found
}

// comparesParam reports a function that tells its parameter at index apart:
// errors.Is or errors.As on it, or a comparison of it with a sentinel.
func comparesParam(fn typedFunc, index int) bool {
	obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || index >= sig.Params().Len() {
		return false
	}
	param := sig.Params().At(index)
	isParam := func(expr ast.Expr) bool {
		ident, ok := ast.Unparen(expr).(*ast.Ident)
		return ok && fn.info.Uses[ident] == param
	}
	found := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && isIdentNamed(sel.X, "errors") && (sel.Sel.Name == "Is" || sel.Sel.Name == "As") &&
				len(node.Args) > 0 && isParam(node.Args[0]) {
				found = true
			}
		case *ast.BinaryExpr:
			if (node.Op == token.EQL || node.Op == token.NEQ) && isParam(node.X) && !isNilIdent(ast.Unparen(node.Y)) {
				found = true
			}
		case *ast.SwitchStmt:
			if node.Tag != nil && isParam(node.Tag) {
				found = true
			}
		}
		return !found
	})
	return found
}

// notFoundSentinel returns the project's not-found sentinel among the errors
// a value may hold: ErrNotFound, ErrRecordNotFound. sql.ErrNoRows is left
// out: the model of the driver gives it to every single-row read, an
// aggregate or an INSERT ... RETURNING included, which always has its row.
func notFoundSentinel(set *errorSet) *types.Var {
	var found *types.Var
	for v := range set.sentinels {
		if isNoRows(v) || !strings.Contains(strings.ToLower(v.Name()), "notfound") {
			continue
		}
		if found == nil || v.Name() < found.Name() {
			found = v
		}
	}
	return found
}
