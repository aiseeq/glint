package patterns

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewServerErrorHidesClientCancelRule())
}

// ServerErrorHidesClientCancelRule detects the shared helper that answers 5xx and
// structurally cannot tell a server failure from a client that walked away.
//
// Клиент закрывает вкладку — вместе с соединением снимается контекст запроса, запрос
// к базе отменяется, и обработчик получает ошибку отмены. Она неотличима от настоящего
// сбоя ровно в одном случае: когда отвечает общий помощник, которому не передали ни
// запрос, ни контекст. Спросить `r.Context().Err()` ему нечего, поэтому уход со
// страницы он объявляет отказом сервера: пятисотка в ответ, строка уровня ERROR в лог
// и запись в мониторинге. На живом трафике таких записей набегает больше, чем
// настоящих сбоев, и за ними перестают следить.
//
// Признаков нужно четыре сразу:
//  1. функция принимает http.ResponseWriter и пишет статус 5xx — через WriteHeader, http.Error
//     или помощник, чей int-параметр доходит до них; 5xx, который она пишет только при сбое
//     собственного json.Marshal/Encode, — это её сбой, а не ответ об ошибке вызывающего;
//  2. среди параметров есть error — ошибка, которую она классифицирует;
//  3. среди параметров нет ни *http.Request, ни context.Context — отмену ей взять негде;
//  4. её зовут из нескольких мест — то есть это общая точка отказа, а не разовый ответ.
//
// Четвёртый признак и делает правило точным: единственный вызов чинится на месте, а общий
// помощник переписывают один раз и лечат им весь слой. Правило молчит, если пакет уже
// знает про context.Canceled: значит отмену там разбирают, и где именно — решать автору.
//
// Вторая форма — помощник, которому запрос передали, а он в контекст не смотрит: статус
// приходит int-параметром и доходит до WriteHeader, пятисотку передают из нескольких
// функций, а ни сам помощник, ни то, что он зовёт, не спрашивает ctx.Err(), ctx.Done()
// и context.Canceled. Знание пакета об отмене здесь не оправдание: разбор, который ловит
// только обёрнутый %w context.Canceled, пропускает отмену, потерянную по дороге, а запрос
// под рукой у помощника. Вызов из функции, которая сама разбирает отмену, не считается.
type ServerErrorHidesClientCancelRule struct {
	*rules.BaseRule
	minCallSites int
}

// NewServerErrorHidesClientCancelRule creates the rule.
func NewServerErrorHidesClientCancelRule() *ServerErrorHidesClientCancelRule {
	return &ServerErrorHidesClientCancelRule{
		BaseRule: rules.NewBaseRule(
			"server-error-hides-client-cancel",
			"patterns",
			"Detects a shared 5xx responder that takes neither the request nor a context, or takes the request and never looks at its context — a client that walked away is answered as a server failure",
			core.SeverityMedium,
		),
		minCallSites: 3,
	}
}

// Configure allows setting rule options.
func (r *ServerErrorHidesClientCancelRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.minCallSites = r.GetIntSetting("min_call_sites", 3)
	return nil
}

// RequiresSSA reports that typed packages are enough — no SSA program needed.
func (r *ServerErrorHidesClientCancelRule) RequiresSSA() bool { return false }

// AnalyzeFile does nothing: the rule needs the whole project to count call sites.
func (r *ServerErrorHidesClientCancelRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// declaredFunc is one function declaration of the project with the type
// information of its package.
type declaredFunc struct {
	decl *ast.FuncDecl
	info *types.Info
}

// statusForward is a call inside a function that hands one of its int
// parameters to a status argument of the callee.
type statusForward struct {
	call       *ast.CallExpr
	argIndex   int
	paramIndex int
}

// blindResponder is a 5xx helper that cannot see the request.
type blindResponder struct {
	decl     *ast.FuncDecl
	callers  map[string]bool
	statuses map[int64]bool
}

// AnalyzeGoProject collects blind responders and the functions that call them.
func (r *ServerErrorHidesClientCancelRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("server error hides client cancel: nil Go project context")
	}

	funcs := map[types.Object]*declaredFunc{}
	cancelAware := map[*types.Info]bool{}
	_, err := rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if referencesCancellation(info, fileCtx.GoAST) {
			cancelAware[info] = true
		}
		for _, decl := range fileCtx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if obj := info.Defs[fn.Name]; obj != nil {
				funcs[obj] = &declaredFunc{decl: fn, info: info}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	statusParams := statusParameters(funcs)
	responders := map[types.Object]*blindResponder{}
	for obj, fn := range funcs {
		if cancelAware[fn.info] || !takesWriterAndErrorBlind(fn.info, fn.decl) {
			continue
		}
		statuses := serverErrorStatuses(fn.info, fn.decl.Body, statusParams)
		if len(statuses) == 0 {
			continue
		}
		responders[obj] = &blindResponder{decl: fn.decl, callers: map[string]bool{}, statuses: statuses}
	}
	// Вызовы стоит считать, только когда есть чьи.
	for obj, fn := range funcs {
		if len(responders) == 0 {
			break
		}
		collectResponderCalls(obj, fn, responders)
	}

	sighted := sightedResponders(funcs, statusParams, responders)

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range fileCtx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if resp, tracked := sighted[info.Defs[fn.Name]]; tracked && len(resp.callers) >= r.minCallSites {
				violations = append(violations, r.sightedViolationFor(fileCtx, resp))
				continue
			}
			resp, tracked := responders[info.Defs[fn.Name]]
			if !tracked || len(resp.callers) < r.minCallSites {
				continue
			}
			violations = append(violations, r.violationFor(fileCtx, resp))
		}
		return violations
	})
}

// sightedResponders returns the responders that take the request or a context
// and a status parameter, never consult the cancellation, and are handed a 5xx
// constant by callers that do not consult it either.
func sightedResponders(funcs map[types.Object]*declaredFunc, statusParams map[types.Object]map[int]bool,
	blind map[types.Object]*blindResponder) map[types.Object]*blindResponder {
	consults := map[types.Object]bool{}
	visiting := map[types.Object]bool{}
	candidates := map[types.Object]*blindResponder{}
	for obj, fn := range funcs {
		if _, isBlind := blind[obj]; isBlind || len(statusParams[obj]) == 0 || !takesWriterAndRequest(fn.info, fn.decl) {
			continue
		}
		if consultsCancellation(obj, funcs, consults, visiting) {
			continue
		}
		candidates[obj] = &blindResponder{decl: fn.decl, callers: map[string]bool{}, statuses: map[int64]bool{}}
	}
	if len(candidates) == 0 {
		return candidates
	}
	for caller, fn := range funcs {
		if consultsCancellation(caller, funcs, consults, visiting) {
			continue
		}
		callerName := caller.Pkg().Path() + "." + fn.decl.Name.Name
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := typeutil.Callee(fn.info, call).(*types.Func)
			if !ok || callee.Origin() == caller {
				return true
			}
			resp, tracked := candidates[callee.Origin()]
			if !tracked {
				return true
			}
			for index := range statusParams[callee.Origin()] {
				if index >= len(call.Args) {
					continue
				}
				if code, ok := constantInt(fn.info, call.Args[index]); ok && code >= 500 && code <= 599 {
					resp.callers[callerName] = true
					resp.statuses[code] = true
				}
			}
			return true
		})
	}
	return candidates
}

// takesWriterAndRequest reports whether the function takes an
// http.ResponseWriter and the request or a context.
func takesWriterAndRequest(info *types.Info, fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}
	writer, request := false, false
	for _, field := range fn.Type.Params.List {
		t := info.TypeOf(field.Type)
		switch {
		case isNamedType(t, "net/http", "ResponseWriter"):
			writer = true
		case isPointerToNamedType(t, "net/http", "Request"), isNamedType(t, "context", "Context"):
			request = true
		}
	}
	return writer && request
}

// consultsCancellation reports whether the function, or a project function it
// calls, asks a context whether it ended (Err, Done) or names
// context.Canceled or context.DeadlineExceeded.
func consultsCancellation(obj types.Object, funcs map[types.Object]*declaredFunc, memo, visiting map[types.Object]bool) bool {
	if done, ok := memo[obj]; ok {
		return done
	}
	fn, ok := funcs[obj]
	if !ok || visiting[obj] {
		return false
	}
	visiting[obj] = true
	defer delete(visiting, obj)
	found := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if node.Sel.Name != "Canceled" && node.Sel.Name != "DeadlineExceeded" {
				return true
			}
			if used := fn.info.Uses[node.Sel]; used != nil && used.Pkg() != nil && used.Pkg().Path() == "context" {
				found = true
			}
		case *ast.CallExpr:
			callee, ok := typeutil.Callee(fn.info, node).(*types.Func)
			if !ok {
				return true
			}
			if sig, isFunc := callee.Type().(*types.Signature); isFunc && sig.Recv() != nil &&
				(callee.Name() == "Err" || callee.Name() == "Done") && isNamedType(sig.Recv().Type(), "context", "Context") {
				found = true
				return false
			}
			found = consultsCancellation(callee.Origin(), funcs, memo, visiting)
		}
		return !found
	})
	memo[obj] = found
	return found
}

// takesWriterAndErrorBlind reports whether the function takes an
// http.ResponseWriter and an error, and is blind: no *http.Request and no
// context.Context among the parameters. Without an error it has no failure to
// misclassify — it answers what it was told to.
func takesWriterAndErrorBlind(info *types.Info, fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}
	writer, withError := false, false
	for _, field := range fn.Type.Params.List {
		t := info.TypeOf(field.Type)
		switch {
		case isNamedType(t, "net/http", "ResponseWriter"):
			writer = true
		case isPointerToNamedType(t, "net/http", "Request"), isNamedType(t, "context", "Context"):
			return false
		case isErrorType(t):
			withError = true
		}
	}
	return writer && withError
}

// statusArgIndexes returns the indexes of the arguments that carries the HTTP
// status in call: w.WriteHeader(code), http.Error(w, msg, code), or a project
// function whose parameter reaches one of them.
func statusArgIndexes(info *types.Info, call *ast.CallExpr, statusParams map[types.Object]map[int]bool) []int {
	callee := typeutil.Callee(info, call)
	fn, ok := callee.(*types.Func)
	if !ok {
		return nil
	}
	if fn.Pkg() != nil && fn.Pkg().Path() == "net/http" && fn.Name() == "Error" && len(call.Args) == 3 {
		return []int{2}
	}
	if sig, isFunc := fn.Type().(*types.Signature); isFunc && sig.Recv() != nil &&
		fn.Name() == "WriteHeader" && len(call.Args) == 1 && isIntType(info.TypeOf(call.Args[0])) {
		// http.ResponseWriter.WriteHeader, or a wrapper's own WriteHeader(code int).
		return []int{0}
	}
	var indexes []int
	for index := range statusParams[fn.Origin()] {
		if index < len(call.Args) {
			indexes = append(indexes, index)
		}
	}
	sort.Ints(indexes)
	return indexes
}

// statusParameters returns, for every project function, the indexes of the
// int parameters its body passes on as an HTTP status — directly to
// WriteHeader/http.Error or through another such function.
func statusParameters(funcs map[types.Object]*declaredFunc) map[types.Object]map[int]bool {
	candidates := map[types.Object][]statusForward{}
	for obj, fn := range funcs {
		params := intParamIndexes(fn.info, fn.decl)
		if len(params) == 0 {
			continue
		}
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for argIndex, arg := range call.Args {
				variable := variableOf(fn.info, ast.Unparen(arg))
				if paramIndex, isParam := params[variable]; isParam {
					candidates[obj] = append(candidates[obj], statusForward{call: call, argIndex: argIndex, paramIndex: paramIndex})
				}
			}
			return true
		})
	}

	statusParams := map[types.Object]map[int]bool{}
	for changed := true; changed; {
		changed = false
		for obj, forwards := range candidates {
			info := funcs[obj].info
			for _, forward := range forwards {
				if statusParams[obj][forward.paramIndex] {
					continue
				}
				for _, index := range statusArgIndexes(info, forward.call, statusParams) {
					if index != forward.argIndex {
						continue
					}
					if statusParams[obj] == nil {
						statusParams[obj] = map[int]bool{}
					}
					statusParams[obj][forward.paramIndex] = true
					changed = true
				}
			}
		}
	}
	return statusParams
}

// intParamIndexes maps the int parameters of the function to their positions.
func intParamIndexes(info *types.Info, fn *ast.FuncDecl) map[types.Object]int {
	params := map[types.Object]int{}
	if fn.Type.Params == nil {
		return params
	}
	position := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			position++
			continue
		}
		for _, name := range field.Names {
			if obj := info.Defs[name]; obj != nil && isIntType(obj.Type()) {
				params[obj] = position
			}
			position++
		}
	}
	return params
}

// isIntType reports whether t is an integer type.
func isIntType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsInteger != 0
}

// serverErrorStatuses collects the 5xx codes the body writes as a status. A
// 5xx the body writes only when its own JSON encoding failed is the writer's
// failure, not an answer about the caller's error, and is left out.
func serverErrorStatuses(info *types.Info, body *ast.BlockStmt, statusParams map[types.Object]map[int]bool) map[int64]bool {
	encodeErrors := jsonEncodeErrors(info, body)
	found := map[int64]bool{}
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, index := range statusArgIndexes(info, call, statusParams) {
			code, ok := constantInt(info, call.Args[index])
			if !ok || code < 500 || code > 599 || guardedByEncodeFailure(info, stack, encodeErrors) {
				continue
			}
			found[code] = true
		}
		return true
	})
	return found
}

// jsonEncodeErrors returns the error variables assigned from json.Marshal,
// json.MarshalIndent or (*json.Encoder).Encode in the body.
func jsonEncodeErrors(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	errs := map[types.Object]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := typeutil.Callee(info, call).(*types.Func)
		if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "encoding/json" {
			return true
		}
		if name := fn.Name(); name != "Marshal" && name != "MarshalIndent" && name != "Encode" {
			return true
		}
		for _, lhs := range assign.Lhs {
			if variable := variableOf(info, lhs); variable != nil && isErrorType(variable.Type()) {
				errs[variable] = true
			}
		}
		return true
	})
	return errs
}

// guardedByEncodeFailure reports whether the innermost node of stack sits in
// the body of an `if err != nil` on a JSON encoding error.
func guardedByEncodeFailure(info *types.Info, stack []ast.Node, encodeErrors map[types.Object]bool) bool {
	if len(encodeErrors) == 0 {
		return false
	}
	for i := len(stack) - 2; i >= 0; i-- {
		branch, ok := stack[i].(*ast.IfStmt)
		if !ok || stack[i+1] != branch.Body {
			continue
		}
		cond, ok := branch.Cond.(*ast.BinaryExpr)
		if ok && cond.Op == token.NEQ && isNilIdent(cond.Y) && encodeErrors[variableOf(info, cond.X)] {
			return true
		}
	}
	return false
}

// constantInt resolves an expression to its integer constant value, if it has one.
func constantInt(info *types.Info, expr ast.Expr) (int64, bool) {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil {
		return 0, false
	}
	value := constant.ToInt(tv.Value)
	if value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(value)
}

// referencesCancellation reports whether the file mentions context.Canceled — the package
// already distinguishes a cancelled client somewhere, and where exactly is the author's call.
func referencesCancellation(info *types.Info, file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Canceled" {
			return true
		}
		if obj := info.Uses[sel.Sel]; obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "context" {
			found = true
		}
		return true
	})
	return found
}

// collectResponderCalls records the distinct functions that call each responder.
func collectResponderCalls(caller types.Object, fn *declaredFunc, responders map[types.Object]*blindResponder) {
	callerName := caller.Pkg().Path() + "." + fn.decl.Name.Name
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee, ok := typeutil.Callee(fn.info, call).(*types.Func)
		if !ok {
			return true
		}
		resp, tracked := responders[callee.Origin()]
		// Рекурсивный вызов вызовом со стороны не считается.
		if tracked && callee.Origin() != caller {
			resp.callers[callerName] = true
		}
		return true
	})
}

// sightedViolationFor renders the finding at a responder that has the request
// and does not look at its context.
func (r *ServerErrorHidesClientCancelRule) sightedViolationFor(ctx *core.FileContext, resp *blindResponder) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, ctx.LineFor(resp.decl),
		resp.decl.Name.Name+"() answers "+statusText(resp.statuses)+" for "+
			strconv.Itoa(len(resp.callers))+" call sites and takes the request, but never looks at its context — "+
			"a client that closed the connection is reported as a server failure")
	v.WithSuggestion("Before answering 5xx, check the request's own context " +
		"(errors.Is(r.Context().Err(), context.Canceled)): log a cancelled request below error level and reply 499; " +
		"a cancellation lost on the way (an error rebuilt from text) is still visible there")
	v.WithContext("pattern", "server_error_hides_client_cancel")
	v.WithContext("responder", resp.decl.Name.Name)
	v.WithContext("call_sites", strconv.Itoa(len(resp.callers)))
	return v
}

// statusText lists the status codes in order: 500/503.
func statusText(statuses map[int64]bool) string {
	codes := make([]int, 0, len(statuses))
	for code := range statuses {
		codes = append(codes, int(code))
	}
	sort.Ints(codes)
	codeText := make([]string, 0, len(codes))
	for _, code := range codes {
		codeText = append(codeText, strconv.Itoa(code))
	}
	return strings.Join(codeText, "/")
}

// violationFor renders the finding at the responder declaration.
func (r *ServerErrorHidesClientCancelRule) violationFor(ctx *core.FileContext, resp *blindResponder) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, ctx.LineFor(resp.decl),
		resp.decl.Name.Name+"() answers "+statusText(resp.statuses)+" for "+
			strconv.Itoa(len(resp.callers))+" call sites but takes neither the request nor a context — "+
			"a client that closed the connection is reported as a server failure")
	v.WithSuggestion("Pass *http.Request to the responder and answer a cancelled request separately " +
		"(errors.Is(r.Context().Err(), context.Canceled)): log it below error level and reply 499, " +
		"so that leaving the page stops looking like an outage")
	v.WithContext("pattern", "server_error_hides_client_cancel")
	v.WithContext("responder", resp.decl.Name.Name)
	v.WithContext("call_sites", strconv.Itoa(len(resp.callers)))
	return v
}
