package patterns

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/packages"
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
// Признаков нужно три сразу:
//  1. функция принимает http.ResponseWriter и пишет код из диапазона 5xx — это ответ об отказе;
//  2. среди параметров нет ни *http.Request, ни context.Context — отмену ей взять негде;
//  3. её зовут из нескольких мест — то есть это общая точка отказа, а не разовый ответ.
//
// Третий признак и делает правило точным: единственный вызов чинится на месте, а общий
// помощник переписывают один раз и лечат им весь слой. Правило молчит, если пакет уже
// знает про context.Canceled: значит отмену там разбирают, и где именно — решать автору.
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
			"Detects a shared 5xx responder that takes neither the request nor a context — a client that walked away is answered as a server failure",
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

// blindResponder is a 5xx helper that cannot see the request.
type blindResponder struct {
	obj      types.Object
	decl     *ast.FuncDecl
	pkgPath  string
	callers  map[string]bool
	statuses map[int64]bool
}

// AnalyzeGoProject collects blind responders and the functions that call them.
func (r *ServerErrorHidesClientCancelRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("server error hides client cancel: nil Go project context")
	}

	responders := map[types.Object]*blindResponder{}
	cancelAware := map[string]bool{}

	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		pkg := pkgCtx.Package
		for _, file := range pkg.Syntax {
			if isGoTestFile(ctx, file) {
				continue
			}
			if referencesCancellation(pkg.TypesInfo, file) {
				cancelAware[pkg.PkgPath] = true
			}
			collectBlindResponders(pkg, file, responders)
		}
	}
	// Второй проход нужен только когда есть за чем считать вызовы.
	if len(responders) > 0 {
		for _, pkgCtx := range ctx.Packages {
			if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
				continue
			}
			pkg := pkgCtx.Package
			for _, file := range pkg.Syntax {
				if isGoTestFile(ctx, file) {
					continue
				}
				collectResponderCalls(pkg, file, responders)
			}
		}
	}

	var violations []*core.Violation
	for _, resp := range responders {
		if cancelAware[resp.pkgPath] || len(resp.callers) < r.minCallSites {
			continue
		}
		violations = append(violations, r.violationFor(ctx, resp))
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

// collectBlindResponders records functions that answer 5xx without access to the request.
func collectBlindResponders(pkg *packages.Package, file *ast.File, out map[types.Object]*blindResponder) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		writer, blind := responderParams(pkg.TypesInfo, fn)
		if !writer || !blind {
			continue
		}
		statuses := serverErrorStatuses(pkg.TypesInfo, fn.Body)
		if len(statuses) == 0 {
			continue
		}
		obj := pkg.TypesInfo.Defs[fn.Name]
		if obj == nil {
			continue
		}
		out[obj] = &blindResponder{
			obj:      obj,
			decl:     fn,
			pkgPath:  pkg.PkgPath,
			callers:  map[string]bool{},
			statuses: statuses,
		}
	}
}

// responderParams reports whether the function takes an http.ResponseWriter and
// whether it is blind: no *http.Request and no context.Context among the parameters.
func responderParams(info *types.Info, fn *ast.FuncDecl) (writer, blind bool) {
	blind = true
	if fn.Type.Params == nil {
		return false, false
	}
	for _, field := range fn.Type.Params.List {
		tv, ok := info.Types[field.Type]
		if !ok || tv.Type == nil {
			continue
		}
		switch types.TypeString(tv.Type, nil) {
		case "net/http.ResponseWriter":
			writer = true
		case "*net/http.Request", "context.Context":
			blind = false
		}
	}
	return writer, blind
}

// serverErrorStatuses collects the 5xx codes the body writes. A status is taken from
// any call argument that is a constant in the 5xx range: that covers http.Error,
// w.WriteHeader and every project's own JSON responder alike, without knowing its name.
func serverErrorStatuses(info *types.Info, body *ast.BlockStmt) map[int64]bool {
	found := map[int64]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			code, ok := constantInt(info, arg)
			if ok && code >= 500 && code <= 599 {
				found[code] = true
			}
		}
		return true
	})
	return found
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
func collectResponderCalls(pkg *packages.Package, file *ast.File, responders map[types.Object]*blindResponder) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		caller := pkg.PkgPath + "." + fn.Name.Name
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			obj := calleeObject(pkg.TypesInfo, call.Fun)
			if obj == nil {
				return true
			}
			resp, tracked := responders[obj]
			// Рекурсивный вызов вызовом со стороны не считается.
			if tracked && obj != pkg.TypesInfo.Defs[fn.Name] {
				resp.callers[caller] = true
			}
			return true
		})
	}
}

// calleeObject resolves the callee of a call expression to its declared object.
func calleeObject(info *types.Info, fun ast.Expr) types.Object {
	switch callee := fun.(type) {
	case *ast.Ident:
		return info.Uses[callee]
	case *ast.SelectorExpr:
		return info.Uses[callee.Sel]
	}
	return nil
}

// violationFor renders the finding at the responder declaration.
func (r *ServerErrorHidesClientCancelRule) violationFor(
	ctx *core.GoProjectContext,
	resp *blindResponder,
) *core.Violation {
	pos := ctx.FileSet.Position(resp.decl.Pos())
	rel := pos.Filename
	if ctx.ProjectRoot != "" {
		if relPath, err := filepath.Rel(ctx.ProjectRoot, pos.Filename); err == nil {
			rel = relPath
		}
	}
	codes := make([]int, 0, len(resp.statuses))
	for code := range resp.statuses {
		codes = append(codes, int(code))
	}
	sort.Ints(codes)
	codeText := make([]string, 0, len(codes))
	for _, code := range codes {
		codeText = append(codeText, strconv.Itoa(code))
	}

	v := r.CreateViolation(rel, pos.Line,
		resp.decl.Name.Name+"() answers "+strings.Join(codeText, "/")+" for "+
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
