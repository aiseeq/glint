package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTestExternalServiceRule())
}

// TestExternalServiceRule detects tests that reach a live third-party service.
//
// A test exists to check our own code. Calling someone else's API from a test buys nothing —
// the vendor is not under our control and their behaviour is not our contract — and it costs
// three things: the suite starts failing on their outages and quotas, the vendor's rate limits
// turn into flaky red builds, and, worst, the test changes the outside world.
//
// Real case (ProjectA, 2026-07-30). Four tests talked to production APIs on every `make test-all`:
// two of them took real deposit requisites from the payment provider cryptoprov, two burned paid
// ExtVault Pro credits. Over one week the suite consumed 537 provider addresses. The failures
// looked like flaky parallelism — the provider starts answering 451 after roughly ten
// allocations per window, so the more workers, the more red.
//
// Two shapes are reported.
//
//   - outbound_client: a test calls into a package that both talks HTTP and carries a literal
//     third-party URL. Packages that merely hold configuration, or clients aimed at localhost,
//     do not qualify — the package must actually make outbound requests.
//
//   - credential_gate: a test guards itself with "skip unless the credential is present".
//     That is not a guard at all. Credentials live in .env, and test runners export it
//     (`set -a && source .env`), so the gate is open in exactly the environment where the test
//     runs. Both ProjectA vault tests carried `if os.Getenv("EXTVAULT_ACCESS_KEY") == "" { t.Skip() }`
//     and were documented as manual; they ran every single time. An opt-in must be a switch
//     nobody sets by accident, not a secret everybody has.
//
// A test that genuinely needs the live service stays possible: name its opt-in helper in the
// guard_functions setting, and calls guarded by it are not reported.
type TestExternalServiceRule struct {
	*rules.BaseRule

	guardFunctions  map[string]bool
	credentialName  *regexp.Regexp
	credentialField *regexp.Regexp
	localHost       *regexp.Regexp
	externalURL     *regexp.Regexp
}

// NewTestExternalServiceRule creates the rule
func NewTestExternalServiceRule() *TestExternalServiceRule {
	return &TestExternalServiceRule{
		BaseRule: rules.NewBaseRule(
			"test-external-service",
			"patterns",
			"Detects tests that call live third-party services, including gates that only check whether a credential is present",
			core.SeverityHigh,
		),
		guardFunctions: map[string]bool{},
		// Имя переменной окружения, которое означает секрет, а не переключатель.
		credentialName: regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?ID)`),
		// Имена объявлений строже имён переменных окружения: подстрока «key» есть и в
		// «monkey», а здесь ошибка выводит целый пакет во внешние.
		credentialField: regexp.MustCompile(`(?i)^[a-z0-9_]*(api_?key|access_?key|private_?key|public_?key|secret_?key|apisecret|api_secret|clientsecret|client_secret|signature)[a-z0-9_]*$`),
		// Локальные адреса и зарезервированные для примеров домены внешними не считаются.
		localHost:   regexp.MustCompile(`(?i)^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|[a-z0-9.-]+\.(local|localhost|test|invalid|internal)|example\.(com|org|net))(:\d+)?$`),
		externalURL: regexp.MustCompile(`^https?://([^/\s]+)`),
	}
}

// Configure accepts the list of opt-in helpers that legitimise a live call.
func (r *TestExternalServiceRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	raw, ok := settings["guard_functions"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("configure test-external-service: guard_functions must be a list, got %T", raw)
	}
	guards := make(map[string]bool, len(list))
	for i, item := range list {
		name, ok := item.(string)
		if !ok {
			return fmt.Errorf("configure test-external-service: guard_functions item %d must be a string, got %T", i, item)
		}
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("configure test-external-service: guard_functions item %d is empty", i)
		}
		guards[name] = true
	}
	r.guardFunctions = guards
	return nil
}

// AnalyzeFile is a no-op: deciding whether a called package talks to the outside world
// needs the whole project, not one file.
func (r *TestExternalServiceRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that plain typed packages are enough — no SSA program needed.
func (r *TestExternalServiceRule) RequiresSSA() bool { return false }

// AnalyzeGoProject marks packages that make outbound calls, then looks for tests reaching them.
func (r *TestExternalServiceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("test external service: nil Go project context")
	}

	outbound := r.outboundPackages(ctx)
	// Тест может лежать в самом вендорском пакете (package cryptoprov) и звать клиента
	// без квалификатора. Такой вызов по секции import не находится, поэтому запоминаем,
	// какому каталогу принадлежит внешний пакет.
	outboundDirs := outboundDirectories(ctx, outbound)
	// Тест-файлы разбираются по AST, а не по типам: пакеты грузятся без Tests:true,
	// поэтому у *_test.go типовой информации нет, и они висят только в ctx.Files.
	// Имя пакета в вызове разрешается по секции import самого файла — этого хватает
	// и заодно корректно обрабатывает алиасы импорта.
	var violations []*core.Violation
	for _, file := range ctx.Files {
		if file == nil || !file.IsTestFile() || file.GoAST == nil {
			continue
		}
		violations = append(violations, r.analyzeTestFile(file, outbound, outboundDirs)...)
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

// outboundDirectories maps a package directory to its outbound description, so an in-package
// test (same directory, unqualified calls) is checked as well.
func outboundDirectories(ctx *core.GoProjectContext, outbound map[string]outboundPackage) map[string]outboundPackage {
	dirs := make(map[string]outboundPackage, len(outbound))
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		entry, ok := outbound[pkg.Package.PkgPath]
		if !ok {
			continue
		}
		for _, file := range pkg.Files {
			if file == nil {
				continue
			}
			dirs[filepath.Dir(file.Path)] = entry
		}
	}
	return dirs
}

// outboundPackage records why a package counts as talking to a third party.
type outboundPackage struct {
	// evidence renders inside the message: either the vendor URL or the credential the
	// package signs its requests with.
	evidence string
	// entries are the exported functions that actually hand a test the wire: either they
	// reach an HTTP call themselves, or they return a client whose methods do. Everything
	// else the package exports — config readers, decoders, constructors of inert types —
	// is left alone, otherwise a test that never sends anything gets reported.
	entries map[string]bool
}

// outboundPackages finds packages that issue HTTP requests to somebody else's server.
//
// Issuing requests is never enough on its own: a helper that drives the project's own server
// does exactly that without leaving the machine. One of two additional signs is required.
//
//   - A third-party URL literal. Direct, but it only covers clients with the address baked in;
//     a configuration package holding a vendor URL it never dials is excluded separately.
//
//   - Credentials plus no local address anywhere in the package. A client whose base URL comes
//     from configuration carries no literal at all — ProjectA's cryptoprov client is exactly that —
//     but it still signs every request with an API key. Nobody signs requests to their own
//     localhost, so "authenticates and is not aimed at localhost" means the same thing.
func (r *TestExternalServiceRule) outboundPackages(ctx *core.GoProjectContext) map[string]outboundPackage {
	outbound := make(map[string]outboundPackage)

	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		var doesHTTP, hasLocalURL bool
		var url, credential string

		for _, file := range pkg.Files {
			if file == nil || file.GoAST == nil || file.IsTestFile() {
				continue
			}
			if !doesHTTP && fileIssuesHTTPRequest(file.GoAST, pkg.Package.TypesInfo) {
				doesHTTP = true
			}
			if url == "" {
				url = r.externalURLLiteral(file.GoAST)
			}
			if !hasLocalURL {
				hasLocalURL = r.hasLocalURLLiteral(file.GoAST)
			}
			if credential == "" {
				credential = r.credentialIdentifier(file.GoAST)
			}
		}

		var evidence string
		switch {
		case doesHTTP && url != "":
			evidence = "ходит в " + url
		case doesHTTP && credential != "" && !hasLocalURL:
			evidence = "подписывает запросы секретом (" + credential + "), адрес приходит из конфигурации"
		default:
			continue
		}

		entries := liveEntryPoints(pkg)
		if len(entries) == 0 {
			continue
		}
		outbound[pkg.Package.PkgPath] = outboundPackage{evidence: evidence, entries: entries}
	}
	return outbound
}

// httpRequestFuncs are the net/http entry points that put a request on the wire.
var httpRequestFuncs = map[string]bool{
	"Get": true, "Post": true, "Head": true, "PostForm": true,
	"NewRequest": true, "NewRequestWithContext": true,
}

const netHTTPPath = "net/http"

// fileIssuesHTTPRequest reports whether the file builds or sends an HTTP request.
//
// The check is resolved through types, not names. Matching a bare `.Do(` marked ProjectA's config
// package as an HTTP client because of `bootstrapOnce.Do(...)`, and every test touching config
// was reported.
func fileIssuesHTTPRequest(file *ast.File, info *types.Info) bool {
	return nodeIssuesHTTPRequest(file, info)
}

// nodeIssuesHTTPRequest is the same check narrowed to one subtree — a function body, when the
// question is which of the package's functions actually reach the wire.
func nodeIssuesHTTPRequest(root ast.Node, info *types.Info) bool {
	if info == nil || root == nil {
		return false
	}
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// http.Get / http.NewRequest и прочие пакетные функции.
			if ident, ok := sel.X.(*ast.Ident); ok {
				if pkgName, ok := info.Uses[ident].(*types.PkgName); ok {
					if pkgName.Imported().Path() == netHTTPPath && httpRequestFuncs[sel.Sel.Name] {
						found = true
						return false
					}
					return true
				}
			}
			// client.Do(req) — только если получатель действительно *http.Client.
			if sel.Sel.Name == "Do" && isNetHTTPClientMethod(info, sel) {
				found = true
				return false
			}
		case *ast.CompositeLit:
			if isNetHTTPType(info, node.Type, "Client") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// isNetHTTPClientMethod reports whether the selector resolves to a method on net/http.Client.
func isNetHTTPClientMethod(info *types.Info, sel *ast.SelectorExpr) bool {
	selection, ok := info.Selections[sel]
	if !ok {
		return false
	}
	recv := selection.Recv()
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := recv.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == netHTTPPath && named.Obj().Name() == "Client"
}

// isNetHTTPType reports whether the expression names the given net/http type.
func isNetHTTPType(info *types.Info, expr ast.Expr, name string) bool {
	if expr == nil {
		return false
	}
	typ := info.TypeOf(expr)
	if typ == nil {
		return false
	}
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == netHTTPPath && named.Obj().Name() == name
}

// externalURLLiteral returns the first third-party URL literal in the file, if any.
//
// Struct tags are skipped on purpose: `default:"https://api.vendor.com"` describes a value the
// package never dials itself, and counting tags marked ProjectA's whole config package as outbound.
func (r *TestExternalServiceRule) externalURLLiteral(file *ast.File) string {
	var found string
	ast.Inspect(file, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		if field, ok := n.(*ast.Field); ok {
			// Обходим поле без его тега.
			for _, name := range field.Names {
				ast.Inspect(name, func(ast.Node) bool { return true })
			}
			if field.Type != nil {
				ast.Inspect(field.Type, func(inner ast.Node) bool {
					if lit, ok := inner.(*ast.BasicLit); ok {
						if host := r.externalHost(lit); host != "" && found == "" {
							found = host
						}
					}
					return true
				})
			}
			return false
		}
		lit, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}
		if host := r.externalHost(lit); host != "" {
			found = host
		}
		return true
	})
	return found
}

// hasLocalURLLiteral reports whether the package names a local address anywhere.
//
// Such a package drives our own server, so credentials in it are our own JWTs rather than a
// vendor's API key, and it must not be treated as outbound.
func (r *TestExternalServiceRule) hasLocalURLLiteral(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind.String() != "STRING" {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		match := r.externalURL.FindStringSubmatch(value)
		if match != nil && r.localHost.MatchString(match[1]) {
			found = true
			return false
		}
		return true
	})
	return found
}

// credentialIdentifier returns the first vendor-credential name declared in the file.
//
// Only declarations count — struct fields, constants, variables and parameters. Matching every
// identifier would catch the local variable that merely passes a value along, and the point is
// that the package itself owns a secret.
func (r *TestExternalServiceRule) credentialIdentifier(file *ast.File) string {
	var found string
	record := func(names []*ast.Ident) {
		for _, name := range names {
			if found == "" && r.credentialField.MatchString(name.Name) {
				found = name.Name
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		switch node := n.(type) {
		case *ast.Field:
			record(node.Names)
		case *ast.ValueSpec:
			record(node.Names)
		}
		return true
	})
	return found
}

// externalHost returns the literal's URL when it points at a third-party host.
func (r *TestExternalServiceRule) externalHost(lit *ast.BasicLit) string {
	if lit.Kind.String() != "STRING" {
		return ""
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	match := r.externalURL.FindStringSubmatch(value)
	if match == nil {
		return ""
	}
	if r.localHost.MatchString(match[1]) {
		return ""
	}
	return value
}

// analyzeTestFile reports live calls and credential gates inside one test file.
func (r *TestExternalServiceRule) analyzeTestFile(
	file *core.FileContext, outbound map[string]outboundPackage, outboundDirs map[string]outboundPackage,
) []*core.Violation {
	imports := importAliases(file.GoAST)
	// Тест, поднявший свой httptest-сервер, никуда наружу не идёт.
	usesHTTPTest := false
	for _, imp := range file.GoImports {
		if imp == "net/http/httptest" {
			usesHTTPTest = true
			break
		}
	}

	// Файл, называющий локальный адрес, гоняет наш собственный сервер, и «секрет» в нём —
	// наш же JWT. В projectB на этом ловился reference-тест, который гейтится
	// BO_ADMIN_TOKEN и ходит в http://localhost:8090.
	drivesOwnServer := r.hasLocalURLLiteral(file.GoAST)

	var violations []*core.Violation
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		if r.hasGuard(fn) {
			continue
		}
		if !drivesOwnServer {
			violations = append(violations, r.credentialGates(file, fn)...)
		}
		if usesHTTPTest {
			continue
		}
		violations = append(violations, r.outboundCalls(file, imports, fn, outbound)...)
		if own, ok := outboundDirs[filepath.Dir(file.Path)]; ok {
			violations = append(violations, r.inPackageCalls(file, fn, own)...)
		}
	}
	return violations
}

// hasGuard reports whether the test opens with a project-declared live-call opt-in.
func (r *TestExternalServiceRule) hasGuard(fn *ast.FuncDecl) bool {
	if len(r.guardFunctions) == 0 {
		return false
	}
	guarded := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if guarded {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name := calleeName(call); name != "" && r.guardFunctions[name] {
			guarded = true
			return false
		}
		return true
	})
	return guarded
}

// calleeName renders `pkg.Func` or `Func` for a call expression.
func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			return ident.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	}
	return ""
}

// outboundCalls reports calls into packages that talk to a third party.
func (r *TestExternalServiceRule) outboundCalls(
	file *core.FileContext, imports map[string]string, fn *ast.FuncDecl, outbound map[string]outboundPackage,
) []*core.Violation {
	var violations []*core.Violation
	reported := map[string]bool{}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		path, ok := imports[ident.Name]
		if !ok {
			return true
		}
		evidence, ok := outbound[path]
		if !ok || !evidence.entries[sel.Sel.Name] {
			return true
		}
		// Конструктор, которому транспорт передали как nil, никуда не пойдёт: так тесты
		// собирают настоящий сервис ради его работы с БД. ProjectA-шный тест на пыль
		// (cryptoprov.NewDepositService(nil, …)) именно такой.
		if hasNilArgument(call) {
			return true
		}
		key := path + "." + sel.Sel.Name
		if reported[key] {
			return true
		}
		reported[key] = true

		pos := file.PositionFor(call)
		v := r.CreateViolation(file.RelPath, pos.Line, fmt.Sprintf(
			"Тест %s вызывает %s.%s — пакет %s. Тест не проверяет чужой код и не должен менять внешний мир",
			fn.Name.Name, ident.Name, sel.Sel.Name, evidence.evidence))
		v.WithCode(file.GetLine(pos.Line))
		v.WithSuggestion("Подставьте провайдера на HTTP-границе (httptest) или засейте данные напрямую; живой вызов оставьте за явным опт-ином из guard_functions")
		v.WithContext("pattern", "test_external_service")
		v.WithContext("kind", "outbound_client")
		v.WithContext("package", path)
		violations = append(violations, v)
		return true
	})
	return violations
}

// inPackageCalls reports unqualified calls to the vendor package's own entry points.
//
// A test living inside the vendor client's package writes `NewClient(cfg)`, not
// `cryptoprov.NewClient(cfg)`, so the import-based lookup above never sees it. That is exactly
// how ProjectA's cryptoprov integration test stayed invisible to the rule.
func (r *TestExternalServiceRule) inPackageCalls(
	file *core.FileContext, fn *ast.FuncDecl, own outboundPackage,
) []*core.Violation {
	var violations []*core.Violation
	reported := map[string]bool{}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || !own.entries[ident.Name] || hasNilArgument(call) {
			return true
		}
		if reported[ident.Name] {
			return true
		}
		reported[ident.Name] = true

		pos := file.PositionFor(call)
		v := r.CreateViolation(file.RelPath, pos.Line, fmt.Sprintf(
			"Тест %s вызывает %s из своего же пакета — пакет %s. Тест не проверяет чужой код и не должен менять внешний мир",
			fn.Name.Name, ident.Name, own.evidence))
		v.WithCode(file.GetLine(pos.Line))
		v.WithSuggestion("Подставьте провайдера на HTTP-границе (httptest) или засейте данные напрямую; живой вызов оставьте за явным опт-ином из guard_functions")
		v.WithContext("pattern", "test_external_service")
		v.WithContext("kind", "outbound_client")
		violations = append(violations, v)
		return true
	})
	return violations
}

// hasNilArgument reports whether the call passes an explicit nil.
func hasNilArgument(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && ident.Name == "nil" {
			return true
		}
	}
	return false
}

// credentialGates reports skips that only check whether a secret is configured.
func (r *TestExternalServiceRule) credentialGates(file *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	// Переменные, которым присвоен os.Getenv("NAME") с секретоподобным именем.
	fromCredential := map[string]string{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name := r.credentialEnvName(assign.Rhs[0])
		if name == "" {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
			fromCredential[ident.Name] = name
		}
		return true
	})

	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || !bodySkips(ifStmt.Body) {
			return true
		}
		envName := r.emptyCredentialCheck(ifStmt.Cond, fromCredential)
		if envName == "" {
			return true
		}
		pos := file.PositionFor(ifStmt)
		v := r.CreateViolation(file.RelPath, pos.Line, fmt.Sprintf(
			"Тест %s пропускается только когда %s не задана, а секреты лежат в .env и экспортируются раннером — гейт открыт всегда",
			fn.Name.Name, envName))
		v.WithCode(file.GetLine(pos.Line))
		v.WithSuggestion("Гейтить живой вызов отдельным переключателем, которого нет в .env, а не наличием секрета")
		v.WithContext("pattern", "test_external_service")
		v.WithContext("kind", "credential_gate")
		v.WithContext("env", envName)
		violations = append(violations, v)
		return true
	})
	return violations
}

// credentialEnvName returns the variable name when the expression reads a secret from the env.
func (r *TestExternalServiceRule) credentialEnvName(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Getenv" {
		return ""
	}
	if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != "os" {
		return ""
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return ""
	}
	name, err := strconv.Unquote(lit.Value)
	if err != nil || !r.credentialName.MatchString(name) {
		return ""
	}
	return name
}

// emptyCredentialCheck returns the env name compared against "" in the condition.
func (r *TestExternalServiceRule) emptyCredentialCheck(cond ast.Expr, fromCredential map[string]string) string {
	switch expr := cond.(type) {
	case *ast.ParenExpr:
		return r.emptyCredentialCheck(expr.X, fromCredential)
	case *ast.BinaryExpr:
		// Гейт часто перечисляет несколько секретов: `PUB == "" || PRIV == ""`.
		// Раньше разбирался только одиночный `==`, и составное условие проходило мимо
		// правила — так в ProjectA остался незамеченным живой тест cryptoprov.
		if expr.Op.String() == "||" || expr.Op.String() == "&&" {
			if name := r.emptyCredentialCheck(expr.X, fromCredential); name != "" {
				return name
			}
			return r.emptyCredentialCheck(expr.Y, fromCredential)
		}
		if expr.Op.String() != "==" || !isEmptyStringLiteral(expr.Y) {
			return ""
		}
		switch left := expr.X.(type) {
		case *ast.Ident:
			return fromCredential[left.Name]
		case *ast.CallExpr:
			return r.credentialEnvName(left)
		}
	}
	return ""
}

func isEmptyStringLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return false
	}
	value, err := strconv.Unquote(lit.Value)
	return err == nil && value == ""
}

// bodySkips reports whether the block calls t.Skip / t.Skipf / t.SkipNow.
func bodySkips(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	skips := false
	ast.Inspect(body, func(n ast.Node) bool {
		if skips {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if strings.HasPrefix(sel.Sel.Name, "Skip") {
			skips = true
			return false
		}
		return true
	})
	return skips
}

// importAliases maps the identifier used in code to the imported package path.
// Explicit aliases win; otherwise the last path segment is the package name, which
// matches Go's own default and is what a test file writes at the call site.
func importAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string, len(file.Imports))
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path
		if idx := strings.LastIndex(path, "/"); idx >= 0 {
			name = path[idx+1:]
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				continue
			}
			name = imp.Name.Name
		}
		aliases[name] = path
	}
	return aliases
}
