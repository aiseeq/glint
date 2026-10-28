package qarules

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// testDirFacts are what the test files of one directory tell about its
// tests: the names that stand for a test server and the helpers that skip a
// test unless a dedicated env flag is set.
type testDirFacts struct {
	// servedLocally holds the functions, methods and package-level variables
	// of the test files that start an httptest server, directly or through
	// one another.
	servedLocally map[string]bool
	// optInHelpers holds the functions of the test files that skip the test
	// unless a dedicated env flag is set.
	optInHelpers map[string]bool
}

// collectTestDirFacts reads the test files of every directory once.
//
// A test aimed at a test server is told by its own body: it uses httptest or
// a name that does. The httptest import of the file vouches for nothing more
// - a file of fake-feed tests held the test that built the rates client with
// its production address and called the live feed on every full run.
func (r *TestExternalServiceRule) collectTestDirFacts(files []*core.FileContext, envKeys map[string]bool) map[string]*testDirFacts {
	byDir := map[string][]*core.FileContext{}
	for _, file := range files {
		if file != nil && file.IsTestFile() && file.GoAST != nil {
			dir := filepath.Dir(file.Path)
			byDir[dir] = append(byDir[dir], file)
		}
	}
	facts := make(map[string]*testDirFacts, len(byDir))
	for dir, dirFiles := range byDir {
		facts[dir] = r.dirFacts(dirFiles, envKeys)
	}
	return facts
}

// namedTestDecl is a function or a package-level variable of a test file,
// with the names its file imports httptest under.
type namedTestDecl struct {
	name     string
	node     ast.Node
	httptest map[string]bool
}

// dirFacts reads the test files of one directory.
func (r *TestExternalServiceRule) dirFacts(dirFiles []*core.FileContext, envKeys map[string]bool) *testDirFacts {
	f := &testDirFacts{servedLocally: map[string]bool{}, optInHelpers: map[string]bool{}}
	var decls []namedTestDecl
	for _, file := range dirFiles {
		httptestPkgs := helpers.PackageAliases(file.GoAST, `"net/http/httptest"`, "httptest")
		osPkgs := helpers.PackageAliases(file.GoAST, `"os"`, "os")
		for _, decl := range file.GoAST.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				decls = append(decls, namedTestDecl{d.Name.Name, d.Body, httptestPkgs})
				if d.Recv == nil && r.opensWithEnvFlagSkip(d.Body, envKeys, osPkgs, f.optInHelpers) {
					f.optInHelpers[d.Name.Name] = true
				}
			case *ast.GenDecl:
				if d.Tok == token.VAR {
					decls = append(decls, packageVars(d, httptestPkgs)...)
				}
			}
		}
	}
	// Транзитивно: helper, который зовёт helper с httptest, тоже поднимает сервер.
	for changed := true; changed; {
		changed = false
		for _, d := range decls {
			if !f.servedLocally[d.name] && referencesTestServer(d.node, d.httptest, f.servedLocally) {
				f.servedLocally[d.name] = true
				changed = true
			}
		}
	}
	return f
}

// packageVars lists the variables of a var declaration with their specs.
func packageVars(d *ast.GenDecl, httptestPkgs map[string]bool) []namedTestDecl {
	var vars []namedTestDecl
	for _, spec := range d.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, ident := range value.Names {
			if ident.Name == "_" {
				continue
			}
			vars = append(vars, namedTestDecl{ident.Name, value, httptestPkgs})
		}
	}
	return vars
}

// referencesTestServer reports a use of httptest or of a name that starts a
// test server: an unqualified identifier, or the selected name of a value
// (s.newServer()), never of an imported package.
func referencesTestServer(node ast.Node, httptestPkgs, served map[string]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		switch e := n.(type) {
		case *ast.SelectorExpr:
			if x, ok := e.X.(*ast.Ident); ok && httptestPkgs[x.Name] {
				found = true
				return false
			}
			if served[e.Sel.Name] {
				found = true
			}
		case *ast.Ident:
			if served[e.Name] {
				found = true
			}
		}
		return !found
	})
	return found
}

// optInStart returns where the explicit opt-in of a test starts: the first
// top-level statement that skips the test unless a dedicated env flag is set,
// either inline or through a helper of the test files. Live calls after it
// run only when someone sets the flag. token.NoPos means no opt-in.
func (r *TestExternalServiceRule) optInStart(fn *ast.FuncDecl, envKeys, osPkgs, optInHelpers map[string]bool) token.Pos {
	flagVars := map[string]string{}
	for _, stmt := range fn.Body.List {
		r.recordFlagVars(stmt, osPkgs, flagVars)
		if r.envFlagSkip(stmt, envKeys, osPkgs, flagVars) || callsOptInHelper(stmt, optInHelpers) {
			return stmt.Pos()
		}
	}
	return token.NoPos
}

// opensWithEnvFlagSkip reports a helper body with an env-flag skip among its
// top-level statements.
func (r *TestExternalServiceRule) opensWithEnvFlagSkip(body *ast.BlockStmt, envKeys, osPkgs, optInHelpers map[string]bool) bool {
	flagVars := map[string]string{}
	for _, stmt := range body.List {
		r.recordFlagVars(stmt, osPkgs, flagVars)
		if r.envFlagSkip(stmt, envKeys, osPkgs, flagVars) || callsOptInHelper(stmt, optInHelpers) {
			return true
		}
	}
	return false
}

// callsOptInHelper reports a statement that is a call of an opt-in helper.
func callsOptInHelper(stmt ast.Stmt, optInHelpers map[string]bool) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && optInHelpers[ident.Name]
}

// recordFlagVars remembers the variables a statement reads an env variable
// into: live := os.Getenv("LIVE").
func (r *TestExternalServiceRule) recordFlagVars(stmt ast.Stmt, osPkgs map[string]bool, flagVars map[string]string) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return
	}
	ident, isIdent := assign.Lhs[0].(*ast.Ident)
	if name := envRead(assign.Rhs[0], osPkgs, "Getenv"); isIdent && name != "" {
		flagVars[ident.Name] = name
	}
}

// envFlagSkip reports `if <flag unset> { t.Skip(...) }`: the test goes on
// only when a dedicated env flag - one no env file of the project sets - is
// present.
func (r *TestExternalServiceRule) envFlagSkip(stmt ast.Stmt, envKeys, osPkgs map[string]bool, flagVars map[string]string) bool {
	ifStmt, ok := stmt.(*ast.IfStmt)
	if !ok || !bodySkips(ifStmt.Body) {
		return false
	}
	lookedUp := map[string]string{}
	if assign, isAssign := ifStmt.Init.(*ast.AssignStmt); isAssign && len(assign.Lhs) == 2 && len(assign.Rhs) == 1 {
		if okIdent, isIdent := assign.Lhs[1].(*ast.Ident); isIdent {
			if name := envRead(assign.Rhs[0], osPkgs, "LookupEnv"); name != "" {
				lookedUp[okIdent.Name] = name
			}
		}
	}
	name := flagUnset(ifStmt.Cond, osPkgs, flagVars, lookedUp)
	return name != "" && !envKeys[name]
}

// flagUnset returns the env variable whose absence the condition tests:
// os.Getenv("X") == "", os.Getenv("X") != "1", !ok of os.LookupEnv("X").
// A disjunction skips when either side holds, so one flag side makes the
// test wait for the flag.
func flagUnset(cond ast.Expr, osPkgs map[string]bool, flagVars, lookedUp map[string]string) string {
	switch e := ast.Unparen(cond).(type) {
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LOR:
			if name := flagUnset(e.X, osPkgs, flagVars, lookedUp); name != "" {
				return name
			}
			return flagUnset(e.Y, osPkgs, flagVars, lookedUp)
		case token.EQL, token.NEQ:
			lit, isLit := e.Y.(*ast.BasicLit)
			if !isLit {
				return ""
			}
			value, isString := patternkit.GoStringLiteral(lit)
			// == "" и != "<значение>" пропускают тест, пока флаг не задан;
			// != "" и == "<значение>" пропускают как раз заданный флаг.
			if !isString || (e.Op == token.EQL) != (value == "") {
				return ""
			}
			if ident, isIdent := e.X.(*ast.Ident); isIdent {
				return flagVars[ident.Name]
			}
			return envRead(e.X, osPkgs, "Getenv")
		}
	case *ast.UnaryExpr:
		if ident, isIdent := e.X.(*ast.Ident); isIdent && e.Op == token.NOT {
			return lookedUp[ident.Name]
		}
	}
	return ""
}

// envRead returns the variable name of os.<fn>("NAME").
func envRead(expr ast.Expr, osPkgs map[string]bool, fn string) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != fn {
		return ""
	}
	if pkg, isIdent := sel.X.(*ast.Ident); !isIdent || !osPkgs[pkg.Name] {
		return ""
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return ""
	}
	name, ok := patternkit.GoStringLiteral(lit)
	if !ok {
		return ""
	}
	return name
}

// liveCallScope is what decides whether a call of a test reaches the wire.
type liveCallScope struct {
	// liveEnd is where the explicit opt-in of the test starts: calls after it are not live.
	liveEnd token.Pos
	// unitTests marks a file that serves a test server: its tests build clients to check
	// validation, signing and limits, and only a request on a production address counts.
	unitTests bool
	// hostOf names the third-party URL of a literal.
	hostOf func(*ast.BasicLit) string
	// isLocalURL reports a literal URL on a loopback or reserved host.
	isLocalURL func(*ast.BasicLit) bool
}

// reaches returns the evidence of a live call and whether the call is one. Outside a file of
// unit tests every call of an entry is, as the client it builds has no offline mode. In such a
// file the call must aim at production - the entry's own address, a URL literal or a URL
// constant of the package among the arguments - and reach the wire: a function that sends
// itself, or a client whose sending method the test calls. In any file an entry that takes its
// address from the caller and gets a loopback or reserved URL literal reaches nothing outside.
func (s liveCallScope) reaches(body *ast.BlockStmt, call *ast.CallExpr, entry liveEntry, pkg outboundPackage, isQualifier func(ast.Expr) bool) (string, bool) {
	evidence := pkg.evidence
	if entry.address != "" {
		evidence = "ходит в " + entry.address
	} else if s.aimsLocally(call) {
		return "", false
	}
	if !s.unitTests {
		return evidence, true
	}
	host := entry.address
	for _, arg := range call.Args {
		if host != "" {
			break
		}
		host = productionArgument(arg, pkg.urlNames, isQualifier, s.hostOf)
	}
	if host == "" || (!entry.direct && !callsLiveMethod(body, call, entry.liveMethods)) {
		return "", false
	}
	return "ходит в " + host, true
}

// aimsLocally reports a loopback or reserved URL literal among the arguments of the call.
func (s liveCallScope) aimsLocally(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if lit, ok := ast.Unparen(arg).(*ast.BasicLit); ok && s.isLocalURL(lit) {
			return true
		}
	}
	return false
}

// productionArgument returns the third-party URL an argument names: a literal, or a URL
// constant of the package, unqualified in its own tests (isQualifier nil) or qualified by the
// package's import.
func productionArgument(arg ast.Expr, urlNames map[string]string, isQualifier func(ast.Expr) bool, hostOf func(*ast.BasicLit) string) string {
	switch a := ast.Unparen(arg).(type) {
	case *ast.BasicLit:
		// Хост без точки ("http://stub", имя сервиса в compose) - заглушка, не боевой адрес.
		if host := hostOf(a); strings.Contains(hostName(host), ".") {
			return host
		}
	case *ast.Ident:
		if isQualifier == nil {
			return urlNames[a.Name]
		}
	case *ast.SelectorExpr:
		if isQualifier != nil && isQualifier(a.X) {
			return urlNames[a.Sel.Name]
		}
	}
	return ""
}

// callsLiveMethod reports a sending method called on the result of the constructor call:
// chained (New().Rate()) or through the variable it is assigned to.
func callsLiveMethod(body *ast.BlockStmt, ctor *ast.CallExpr, methods map[string]bool) bool {
	holders := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 && assign.Rhs[0] == ast.Expr(ctor) && len(assign.Lhs) > 0 {
			if ident, isIdent := assign.Lhs[0].(*ast.Ident); isIdent {
				holders[ident.Name] = true
			}
		}
		return true
	})
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !methods[sel.Sel.Name] {
			return true
		}
		switch x := ast.Unparen(sel.X).(type) {
		case *ast.CallExpr:
			found = x == ctor
		case *ast.Ident:
			found = holders[x.Name]
		}
		return !found
	})
	return found
}

// hostName returns the host of a URL the externalURL pattern matched, without the scheme,
// the port and the path.
func hostName(rawURL string) string {
	_, rest, _ := strings.Cut(rawURL, "://")
	host, _, _ := strings.Cut(rest, "/")
	host, _, _ = strings.Cut(host, ":")
	return host
}
