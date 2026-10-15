package patterns

import (
	"go/ast"
	"go/token"
	"path/filepath"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
			value, isString := goStringLiteral(lit)
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
	name, ok := goStringLiteral(lit)
	if !ok {
		return ""
	}
	return name
}
