package qarules

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
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
	// emptyFuncs holds "package.function" for the functions of the directory,
	// test files and sources alike, whose body is only bare returns.
	emptyFuncs map[string]bool
	// packageValues holds, by "package.variable", the values given to the
	// package-level variables of the directory, test files and sources alike.
	packageValues map[string][]ast.Expr
}

type clientHolder struct {
	name string
	obj  types.Object
	// field is the field of the struct literal the name holds that keeps the
	// client (b := Box{C: New()}): the name is the client only through it.
	// Empty when the name holds the client itself.
	field string
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
		facts[dir].emptyFuncs = map[string]bool{}
		facts[dir].packageValues = map[string][]ast.Expr{}
	}
	for _, file := range files {
		if file == nil || file.GoAST == nil {
			continue
		}
		if f := facts[filepath.Dir(file.Path)]; f != nil {
			for _, decl := range file.GoAST.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && onlyBareReturns(fn.Body) {
					f.emptyFuncs[file.GoAST.Name.Name+"."+fn.Name.Name] = true
				}
				f.addPackageValues(file.GoAST.Name.Name, decl)
			}
		}
	}
	return facts
}

// addPackageValues records the values decl gives to package-level variables
// of pkg: a var declaration, and assignments in init, whose value holds for
// every test.
func (f *testDirFacts) addPackageValues(pkg string, decl ast.Decl) {
	add := func(name string, value ast.Expr) {
		f.packageValues[pkg+"."+name] = append(f.packageValues[pkg+"."+name], value)
	}
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv != nil || d.Name.Name != "init" || d.Body == nil {
			return
		}
		ast.Inspect(d.Body, func(n ast.Node) bool {
			as, isAssign := n.(*ast.AssignStmt)
			if !isAssign || as.Tok != token.ASSIGN || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for i, lhs := range as.Lhs {
				if id, isIdent := lhs.(*ast.Ident); isIdent {
					add(id.Name, as.Rhs[i])
				}
			}
			return true
		})
	case *ast.GenDecl:
		if d.Tok != token.VAR {
			return
		}
		for _, spec := range d.Specs {
			vs, isValue := spec.(*ast.ValueSpec)
			for i := 0; isValue && i < len(vs.Names) && i < len(vs.Values); i++ {
				add(vs.Names[i].Name, vs.Values[i])
			}
		}
	}
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
	// emptyFunc reports a function of the test's own package whose body is
	// only bare returns.
	emptyFunc func(name string) bool
	// packageValues lists the values given to a package-level variable of
	// the test's own package.
	packageValues func(name string) []ast.Expr
	// consumers are the standard functions the test may hand the client to
	// without the client escaping.
	consumers stdConsumers
}

// stdConsumers names, by the import names of the test file and the testing
// handles of the test, the known standard functions that take the client
// without calling it: the printers of fmt and the log methods of the testing
// handle call only its formatting methods, reflect.DeepEqual calls none.
type stdConsumers struct {
	fmtPkgs, reflectPkgs, handles map[string]bool
}

// fmtPrinters maps a printer of fmt to the index of its first formatted
// argument: before it stands the writer or buffer the printer writes to.
var fmtPrinters = map[string]int{
	"Print": 0, "Printf": 0, "Println": 0, "Sprint": 0, "Sprintf": 0, "Sprintln": 0, "Errorf": 0,
	"Fprint": 1, "Fprintf": 1, "Fprintln": 1, "Append": 1, "Appendf": 1, "Appendln": 1,
}

// testingLoggers are the methods of a testing handle that format their arguments.
var testingLoggers = map[string]bool{"Log": true, "Logf": true, "Error": true, "Errorf": true, "Fatal": true, "Fatalf": true}

// formattingMethods are the methods fmt calls on a value it formats.
var formattingMethods = []string{"String", "Error", "GoString", "Format"}

// inert reports whether call is a known standard function given value as an
// argument that calls no live method of it: a printer of fmt or a log method
// of the testing handle formatting it while none of its formatting methods is
// live, or reflect.DeepEqual. A package name the test declares itself is not
// the package, and a handle name bound to a value of another type is no handle.
func (c stdConsumers) inert(body *ast.BlockStmt, call *ast.CallExpr, value ast.Expr, liveMethods map[string]bool, info *types.Info) bool {
	sel, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector {
		return false
	}
	x, isIdent := sel.X.(*ast.Ident)
	at := slices.Index(call.Args, value)
	if !isIdent || at < 0 {
		return false
	}
	switch {
	case c.reflectPkgs[x.Name]:
		return sel.Sel.Name == "DeepEqual" && !declaresName(body, x.Name)
	case c.fmtPkgs[x.Name]:
		start, printer := fmtPrinters[sel.Sel.Name]
		if !printer || at < start || declaresName(body, x.Name) {
			return false
		}
	case c.handles[x.Name]:
		if !testingLoggers[sel.Sel.Name] || !testingHandleValue(body, x, info) {
			return false
		}
	default:
		return false
	}
	return !slices.ContainsFunc(formattingMethods, func(method string) bool { return liveMethods[method] })
}

// reaches returns the evidence of a live call and whether the call is one. A direct sending
// entry reaches the wire itself. A constructor counts only when the test calls one of its live
// methods. The call must use an external address: the entry's own address, a URL literal or
// package URL constant among the arguments, or an address passed to a live method. In a file
// of unit tests the test must also call the sending method explicitly. A caller-supplied
// loopback or reserved URL does not reach outside.
func (s liveCallScope) reaches(body *ast.BlockStmt, call *ast.CallExpr, entry liveEntry, pkg outboundPackage, isQualifier func(ast.Expr) bool, info *types.Info) (string, bool) {
	host := entry.address
	if host == "" {
		if s.aimsLocally(call) {
			return "", false
		}
		for _, arg := range call.Args {
			if host = productionArgument(arg, pkg.urlNames, isQualifier, s.hostOf); host != "" {
				break
			}
		}
	}
	if host == "" && !entry.direct {
		host = liveMethodArgument(body, call, entry.liveMethods, entry.resultIndexes, entry.selfMethods, pkg.urlNames, isQualifier, s.hostOf, info)
	}
	if !s.unitTests {
		if !entry.direct && !callsLiveMethod(body, call, entry.liveMethods, entry.resultIndexes, entry.selfMethods, info) && !constructorResultEscapes(body, call, entry.escapingMethods(), entry.knownMembers, entry.selfMethods, entry.resultIndexes, info, s) {
			return "", false
		}
		if host == "" {
			return pkg.evidence, true
		}
		return "ходит в " + host, true
	}
	if host == "" || (!entry.direct && !callsLiveMethod(body, call, entry.liveMethods, entry.resultIndexes, entry.selfMethods, info)) {
		return "", false
	}
	return "ходит в " + host, true
}

// constructorResultEscapes reports whether the test lets the constructed client reach code
// whose behavior the rule cannot establish. A live method call is handled separately; reads
// of fields, calls to known non-live methods and the known standard consumers of the scope
// are safe.
func constructorResultEscapes(body *ast.BlockStmt, ctor *ast.CallExpr, liveMethods, knownMembers, selfMethods map[string]bool, resultIndexes map[int]bool, info *types.Info, scope liveCallScope) bool {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})

	holders, initializers := constructorResultHolders(body, ctor, resultIndexes, selfMethods, info)
	if constructorOnlyInspectedOrDiscarded(body, ctor, holders, initializers, parents) {
		return false
	}
	consumed := func(call *ast.CallExpr, value ast.Expr) bool {
		return scope.consumers.inert(body, call, value, liveMethods, info)
	}

	// A constructor result used directly as a return value, argument, field, channel value,
	// literal element or any other non-local expression escapes without a named holder.
	if len(holders) == 0 {
		return directConstructorResultEscapes(parents[ctor], parents, ctor, liveMethods, knownMembers, selfMethods, resultIndexes, consumed)
	}
	uses := clientUses{parents: parents, liveMethods: liveMethods, knownMembers: knownMembers, initializers: initializers, consumed: consumed}
	return constructorHolderEscapes(body, holders, info, scope.emptyFunc, uses)
}

func constructorOnlyInspectedOrDiscarded(body *ast.BlockStmt, ctor *ast.CallExpr, holders []clientHolder, initializers map[*ast.Ident]bool, parents map[ast.Node]ast.Node) bool {
	if len(holders) == 0 || !constructorNestedInComposite(ctor, parents) {
		return false
	}
	for _, holder := range holders {
		used := false
		var safe = true
		ast.Inspect(body, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || initializers[id] || id.Name != holder.name {
				return true
			}
			used = true
			parent := parents[id]
			for {
				switch node := parent.(type) {
				case *ast.SelectorExpr:
					if node.X != id && !containsASTNode(node.X, id) {
						safe = false
						return false
					}
					if call, ok := parents[node].(*ast.CallExpr); ok && call.Fun == node {
						safe = false
						return false
					}
					parent = parents[node]
				case *ast.IndexExpr:
					if node.X != id && !containsASTNode(node.X, id) {
						safe = false
						return false
					}
					parent = parents[node]
				case *ast.AssignStmt:
					if len(node.Lhs) == 0 || !allBlank(node.Lhs) {
						safe = false
					}
					return false
				case *ast.ExprStmt:
					return false
				default:
					safe = false
					return false
				}
			}
		})
		if !used || !safe {
			return false
		}
	}
	return true
}

func constructorNestedInComposite(ctor *ast.CallExpr, parents map[ast.Node]ast.Node) bool {
	for parent := parents[ctor]; parent != nil; parent = parents[parent] {
		if _, ok := parent.(*ast.CompositeLit); ok {
			return true
		}
		if _, ok := parent.(*ast.AssignStmt); ok || func() bool { _, ok := parent.(*ast.ValueSpec); return ok }() {
			return false
		}
	}
	return false
}

func directConstructorResultEscapes(parent ast.Node, parents map[ast.Node]ast.Node, ctor *ast.CallExpr, liveMethods, knownMembers, selfMethods map[string]bool, resultIndexes map[int]bool, consumed func(*ast.CallExpr, ast.Expr) bool) bool {
	switch p := parent.(type) {
	case *ast.AssignStmt:
		for i, lhs := range p.Lhs {
			if !resultIndexes[i] {
				continue
			}
			if id, ok := lhs.(*ast.Ident); !ok || id.Name != "_" {
				return true
			}
		}
		return false
	case *ast.ValueSpec:
		for i, name := range p.Names {
			if resultIndexes[i] {
				return name.Name != "_"
			}
		}
		return false
	case *ast.ExprStmt:
		return false
	case *ast.BinaryExpr:
		return !comparedWithNil(p, ctor)
	case *ast.CallExpr:
		return !consumed(p, ctor)
	case *ast.SelectorExpr:
		if p.X == ctor {
			if call, ok := parents[p].(*ast.CallExpr); ok && call.Fun == p && selfMethods[p.Sel.Name] {
				// A builder hands back the client: follow its result.
				return directConstructorResultEscapes(parents[call], parents, call, liveMethods, knownMembers, selfMethods, map[int]bool{0: true}, consumed)
			}
			if call, ok := parents[p].(*ast.CallExpr); ok && call.Fun == p {
				return liveMethods[p.Sel.Name] || !knownMembers[p.Sel.Name]
			}
			return liveMethods[p.Sel.Name] || !knownMembers[p.Sel.Name]
		}
		return true
	case *ast.ReturnStmt, *ast.CompositeLit, *ast.SendStmt, *ast.FuncLit:
		return true
	default:
		return parent != nil
	}
}

// clientUses is what tells a use of a holder of the client that lets it escape from one
// that stays local.
type clientUses struct {
	parents                   map[ast.Node]ast.Node
	liveMethods, knownMembers map[string]bool
	// initializers are the names the holders are bound to: handing the client to one of
	// them is no escape.
	initializers map[*ast.Ident]bool
	// consumed reports a known standard function taking the client without calling it.
	consumed func(*ast.CallExpr, ast.Expr) bool
}

// constructorHolderEscapes reports whether a use of a holder lets the client escape. A
// holder whose literal keeps the client in a field (b := Box{C: New()}) is the client
// only through that field: another field of the literal is not the client, a method of
// the literal may use it.
func constructorHolderEscapes(body *ast.BlockStmt, holders []clientHolder, info *types.Info, emptyFunc func(string) bool, uses clientUses) bool {
	escapes := false
	ast.Inspect(body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || escapes || uses.initializers[id] {
			return !escapes
		}
		holder, isHolder := holderOf(id, holders, info)
		if !isHolder {
			return true
		}
		if call, ok := uses.parents[id].(*ast.CallExpr); ok && localEmptyCallConsumes(body, call, id, emptyFunc) {
			return true
		}
		var use ast.Expr = id
		if sel, ok := uses.parents[id].(*ast.SelectorExpr); ok && sel.X == id && holder.field != "" {
			if sel.Sel.Name != holder.field {
				call, called := uses.parents[sel].(*ast.CallExpr)
				escapes = called && call.Fun == sel
				return !escapes
			}
			use = sel
		}
		escapes = uses.escapes(use)
		return !escapes
	})
	return escapes
}

// escapes reports whether the use of the client value lets it reach unknown code.
func (u clientUses) escapes(use ast.Expr) bool {
	parent := u.parents[use]
	for ancestor := parent; ancestor != nil; ancestor = u.parents[ancestor] {
		if _, ok := ancestor.(*ast.FuncLit); ok {
			return true
		}
	}
	parents, liveMethods, knownMembers := u.parents, u.liveMethods, u.knownMembers
	switch p := parent.(type) {
	case *ast.SelectorExpr:
		if p.X != use {
			return true
		}
		if call, ok := parents[p].(*ast.CallExpr); ok && call.Fun == p {
			return !knownMembers[p.Sel.Name]
		}
		return liveMethods[p.Sel.Name] || !knownMembers[p.Sel.Name]
	case *ast.IndexExpr:
		for ancestor := parents[p]; ancestor != nil; ancestor = parents[ancestor] {
			if assign, ok := ancestor.(*ast.AssignStmt); ok {
				return len(assign.Lhs) > 0 && allBlank(assign.Lhs)
			}
			if _, ok := ancestor.(*ast.ExprStmt); ok {
				return true
			}
			if _, ok := ancestor.(*ast.CallExpr); ok {
				return true
			}
		}
		return true
	case *ast.BinaryExpr:
		return !comparedWithNil(p, use)
	case *ast.AssignStmt:
		for i, rhs := range p.Rhs {
			if rhs == use {
				// The client handed to another holder stays with the test.
				if holder, ok := p.Lhs[i].(*ast.Ident); ok && u.initializers[holder] {
					return false
				}
				discarded := len(p.Lhs) > 0
				for _, lhs := range p.Lhs {
					blank, ok := lhs.(*ast.Ident)
					discarded = discarded && ok && blank.Name == "_"
				}
				return !discarded
			}
		}
		return false
	case *ast.ValueSpec:
		i := slices.Index(p.Values, use)
		if i < 0 {
			// The declaration of a holder (var c *Client) is no use of the client.
			return !slices.ContainsFunc(p.Names, func(name *ast.Ident) bool { return ast.Expr(name) == use })
		}
		return len(p.Names) != len(p.Values) || (p.Names[i].Name != "_" && !u.initializers[p.Names[i]])
	case *ast.CallExpr:
		return !u.consumed(p, use)
	case *ast.UnaryExpr, *ast.CompositeLit, *ast.ReturnStmt, *ast.SendStmt, *ast.KeyValueExpr:
		return true
	default:
		return true
	}
}

func allBlank(lhs []ast.Expr) bool {
	for _, expr := range lhs {
		id, ok := expr.(*ast.Ident)
		if !ok || id.Name != "_" {
			return false
		}
	}
	return true
}

func localEmptyCallConsumes(body *ast.BlockStmt, call *ast.CallExpr, value *ast.Ident, emptyFunc func(string) bool) bool {
	id, ok := call.Fun.(*ast.Ident)
	if !ok || emptyFunc == nil || !emptyFunc(id.Name) || declaresName(body, id.Name) {
		return false
	}
	return slices.ContainsFunc(call.Args, func(arg ast.Expr) bool { return arg == value })
}

// onlyBareReturns reports a body that provably drops its arguments: a
// returned expression can still call them.
func onlyBareReturns(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(ret.Results) > 0 {
			return false
		}
	}
	return true
}

// testingHandleValue reports whether the name stands for a *testing.T, B or F
// or a testing.TB: a test may bind the handle's name to its own logger in a
// nested block. Without type information the name is the handle unless the
// test binds it again.
func testingHandleValue(body *ast.BlockStmt, x *ast.Ident, info *types.Info) bool {
	if info == nil || info.Uses[x] == nil {
		return !redeclaresHandle(body, x)
	}
	t := info.Uses[x].Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T", "B", "F", "TB":
		return true
	}
	return false
}

// redeclaresHandle reports whether, where use stands, the test has bound the
// name of its testing handle to something else by :=, var or a range clause:
// the binding precedes use, and its scope (the enclosing block, the if, for or
// switch it opens, the range statement) encloses it. A parameter of a function
// literal needs no look: a use of the client inside a literal escapes anyway.
func redeclaresHandle(body *ast.BlockStmt, use *ast.Ident) bool {
	name := use.Name
	found := false
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if found {
			return false
		}
		var scope ast.Node
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE && slices.ContainsFunc(node.Lhs, func(lhs ast.Expr) bool { return isIdentNamed(lhs, name) }) {
				scope = enclosingScope(stack)
			}
		case *ast.ValueSpec:
			if slices.ContainsFunc(node.Names, func(id *ast.Ident) bool { return id.Name == name }) {
				scope = enclosingScope(stack)
			}
		case *ast.RangeStmt:
			if node.Tok == token.DEFINE && (isIdentNamed(node.Key, name) || isIdentNamed(node.Value, name)) {
				scope = node
			}
		}
		found = scope != nil && n.Pos() < use.Pos() && scope.Pos() <= use.Pos() && use.End() <= scope.End()
		stack = append(stack, n)
		return true
	})
	return found
}

// enclosingScope returns the innermost node of the stack that opens a scope
// for a binding made in it.
func enclosingScope(stack []ast.Node) ast.Node {
	for i := len(stack) - 1; i >= 0; i-- {
		switch stack[i].(type) {
		case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause, *ast.IfStmt, *ast.ForStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
			return stack[i]
		}
	}
	return nil
}

func isIdentNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// declaresName reports whether the test body declares the name itself, so a
// call by that name may not reach the package function.
func declaresName(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
						found = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range node.Names {
				found = found || id.Name == name
			}
		case *ast.Field:
			for _, id := range node.Names {
				found = found || id.Name == name
			}
		case *ast.TypeSpec:
			found = found || node.Name.Name == name
		}
		return !found
	})
	return found
}

// holdsConstructor reports whether the value of e is the constructed client
// itself, a copy of it (*New()), the client handed back by a builder method
// (New().WithKey(k), c.WithKey(k)), a literal holding it (&Box{C: New()},
// []*Client{New()}) or a value held reports: a holder of the client or the
// field of a literal holder that keeps it. The result of another method
// called on the client (New().Name()) is not the client.
func holdsConstructor(e ast.Expr, ctor *ast.CallExpr, selfMethods map[string]bool, held func(ast.Expr) bool) bool {
	switch e := ast.Unparen(e).(type) {
	case *ast.CallExpr:
		if e == ctor {
			return true
		}
		sel, isMethod := e.Fun.(*ast.SelectorExpr)
		return isMethod && selfMethods[sel.Sel.Name] && holdsConstructor(sel.X, ctor, selfMethods, held)
	case *ast.UnaryExpr:
		return e.Op == token.AND && holdsConstructor(e.X, ctor, selfMethods, held)
	case *ast.StarExpr:
		return holdsConstructor(e.X, ctor, selfMethods, held)
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if holdsConstructor(elt, ctor, selfMethods, held) {
				return true
			}
		}
	case *ast.KeyValueExpr:
		return holdsConstructor(e.Key, ctor, selfMethods, held) || holdsConstructor(e.Value, ctor, selfMethods, held)
	case *ast.Ident, *ast.SelectorExpr:
		return held != nil && held(e)
	}
	return false
}

// heldClient reports whether e is the client through a holder: the name of a
// holder of the client itself, or the field of a literal holder that keeps it.
func heldClient(e ast.Expr, holders []clientHolder, info *types.Info) bool {
	switch e := e.(type) {
	case *ast.Ident:
		holder, ok := holderOf(e, holders, info)
		return ok && holder.field == ""
	case *ast.SelectorExpr:
		x, isIdent := ast.Unparen(e.X).(*ast.Ident)
		if !isIdent {
			return false
		}
		holder, ok := holderOf(x, holders, info)
		return ok && holder.field == e.Sel.Name
	}
	return false
}

// literalField returns the field of a struct literal (Box{C: New()},
// &Box{C: New()}) whose value holds the client, "" for any other value.
func literalField(e ast.Expr, ctor *ast.CallExpr, selfMethods map[string]bool, held func(ast.Expr) bool) string {
	e = ast.Unparen(e)
	if ref, ok := e.(*ast.UnaryExpr); ok && ref.Op == token.AND {
		e = ast.Unparen(ref.X)
	}
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	switch lit.Type.(type) {
	case *ast.MapType, *ast.ArrayType:
		return ""
	}
	for _, elt := range lit.Elts {
		kv, isKeyed := elt.(*ast.KeyValueExpr)
		if !isKeyed {
			continue
		}
		if key, isIdent := kv.Key.(*ast.Ident); isIdent && holdsConstructor(kv.Value, ctor, selfMethods, held) {
			return key.Name
		}
	}
	return ""
}

// constructorResultHolders returns the names the test binds the client to and
// the identifiers that bind them. A name bound to a value of a holder (d := c,
// d := c.WithKey(k), d := b.C) holds the client too, so binding repeats until
// no holder is added.
func constructorResultHolders(body *ast.BlockStmt, ctor *ast.CallExpr, resultIndexes map[int]bool, selfMethods map[string]bool, info *types.Info) ([]clientHolder, map[*ast.Ident]bool) {
	var holders []clientHolder
	initializers := make(map[*ast.Ident]bool)
	held := func(e ast.Expr) bool { return heldClient(e, holders, info) }
	add := func(lhs, value ast.Expr) bool {
		id, ok := lhs.(*ast.Ident)
		if !ok || id.Name == "_" || initializers[id] {
			return false
		}
		var obj types.Object
		if info != nil {
			obj = info.Defs[id]
			if obj == nil {
				obj = info.Uses[id]
			}
		}
		holders = append(holders, clientHolder{name: id.Name, obj: obj, field: literalField(value, ctor, selfMethods, held)})
		initializers[id] = true
		return true
	}
	bind := func(names, values []ast.Expr) bool {
		added := false
		if len(values) == 1 && len(names) > 1 {
			// Only the constructor itself has several results.
			if ast.Unparen(values[0]) == ctor {
				for i, name := range names {
					added = resultIndexes[i] && add(name, values[0]) || added
				}
			}
			return added
		}
		if len(names) != len(values) {
			return false
		}
		for i, value := range values {
			added = holdsConstructor(value, ctor, selfMethods, held) && add(names[i], value) || added
		}
		return added
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			switch assign := n.(type) {
			case *ast.AssignStmt:
				changed = bind(assign.Lhs, assign.Rhs) || changed
			case *ast.ValueSpec:
				names := make([]ast.Expr, len(assign.Names))
				for i, name := range assign.Names {
					names[i] = name
				}
				changed = bind(names, assign.Values) || changed
			}
			return true
		})
	}
	return holders, initializers
}

func containsASTNode(root ast.Node, target ast.Node) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if n == target {
			found = true
			return false
		}
		return !found
	})
	return found
}

// holderOf returns the holder the identifier names: by its object when both
// have one, by name otherwise.
func holderOf(id *ast.Ident, holders []clientHolder, info *types.Info) (clientHolder, bool) {
	var object types.Object
	if info != nil {
		object = info.Uses[id]
		if object == nil {
			object = info.Defs[id]
		}
	}
	for _, h := range holders {
		if object != nil && h.obj != nil {
			if object == h.obj {
				return h, true
			}
			continue
		}
		if h.name == id.Name {
			return h, true
		}
	}
	return clientHolder{}, false
}

func comparedWithNil(expr *ast.BinaryExpr, value ast.Expr) bool {
	if expr.Op != token.EQL && expr.Op != token.NEQ {
		return false
	}
	other := expr.X
	if other == value {
		other = expr.Y
	}
	id, ok := ast.Unparen(other).(*ast.Ident)
	return ok && id.Name == "nil"
}

// liveMethodArgument returns the first external URL passed to a live method of the
// client returned by call. This lets a caller supplied URL take precedence over an unrelated
// URL literal elsewhere in the package.
func liveMethodArgument(body *ast.BlockStmt, ctor *ast.CallExpr, methods map[string]bool, resultIndexes map[int]bool, selfMethods map[string]bool, urls map[string]string, isQualifier func(ast.Expr) bool, hostOf func(*ast.BasicLit) string, info *types.Info) string {
	call := liveMethodCall(body, ctor, methods, resultIndexes, selfMethods, info)
	if call == nil {
		return ""
	}
	for _, arg := range call.Args {
		if host := productionArgument(arg, urls, isQualifier, hostOf); host != "" {
			return host
		}
	}
	return ""
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

// callsLiveMethod returns a sending method called on the result of the constructor call:
// chained (New().Rate()) or through the variable it is assigned to.
func callsLiveMethod(body *ast.BlockStmt, ctor *ast.CallExpr, methods map[string]bool, resultIndexes map[int]bool, selfMethods map[string]bool, info *types.Info) bool {
	return liveMethodCall(body, ctor, methods, resultIndexes, selfMethods, info) != nil
}

func liveMethodCall(body *ast.BlockStmt, ctor *ast.CallExpr, methods map[string]bool, resultIndexes map[int]bool, selfMethods map[string]bool, info *types.Info) *ast.CallExpr {
	holders, _ := constructorResultHolders(body, ctor, resultIndexes, selfMethods, info)
	held := func(e ast.Expr) bool { return heldClient(e, holders, info) }
	var found *ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != nil {
			return found == nil
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !methods[sel.Sel.Name] {
			return true
		}
		switch x := ast.Unparen(sel.X).(type) {
		case *ast.CallExpr, *ast.Ident, *ast.SelectorExpr:
			if holdsConstructor(x, ctor, selfMethods, held) {
				found = call
			}
		}
		return found == nil
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

// calleeCandidates is what a call's function may be: the expression itself
// and, while it is a plain name, every value bound to that name where the
// call can see it — in the test body, at the top of its package or in its
// init — followed
// through names bound to names. A constructor taken as a value (f := New;
// f()) is the same call as the constructor. Test files carry no type
// information, so names are matched syntactically by scope: a definition
// counts when its block encloses the call, an assignment when its function
// does. A stray binding of the same name can only add a candidate, which
// keeps the rule on the side of reporting.
func calleeCandidates(body *ast.BlockStmt, call *ast.CallExpr, packageValues func(string) []ast.Expr) []ast.Expr {
	bindings := visibleBindings(body, call.Pos())
	var candidates []ast.Expr
	seen := map[string]bool{}
	var expand func(ast.Expr)
	expand = func(e ast.Expr) {
		e = ast.Unparen(e)
		candidates = append(candidates, e)
		id, ok := e.(*ast.Ident)
		if !ok || seen[id.Name] {
			return
		}
		seen[id.Name] = true
		for _, value := range bindings[id.Name] {
			expand(value)
		}
		if packageValues != nil {
			for _, value := range packageValues(id.Name) {
				expand(value)
			}
		}
	}
	expand(call.Fun)
	return candidates
}

// visibleBindings maps a name to the values body binds to it that a call at
// pos can see. A definition counts when its scope — a block, a case or comm
// clause, the implicit block of if, for, range, switch and select —
// encloses the call. An assignment counts anywhere in
// body: a closure or a branch may run it before the call.
func visibleBindings(body *ast.BlockStmt, pos token.Pos) map[string][]ast.Expr {
	bindings := map[string][]ast.Expr{}
	encloses := func(n ast.Node) bool { return n.Pos() <= pos && pos < n.End() }
	var scopes, stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(scopes) > 0 && scopes[len(scopes)-1] == top {
				scopes = scopes[:len(scopes)-1]
			}
			return true
		}
		stack = append(stack, n)
		switch n := n.(type) {
		case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause, *ast.IfStmt, *ast.ForStmt,
			*ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			scopes = append(scopes, n)
		case *ast.AssignStmt:
			if len(n.Lhs) != len(n.Rhs) || (n.Tok == token.DEFINE && !encloses(scopes[len(scopes)-1])) {
				return true
			}
			for i, lhs := range n.Lhs {
				if l, isIdent := lhs.(*ast.Ident); isIdent {
					bindings[l.Name] = append(bindings[l.Name], n.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			if encloses(scopes[len(scopes)-1]) {
				for i, name := range n.Names {
					if i < len(n.Values) {
						bindings[name.Name] = append(bindings[name.Name], n.Values[i])
					}
				}
			}
		}
		return true
	})
	return bindings
}
