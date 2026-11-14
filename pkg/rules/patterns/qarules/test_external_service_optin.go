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
				if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.VAR {
					for _, spec := range gen.Specs {
						vs, isValue := spec.(*ast.ValueSpec)
						for i := 0; isValue && i < len(vs.Names) && i < len(vs.Values); i++ {
							key := file.GoAST.Name.Name + "." + vs.Names[i].Name
							f.packageValues[key] = append(f.packageValues[key], vs.Values[i])
						}
					}
				}
			}
		}
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
	// emptyFunc reports a function of the test's own package whose body is
	// only bare returns.
	emptyFunc func(name string) bool
	// packageValues lists the values given to a package-level variable of
	// the test's own package.
	packageValues func(name string) []ast.Expr
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
		host = liveMethodArgument(body, call, entry.liveMethods, entry.resultIndexes, pkg.urlNames, isQualifier, s.hostOf, info)
	}
	if !s.unitTests {
		if !entry.direct && !callsLiveMethod(body, call, entry.liveMethods, entry.resultIndexes, info) && !constructorResultEscapes(body, call, entry.liveMethods, entry.knownMembers, entry.resultIndexes, info, s.emptyFunc) {
			return "", false
		}
		if host == "" {
			return pkg.evidence, true
		}
		return "ходит в " + host, true
	}
	if host == "" || (!entry.direct && !callsLiveMethod(body, call, entry.liveMethods, entry.resultIndexes, info)) {
		return "", false
	}
	return "ходит в " + host, true
}

// constructorResultEscapes reports whether the test lets the constructed client reach code
// whose behavior the rule cannot establish. A live method call is handled separately; reads
// of fields and calls to known non-live methods are safe.
func constructorResultEscapes(body *ast.BlockStmt, ctor *ast.CallExpr, liveMethods, knownMembers map[string]bool, resultIndexes map[int]bool, info *types.Info, emptyFunc func(string) bool) bool {
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

	holders, initializers := constructorResultHolders(body, ctor, resultIndexes, info)
	if constructorOnlyInspectedOrDiscarded(body, ctor, holders, initializers, parents) {
		return false
	}

	// A constructor result used directly as a return value, argument, field, channel value,
	// literal element or any other non-local expression escapes without a named holder.
	if len(holders) == 0 {
		return directConstructorResultEscapes(parents[ctor], parents, ctor, liveMethods, knownMembers, resultIndexes)
	}
	return constructorHolderEscapes(body, parents, holders, initializers, liveMethods, knownMembers, info, emptyFunc)
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

func directConstructorResultEscapes(parent ast.Node, parents map[ast.Node]ast.Node, ctor *ast.CallExpr, liveMethods, knownMembers map[string]bool, resultIndexes map[int]bool) bool {
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
		if p.Fun == ctor {
			return true
		}
		for _, arg := range p.Args {
			if arg == ctor {
				return true
			}
		}
		return true
	case *ast.SelectorExpr:
		if p.X == ctor {
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

func constructorHolderEscapes(body *ast.BlockStmt, parents map[ast.Node]ast.Node, holders []clientHolder, initializers map[*ast.Ident]bool, liveMethods, knownMembers map[string]bool, info *types.Info, emptyFunc func(string) bool) bool {
	escapes := false
	ast.Inspect(body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || escapes || initializers[id] || !isHolderUse(id, holders, info) {
			return !escapes
		}
		if call, ok := parents[id].(*ast.CallExpr); ok && localEmptyCallConsumes(body, call, id, emptyFunc) {
			return true
		}
		escapes = holderUseEscapes(id, parents[id], parents, liveMethods, knownMembers)
		return !escapes
	})
	return escapes
}

func holderUseEscapes(id *ast.Ident, parent ast.Node, parents map[ast.Node]ast.Node, liveMethods, knownMembers map[string]bool) bool {
	for ancestor := parent; ancestor != nil; ancestor = parents[ancestor] {
		if _, ok := ancestor.(*ast.FuncLit); ok {
			return true
		}
	}
	switch p := parent.(type) {
	case *ast.SelectorExpr:
		if p.X != id {
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
		return !comparedWithNil(p, id)
	case *ast.AssignStmt:
		for _, rhs := range p.Rhs {
			if rhs == id {
				discarded := len(p.Lhs) > 0
				for _, lhs := range p.Lhs {
					blank, ok := lhs.(*ast.Ident)
					discarded = discarded && ok && blank.Name == "_"
				}
				return !discarded
			}
		}
		return false
	case *ast.CallExpr:
		return true
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

func constructorResultHolders(body *ast.BlockStmt, ctor *ast.CallExpr, resultIndexes map[int]bool, info *types.Info) ([]clientHolder, map[*ast.Ident]bool) {
	var holders []clientHolder
	initializers := make(map[*ast.Ident]bool)
	add := func(id *ast.Ident) {
		if id == nil || id.Name == "_" {
			return
		}
		var obj types.Object
		if info != nil {
			obj = info.Defs[id]
			if obj == nil {
				obj = info.Uses[id]
			}
		}
		holders = append(holders, clientHolder{name: id.Name, obj: obj})
		initializers[id] = true
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch assign := n.(type) {
		case *ast.AssignStmt:
			if len(assign.Rhs) == 1 && containsASTNode(assign.Rhs[0], ctor) {
				for i, lhs := range assign.Lhs {
					if resultIndexes[i] {
						if id, ok := lhs.(*ast.Ident); ok {
							add(id)
						}
					}
				}
			}
		case *ast.ValueSpec:
			if len(assign.Values) == 1 && containsASTNode(assign.Values[0], ctor) {
				for i, id := range assign.Names {
					if resultIndexes[i] {
						add(id)
					}
				}
			}
		}
		return true
	})
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

func isHolderUse(id *ast.Ident, holders []clientHolder, info *types.Info) bool {
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
				return true
			}
			continue
		}
		if h.name == id.Name {
			return true
		}
	}
	return false
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
func liveMethodArgument(body *ast.BlockStmt, ctor *ast.CallExpr, methods map[string]bool, resultIndexes map[int]bool, urls map[string]string, isQualifier func(ast.Expr) bool, hostOf func(*ast.BasicLit) string, info *types.Info) string {
	call := liveMethodCall(body, ctor, methods, resultIndexes, info)
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
func callsLiveMethod(body *ast.BlockStmt, ctor *ast.CallExpr, methods map[string]bool, resultIndexes map[int]bool, info *types.Info) bool {
	return liveMethodCall(body, ctor, methods, resultIndexes, info) != nil
}

func liveMethodCall(body *ast.BlockStmt, ctor *ast.CallExpr, methods map[string]bool, resultIndexes map[int]bool, info *types.Info) *ast.CallExpr {
	holders, _ := constructorResultHolders(body, ctor, resultIndexes, info)
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
		case *ast.CallExpr:
			if x == ctor {
				found = call
			}
		case *ast.Ident:
			if isHolderUse(x, holders, info) {
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
// call can see it — in the test body or at the top of its package — followed
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
// pos can see.
func visibleBindings(body *ast.BlockStmt, pos token.Pos) map[string][]ast.Expr {
	bindings := map[string][]ast.Expr{}
	bindSpec := func(spec *ast.ValueSpec) {
		for i, name := range spec.Names {
			if i < len(spec.Values) {
				bindings[name.Name] = append(bindings[name.Name], spec.Values[i])
			}
		}
	}
	encloses := func(n ast.Node) bool { return n.Pos() <= pos && pos < n.End() }
	var blocks, funcs []ast.Node
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(blocks) > 0 && blocks[len(blocks)-1] == top {
				blocks = blocks[:len(blocks)-1]
			}
			if len(funcs) > 0 && funcs[len(funcs)-1] == top {
				funcs = funcs[:len(funcs)-1]
			}
			return true
		}
		stack = append(stack, n)
		switch n := n.(type) {
		case *ast.BlockStmt:
			blocks = append(blocks, n)
			if len(funcs) == 0 {
				funcs = append(funcs, n)
			}
		case *ast.FuncLit:
			funcs = append(funcs, n)
		case *ast.AssignStmt:
			if len(n.Lhs) != len(n.Rhs) {
				return true
			}
			scope := funcs[len(funcs)-1]
			if n.Tok == token.DEFINE {
				scope = blocks[len(blocks)-1]
			}
			if !encloses(scope) {
				return true
			}
			for i, lhs := range n.Lhs {
				if l, isIdent := lhs.(*ast.Ident); isIdent {
					bindings[l.Name] = append(bindings[l.Name], n.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			if encloses(blocks[len(blocks)-1]) {
				bindSpec(n)
			}
		}
		return true
	})
	return bindings
}
