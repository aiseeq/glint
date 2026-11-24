package qarules

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// selfExecIndex finds the bodies a call names: typed calls by their object,
// calls of a test file by name.
type selfExecIndex struct {
	// funcs and methods hold the typed functions by package path and name.
	funcs   map[string]map[string][]*selfExecBody
	methods map[string]map[string][]*selfExecBody
	// pkgNames holds the package name of each module package path.
	pkgNames map[string]string
	pkgOfDir map[string]string
	objects  map[*selfExecBody]*types.Func
	roots    []*selfExecBody
}

// selfExecTestPkg is the test package of a directory: the functions,
// methods and types of its test files, by name.
type selfExecTestPkg struct {
	dir, name string
	funcs     map[string][]*selfExecBody
	methods   map[string][]*selfExecBody
	types     map[string]bool
}

// internal reports a test package compiled with the package it tests.
func (tp *selfExecTestPkg) internal() bool { return !strings.HasSuffix(tp.name, "_test") }

func newSelfExecIndex(a *selfExecAnalysis) *selfExecIndex {
	idx := &selfExecIndex{
		funcs:    map[string]map[string][]*selfExecBody{},
		methods:  map[string]map[string][]*selfExecBody{},
		pkgNames: map[string]string{},
		pkgOfDir: map[string]string{},
		objects:  map[*selfExecBody]*types.Func{},
	}
	idx.addTyped(a)
	idx.addTests(a)
	return idx
}

func (idx *selfExecIndex) addTyped(a *selfExecAnalysis) {
	for _, pkgCtx := range a.ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		pkg := pkgCtx.Package
		idx.pkgNames[pkg.PkgPath] = pkg.Name
		for _, file := range pkg.GoFiles {
			idx.pkgOfDir[filepath.Dir(file)] = pkg.PkgPath
		}
		for _, file := range pkgCtx.Files {
			idx.pkgOfDir[filepath.Dir(file.Path)] = pkg.PkgPath
		}
		if level := selfExecPackageVars(pkg.Syntax, pkg.TypesInfo); level != nil {
			level.pkg, level.pkgName = pkg.PkgPath, pkg.Name
			a.pkgLevel = append(a.pkgLevel, level)
		}
	}
	for _, fn := range patternkit.OrderedFuncObjects(a.decls) {
		decl := a.decls[fn]
		if fn.Pkg() == nil {
			continue
		}
		b := &selfExecBody{decl: decl.Decl, info: decl.Info, pkg: fn.Pkg().Path(), pkgName: fn.Pkg().Name()}
		b.paramKeys()
		a.typed[fn] = b
		a.bodies = append(a.bodies, b)
		idx.objects[b] = fn
		byName := idx.funcs
		if fn.Signature().Recv() != nil {
			byName = idx.methods
		}
		if byName[b.pkg] == nil {
			byName[b.pkg] = map[string][]*selfExecBody{}
		}
		byName[b.pkg][fn.Name()] = append(byName[b.pkg][fn.Name()], b)
	}
}

// selfExecPackageVars returns a body holding the package variable
// declarations of a package, nil when it has none.
func selfExecPackageVars(files []*ast.File, info *types.Info) *selfExecBody {
	level := &selfExecBody{info: info, facts: &selfExecFacts{}}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				keys := make([]any, len(vs.Names))
				for i, name := range vs.Names {
					keys[i] = level.key(name)
				}
				if len(vs.Values) > 0 {
					level.facts.assigns = append(level.facts.assigns, selfExecAssign{lhs: keys, rhs: vs.Values})
				}
			}
		}
	}
	if len(level.facts.assigns) == 0 {
		return nil
	}
	return level
}

func (idx *selfExecIndex) addTests(a *selfExecAnalysis) {
	var files []*core.FileContext
	for _, file := range a.ctx.Files {
		if file != nil && file.GoAST != nil && file.GoTypesInfo == nil && strings.HasSuffix(file.Path, "_test.go") {
			files = append(files, file)
		}
	}
	slices.SortFunc(files, func(x, y *core.FileContext) int { return cmp.Compare(x.Path, y.Path) })
	pkgs := map[[2]string]*selfExecTestPkg{}
	for _, file := range files {
		key := [2]string{filepath.Dir(file.Path), file.GoAST.Name.Name}
		if pkgs[key] == nil {
			pkgs[key] = &selfExecTestPkg{dir: key[0], name: key[1], funcs: map[string][]*selfExecBody{}, methods: map[string][]*selfExecBody{}, types: map[string]bool{}}
		}
		idx.addTestFile(a, file.GoAST, pkgs[key])
	}
	protected := map[string]bool{}
	var roots []*selfExecBody
	for _, file := range files {
		tp := pkgs[[2]string{filepath.Dir(file.Path), file.GoAST.Name.Name}]
		testingPkgs := testingImportNames(file.GoAST)
		for _, b := range tp.funcs {
			for _, root := range b {
				if root.file != file.GoAST {
					continue
				}
				kind := goTestFuncKind(root.decl, testingPkgs)
				if kind == goTestMain && selfExecDispatches(root, tp) {
					protected[tp.dir] = true
				}
				if kind != goNotTest || selfExecRunExample(file.GoAST, root.decl) {
					roots = append(roots, root)
				}
			}
		}
	}
	for _, root := range roots {
		if !protected[root.tests.dir] {
			idx.roots = append(idx.roots, root)
		}
	}
	slices.SortFunc(idx.roots, func(x, y *selfExecBody) int {
		return cmp.Or(cmp.Compare(x.tests.dir, y.tests.dir), cmp.Compare(x.decl.Pos(), y.decl.Pos()))
	})
}

func (idx *selfExecIndex) addTestFile(a *selfExecAnalysis, file *ast.File, tp *selfExecTestPkg) {
	for _, decl := range file.Decls {
		switch node := decl.(type) {
		case *ast.FuncDecl:
			if node.Body == nil {
				continue
			}
			b := &selfExecBody{decl: node, file: file, tests: tp, pkgName: strings.TrimSuffix(tp.name, "_test")}
			b.paramKeys()
			a.bodies = append(a.bodies, b)
			if node.Recv != nil {
				tp.methods[node.Name.Name] = append(tp.methods[node.Name.Name], b)
			} else {
				tp.funcs[node.Name.Name] = append(tp.funcs[node.Name.Name], b)
			}
		case *ast.GenDecl:
			for _, spec := range node.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					tp.types[ts.Name.Name] = true
				}
			}
		}
	}
}

// selfExecRunExample reports an example go test runs: one with an output
// comment.
func selfExecRunExample(file *ast.File, fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Example") || fn.Type.Params.NumFields() > 0 || fn.Type.Results.NumFields() > 0 {
		return false
	}
	for _, group := range file.Comments {
		if group.Pos() < fn.Body.Pos() || group.End() > fn.Body.End() {
			continue
		}
		text := strings.ToLower(strings.TrimSpace(group.Text()))
		if strings.HasPrefix(text, "output:") || strings.HasPrefix(text, "unordered output:") {
			return true
		}
	}
	return false
}

// selfExecDispatches reports a TestMain that answers a child of the test
// binary before m.Run: a statement that reads the arguments or the
// environment, directly or through a function of the test files, and exits
// or returns on one of its branches.
func selfExecDispatches(main *selfExecBody, tp *selfExecTestPkg) bool {
	m := ""
	if params := main.decl.Type.Params.List; len(params) == 1 && len(params[0].Names) == 1 {
		m = params[0].Names[0].Name
	}
	for _, stmt := range main.decl.Body.List {
		if selfExecRunsSuite(stmt, m) {
			return false
		}
		header, branches := selfExecGuardParts(stmt)
		if len(header) > 0 && selfExecReadsChildMarker(main.file, header, tp, map[*ast.FuncDecl]bool{}) && selfExecTerminates(main.file, branches) {
			return true
		}
	}
	return false
}

// selfExecRunsSuite reports a statement that names m.Run.
func selfExecRunsSuite(stmt ast.Stmt, m string) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == m {
				found = true
			}
		}
		return !found
	})
	return found
}

// selfExecGuardParts splits a branching statement into the parts that decide
// the branch and the branches.
func selfExecGuardParts(stmt ast.Stmt) (header, branches []ast.Node) {
	switch node := stmt.(type) {
	case *ast.IfStmt:
		header = append(selfExecInit(node.Init), node.Cond)
		branches = []ast.Node{node.Body}
		if node.Else != nil {
			branches = append(branches, node.Else)
		}
	case *ast.RangeStmt:
		return []ast.Node{node.X}, []ast.Node{node.Body}
	case *ast.ForStmt:
		header = selfExecInit(node.Init)
		if node.Cond != nil {
			header = append(header, node.Cond)
		}
		return header, []ast.Node{node.Body}
	case *ast.SwitchStmt:
		header = selfExecInit(node.Init)
		if node.Tag != nil {
			header = append(header, node.Tag)
		}
		for _, item := range node.Body.List {
			clause, ok := item.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range clause.List {
				header = append(header, expr)
			}
			for _, body := range clause.Body {
				branches = append(branches, body)
			}
		}
	}
	return header, branches
}

// selfExecInit returns the init statement of a branching statement as a list.
func selfExecInit(init ast.Stmt) []ast.Node {
	if init == nil {
		return nil
	}
	return []ast.Node{init}
}

// selfExecChildMarkers lists what tells a child of the test binary: its
// arguments and its environment.
var selfExecChildMarkers = map[string]map[string]bool{
	"os":   {"Args": true, "Getenv": true, "LookupEnv": true, "Environ": true},
	"flag": {"Arg": true, "Args": true, "NArg": true},
}

func selfExecReadsChildMarker(file *ast.File, nodes []ast.Node, tp *selfExecTestPkg, seen map[*ast.FuncDecl]bool) bool {
	found := false
	for _, node := range nodes {
		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				for pkg, names := range selfExecChildMarkers {
					if names[x.Sel.Name] && selfExecMember(file, nil, x, pkg) {
						found = true
					}
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok {
					found = found || selfExecHelperReads(id.Name, tp, seen)
				}
			}
			return !found
		})
	}
	return found
}

// selfExecHelperReads reports a function of the test files that reads the
// arguments or the environment.
func selfExecHelperReads(name string, tp *selfExecTestPkg, seen map[*ast.FuncDecl]bool) bool {
	for _, helper := range tp.funcs[name] {
		if seen[helper.decl] {
			continue
		}
		seen[helper.decl] = true
		if selfExecReadsChildMarker(helper.file, []ast.Node{helper.decl.Body}, tp, seen) {
			return true
		}
	}
	return false
}

// selfExecTerminates reports branches that exit or return.
func selfExecTerminates(file *ast.File, branches []ast.Node) bool {
	found := false
	for _, branch := range branches {
		ast.Inspect(branch, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ReturnStmt:
				found = true
			case *ast.ExprStmt:
				found = found || patternkit.StmtNoReturn(x, nil, file) != patternkit.CallReturns
			}
			return !found
		})
	}
	return found
}

// resolve returns the bodies a call may run.
func (a *selfExecAnalysis) resolve(b *selfExecBody, call *ast.CallExpr) []*selfExecBody {
	if callees, ok := a.resolved[call]; ok {
		return callees
	}
	var callees []*selfExecBody
	if b.info != nil {
		if fn := patternkit.StaticFunc(b.info, call); fn != nil {
			if callee := a.typed[fn.Origin()]; callee != nil {
				callees = []*selfExecBody{callee}
			}
		}
	} else if b.tests != nil {
		callees = a.index.resolveTest(b, call)
	}
	a.resolved[call] = callees
	return callees
}

// resolveTest resolves a call of a test file by name: a function of the test
// package or, from an internal test, of the package under test; a function
// of an imported module package; a method by the type of its receiver where
// the test file tells it, by name otherwise.
func (idx *selfExecIndex) resolveTest(b *selfExecBody, call *ast.CallExpr) []*selfExecBody {
	tp := b.tests
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		if b.declares(fun.Name) {
			return nil
		}
		callees := slices.Clone(tp.funcs[fun.Name])
		if tp.internal() {
			callees = append(callees, idx.funcs[idx.pkgOfDir[tp.dir]][fun.Name]...)
		}
		return callees
	case *ast.SelectorExpr:
		if q, ok := fun.X.(*ast.Ident); ok && !b.declares(q.Name) {
			if importPath, ok := idx.importPath(b.file, q.Name); ok {
				return idx.funcs[importPath][fun.Sel.Name]
			}
		}
		return idx.methodCandidates(b, fun)
	}
	return nil
}

// declares reports whether a test file body declares a name - a parameter,
// a result, a variable, a function literal's parameter - that shadows a
// function or an import of the same name anywhere in the body.
func (b *selfExecBody) declares(name string) bool {
	if b.locals == nil {
		b.locals = map[string]bool{}
		fields := func(list *ast.FieldList) {
			if list == nil {
				return
			}
			for _, field := range list.List {
				for _, id := range field.Names {
					b.locals[id.Name] = true
				}
			}
		}
		fields(b.decl.Recv)
		fields(b.decl.Type.Params)
		fields(b.decl.Type.Results)
		ast.Inspect(b.decl.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if node.Tok == token.DEFINE {
					for _, lhs := range node.Lhs {
						if id, ok := lhs.(*ast.Ident); ok {
							b.locals[id.Name] = true
						}
					}
				}
			case *ast.RangeStmt:
				if node.Tok == token.DEFINE {
					for _, expr := range []ast.Expr{node.Key, node.Value} {
						if id, ok := expr.(*ast.Ident); ok {
							b.locals[id.Name] = true
						}
					}
				}
			case *ast.ValueSpec:
				for _, id := range node.Names {
					b.locals[id.Name] = true
				}
			case *ast.FuncType:
				fields(node.Params)
				fields(node.Results)
			}
			return true
		})
	}
	return b.locals[name]
}

// importPath resolves a qualifier through the imports of a file; a module
// package is named by its package name.
func (idx *selfExecIndex) importPath(file *ast.File, qualifier string) (string, bool) {
	for _, spec := range file.Imports {
		// The parser only accepts string literals here, quoted or raw.
		importPath := strings.Trim(spec.Path.Value, "\"`")
		name := path.Base(importPath)
		if pkgName, ok := idx.pkgNames[importPath]; ok {
			name = pkgName
		}
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == qualifier {
			return importPath, true
		}
	}
	return "", false
}

// selfExecRecvKind says what a test file tells of a receiver's type.
type selfExecRecvKind int

const (
	// The zero kind: the test file does not tell the type.
	_ selfExecRecvKind = iota
	// recvOutside: a type outside the module (testing.T, sync.WaitGroup).
	recvOutside
	recvModule
	recvTestLocal
)

type selfExecRecv struct {
	kind     selfExecRecvKind
	pkg, typ string
}

func (idx *selfExecIndex) methodCandidates(b *selfExecBody, sel *ast.SelectorExpr) []*selfExecBody {
	recv := idx.receiverType(b, sel.X)
	name := sel.Sel.Name
	switch recv.kind {
	case recvOutside:
		return nil
	case recvModule:
		return selfExecOfType(idx.methods[recv.pkg][name], recv.typ)
	case recvTestLocal:
		return selfExecOfType(b.tests.methods[name], recv.typ)
	}
	callees := slices.Clone(b.tests.methods[name])
	pkgs := []string{idx.pkgOfDir[b.tests.dir]}
	for _, spec := range b.file.Imports {
		if importPath, err := strconv.Unquote(spec.Path.Value); err == nil && importPath != pkgs[0] {
			pkgs = append(pkgs, importPath)
		}
	}
	for _, pkg := range pkgs {
		callees = append(callees, idx.methods[pkg][name]...)
	}
	return callees
}

// selfExecOfType keeps the methods declared on the named type.
func selfExecOfType(methods []*selfExecBody, typ string) []*selfExecBody {
	var kept []*selfExecBody
	for _, method := range methods {
		if patternkit.ReceiverTypeName(method.decl.Recv) == typ {
			kept = append(kept, method)
		}
	}
	return kept
}

// receiverType tells the type of a receiver expression of a test file from
// the declaration of the variable or the value it is built from.
func (idx *selfExecIndex) receiverType(b *selfExecBody, x ast.Expr) selfExecRecv {
	id, ok := ast.Unparen(x).(*ast.Ident)
	if !ok {
		return idx.valueType(b, x)
	}
	recv := selfExecRecv{}
	found := false
	ast.Inspect(b.decl, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.Field:
			if slices.ContainsFunc(node.Names, func(name *ast.Ident) bool { return name.Name == id.Name }) {
				recv, found = idx.typeExprType(b, node.Type), true
			}
		case *ast.ValueSpec:
			recv, found = idx.specType(b, node, id.Name)
		case *ast.AssignStmt:
			recv, found = idx.assignType(b, node, id.Name)
		}
		return !found
	})
	return recv
}

func (idx *selfExecIndex) specType(b *selfExecBody, spec *ast.ValueSpec, name string) (selfExecRecv, bool) {
	for i, n := range spec.Names {
		if n.Name != name {
			continue
		}
		if spec.Type != nil {
			return idx.typeExprType(b, spec.Type), true
		}
		if i < len(spec.Values) {
			return idx.valueType(b, spec.Values[i]), true
		}
		return selfExecRecv{}, true
	}
	return selfExecRecv{}, false
}

func (idx *selfExecIndex) assignType(b *selfExecBody, assign *ast.AssignStmt, name string) (selfExecRecv, bool) {
	if assign.Tok != token.DEFINE {
		return selfExecRecv{}, false
	}
	for i, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); !ok || id.Name != name {
			continue
		}
		if len(assign.Rhs) == len(assign.Lhs) {
			return idx.valueType(b, assign.Rhs[i]), true
		}
		if i == 0 && len(assign.Rhs) == 1 {
			return idx.valueType(b, assign.Rhs[0]), true
		}
		return selfExecRecv{}, true
	}
	return selfExecRecv{}, false
}

// valueType tells the type of a value: a composite literal, its address, a
// new, or the first result of a function the call resolves to.
func (idx *selfExecIndex) valueType(b *selfExecBody, value ast.Expr) selfExecRecv {
	switch node := ast.Unparen(value).(type) {
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			return idx.valueType(b, node.X)
		}
	case *ast.CompositeLit:
		if node.Type != nil {
			return idx.typeExprType(b, node.Type)
		}
	case *ast.CallExpr:
		if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "new" && len(node.Args) == 1 {
			return idx.typeExprType(b, node.Args[0])
		}
		return idx.resultType(b, node)
	}
	return selfExecRecv{}
}

// resultType tells the type of the first result of the function a call of a
// test file names, when the call names one function.
func (idx *selfExecIndex) resultType(b *selfExecBody, call *ast.CallExpr) selfExecRecv {
	callees := idx.resolveTest(b, call)
	if len(callees) != 1 {
		return selfExecRecv{}
	}
	callee := callees[0]
	if callee.info == nil {
		if results := callee.decl.Type.Results; results != nil && len(results.List) > 0 {
			return idx.typeExprType(callee, results.List[0].Type)
		}
		return selfExecRecv{}
	}
	fn := idx.objects[callee]
	if fn == nil || fn.Signature().Results().Len() == 0 {
		return selfExecRecv{}
	}
	t := fn.Signature().Results().At(0).Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return selfExecRecv{kind: recvOutside}
	}
	return idx.namedRecv(named.Obj().Pkg().Path(), named.Obj().Name())
}

func (idx *selfExecIndex) namedRecv(pkg, typ string) selfExecRecv {
	if _, ok := idx.pkgNames[pkg]; ok {
		return selfExecRecv{kind: recvModule, pkg: pkg, typ: typ}
	}
	return selfExecRecv{kind: recvOutside}
}

// typeExprType tells a type written in a test file.
func (idx *selfExecIndex) typeExprType(b *selfExecBody, expr ast.Expr) selfExecRecv {
	switch node := expr.(type) {
	case *ast.StarExpr:
		return idx.typeExprType(b, node.X)
	case *ast.IndexExpr:
		return idx.typeExprType(b, node.X)
	case *ast.IndexListExpr:
		return idx.typeExprType(b, node.X)
	case *ast.Ident:
		if b.tests.types[node.Name] {
			return selfExecRecv{kind: recvTestLocal, typ: node.Name}
		}
		if b.tests.internal() {
			return idx.namedRecv(idx.pkgOfDir[b.tests.dir], node.Name)
		}
		return selfExecRecv{}
	case *ast.SelectorExpr:
		if q, ok := node.X.(*ast.Ident); ok {
			if importPath, ok := idx.importPath(b.file, q.Name); ok {
				return idx.namedRecv(importPath, node.Sel.Name)
			}
		}
		return selfExecRecv{}
	}
	return selfExecRecv{kind: recvOutside}
}

// reached follows the calls from the tests of the module and returns the
// starts of the own executable on the way, each with the shortest chain
// from the first test that reaches it. A start of the own executable as the
// fallback of environment variables counts only from the tests that set
// none of them: the others start the binary the variable names.
func (a *selfExecAnalysis) reached() []selfExecFinding {
	findings, fallbacks := a.findingsFrom(a.index.roots, func(point selfExecPoint) bool { return len(point.env) == 0 })
	for _, key := range slices.Sorted(maps.Keys(fallbacks)) {
		env := strings.Split(key, "\x00")
		var roots []*selfExecBody
		for _, root := range a.index.roots {
			if !a.setsAnyEnv(root, env) {
				roots = append(roots, root)
			}
		}
		found, _ := a.findingsFrom(roots, func(point selfExecPoint) bool { return strings.Join(point.env, "\x00") == key })
		findings = append(findings, found...)
	}
	return findings
}

// findingsFrom returns the starts the roots reach that accept takes, and
// the environment variables of every start reached as their fallback.
func (a *selfExecAnalysis) findingsFrom(roots []*selfExecBody, accept func(selfExecPoint) bool) ([]selfExecFinding, map[string]bool) {
	order, parent := a.reach(roots)
	var findings []selfExecFinding
	fallbacks := map[string]bool{}
	seen := map[ast.Node]bool{}
	for _, node := range order {
		skipped := a.skipped(node)
		for _, point := range a.points(node.body) {
			if seen[point.call] || skipped(point.call) {
				continue
			}
			if len(point.env) > 0 {
				fallbacks[strings.Join(point.env, "\x00")] = true
			}
			if accept(point) {
				seen[point.call] = true
				findings = append(findings, selfExecFinding{point: point, chain: selfExecChain(node, parent)})
			}
		}
	}
	return findings, fallbacks
}

// reach returns the bodies the roots reach in breadth-first order, each
// with the names the calls give it (selfExecNode), and the node each was
// first reached from.
func (a *selfExecAnalysis) reach(roots []*selfExecBody) ([]selfExecNode, map[selfExecNode]selfExecNode) {
	parent := map[selfExecNode]selfExecNode{}
	seen := map[selfExecNode]bool{}
	contexts := map[*selfExecBody]int{}
	var queue []selfExecNode
	for _, root := range roots {
		node := selfExecNode{body: root}
		if !seen[node] {
			seen[node] = true
			queue = append(queue, node)
		}
	}
	var order []selfExecNode
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		order = append(order, node)
		skipped := a.skipped(node)
		for _, call := range a.facts(node.body).calls {
			if skipped(call) {
				continue
			}
			for _, callee := range a.resolve(node.body, call) {
				next := selfExecNode{body: callee, names: a.calleeNames(node, call, callee)}
				if next.names != "" && !seen[next] && contexts[callee] >= selfExecMaxContexts {
					next.names = ""
				}
				if !seen[next] {
					seen[next], parent[next] = true, node
					contexts[callee]++
					queue = append(queue, next)
				}
			}
		}
	}
	return order, parent
}

// setsAnyEnv reports whether a test sets one of the environment variables.
func (a *selfExecAnalysis) setsAnyEnv(root *selfExecBody, env []string) bool {
	sets := a.envSetBy(root)
	return slices.ContainsFunc(env, func(name string) bool { return sets[name] })
}

// envSetBy returns the environment variables a test body sets to a value
// other than "": t.Setenv or os.Setenv, in the body or in a function of the
// test files it calls.
func (a *selfExecAnalysis) envSetBy(b *selfExecBody) map[string]bool {
	if sets, ok := a.setsEnv[b]; ok {
		return sets
	}
	sets := map[string]bool{}
	a.setsEnv[b] = sets
	for _, call := range a.facts(b).calls {
		if name, ok := selfExecSetenv(b, call); ok {
			sets[name] = true
		}
		for _, callee := range a.resolve(b, call) {
			if callee.tests != nil {
				maps.Copy(sets, a.envSetBy(callee))
			}
		}
	}
	return sets
}

// selfExecSetenv returns the variable a Setenv call sets to a value other
// than "".
func selfExecSetenv(b *selfExecBody, call *ast.CallExpr) (string, bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Setenv" || len(call.Args) != 2 {
		return "", false
	}
	if value, ok := selfExecString(b, call.Args[1]); ok && value == "" {
		return "", false
	}
	return selfExecString(b, call.Args[0])
}

func selfExecChain(node selfExecNode, parent map[selfExecNode]selfExecNode) []string {
	bodies := []*selfExecBody{node.body}
	for cur, ok := parent[node]; ok; cur, ok = parent[cur] {
		bodies = append(bodies, cur.body)
	}
	slices.Reverse(bodies)
	chain := make([]string, len(bodies))
	for i, body := range bodies {
		var prev *selfExecBody
		if i > 0 {
			prev = bodies[i-1]
		}
		chain[i] = body.name(prev)
	}
	return chain
}
