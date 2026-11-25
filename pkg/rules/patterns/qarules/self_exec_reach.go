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
	pkgTypes map[string]*types.Package
	// rootsOf holds the functions go test runs, by the directory of their
	// test binary; kinds their kind and mains the TestMain of a directory.
	rootsOf map[string][]*selfExecBody
	kinds   map[*selfExecBody]goTestKind
	mains   map[string]*selfExecBody
	// typing holds the names whose type is being told, against a cycle.
	typing map[*ast.Ident]bool
}

// selfExecTestPkg is the test package of a directory: the functions,
// methods and types of its test files, by name.
type selfExecTestPkg struct {
	dir, name string
	funcs     map[string][]*selfExecBody
	methods   map[string][]*selfExecBody
	types     map[string]bool
	// consts holds the values of the constants of the test files, vars the
	// names of their package variables.
	consts map[string]ast.Expr
	vars   map[string]bool
	idx    *selfExecIndex
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
		pkgTypes: map[string]*types.Package{},
		rootsOf:  map[string][]*selfExecBody{},
		kinds:    map[*selfExecBody]goTestKind{},
		mains:    map[string]*selfExecBody{},
		typing:   map[*ast.Ident]bool{},
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
		idx.pkgTypes[pkg.PkgPath] = pkg.Types
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
			pkgs[key] = &selfExecTestPkg{dir: key[0], name: key[1], funcs: map[string][]*selfExecBody{}, methods: map[string][]*selfExecBody{},
				types: map[string]bool{}, consts: map[string]ast.Expr{}, vars: map[string]bool{}, idx: idx}
		}
		idx.addTestFile(a, file.GoAST, pkgs[key])
	}
	for _, file := range files {
		tp := pkgs[[2]string{filepath.Dir(file.Path), file.GoAST.Name.Name}]
		testingPkgs := testingImportNames(file.GoAST)
		for _, b := range tp.funcs {
			for _, root := range b {
				if root.file != file.GoAST {
					continue
				}
				kind := goTestFuncKind(root.decl, testingPkgs)
				if kind == goNotTest && selfExecRunExample(file.GoAST, root.decl) {
					kind = goTestCase
				}
				if kind == goNotTest {
					continue
				}
				idx.kinds[root] = kind
				idx.rootsOf[tp.dir] = append(idx.rootsOf[tp.dir], root)
				if kind == goTestMain {
					idx.mains[tp.dir] = root
				}
			}
		}
	}
	for dir, roots := range idx.rootsOf {
		slices.SortFunc(roots, func(x, y *selfExecBody) int {
			return cmp.Or(cmp.Compare(x.file.Name.Pos(), y.file.Name.Pos()), cmp.Compare(x.decl.Pos(), y.decl.Pos()))
		})
		idx.rootsOf[dir] = roots
	}
}

func (idx *selfExecIndex) addTestFile(a *selfExecAnalysis, file *ast.File, tp *selfExecTestPkg) {
	level := &selfExecBody{file: file, tests: tp, pkgName: strings.TrimSuffix(tp.name, "_test"), facts: &selfExecFacts{}, testLevel: true}
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
			idx.addTestDecl(tp, level, node)
		}
	}
	if len(level.facts.assigns) > 0 {
		a.pkgLevel = append(a.pkgLevel, level)
	}
}

// addTestDecl records the types, the string constants and the package
// variables of a test file.
func (idx *selfExecIndex) addTestDecl(tp *selfExecTestPkg, level *selfExecBody, decl *ast.GenDecl) {
	for _, spec := range decl.Specs {
		switch node := spec.(type) {
		case *ast.TypeSpec:
			tp.types[node.Name.Name] = true
		case *ast.ValueSpec:
			keys := make([]any, len(node.Names))
			for i, name := range node.Names {
				keys[i] = name.Name
				switch {
				case decl.Tok == token.CONST && i < len(node.Values):
					tp.consts[name.Name] = node.Values[i]
				case decl.Tok == token.VAR:
					tp.vars[name.Name] = true
				}
			}
			if decl.Tok == token.VAR && len(node.Values) > 0 {
				level.facts.assigns = append(level.facts.assigns, selfExecAssign{lhs: keys, rhs: node.Values})
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

// selfExecRunsSuite reports a statement that names m.Run.
func selfExecRunsSuite(stmt ast.Node, m string) bool {
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
		if b.declaresAt(fun.Name, fun.Pos()) {
			return nil
		}
		callees := slices.Clone(tp.funcs[fun.Name])
		if tp.internal() {
			callees = append(callees, idx.funcs[idx.pkgOfDir[tp.dir]][fun.Name]...)
		}
		return callees
	case *ast.SelectorExpr:
		if q, ok := fun.X.(*ast.Ident); ok && !b.declaresAt(q.Name, q.Pos()) {
			if importPath, ok := idx.importPath(b.file, q.Name); ok {
				return idx.funcs[importPath][fun.Sel.Name]
			}
		}
		return idx.methodCandidates(b, fun)
	}
	return nil
}

// selfExecLocal is a name a test file body declares, with the declaration -
// a field, a value spec, an assignment or a range statement - and the span
// of its scope.
type selfExecLocal struct {
	name     string
	decl     ast.Node
	from, to token.Pos
	// konst marks a constant.
	konst bool
}

// declaresAt reports whether a test file body declares a name - a
// parameter, a result, a variable, a function literal's parameter - whose
// scope holds the position: there it shadows a function, an import or a
// package variable of the same name.
func (b *selfExecBody) declaresAt(name string, pos token.Pos) bool {
	return b.localAt(name, pos) != nil
}

// localAt returns the innermost declaration of a name whose scope holds the
// position, nil when the name is not local there.
func (b *selfExecBody) localAt(name string, pos token.Pos) *selfExecLocal {
	// The package variables of a test file have no function around them.
	if b.decl == nil {
		return nil
	}
	var found *selfExecLocal
	for i := range b.scopes() {
		local := &b.locals[i]
		if local.name == name && local.from <= pos && pos < local.to && (found == nil || local.from > found.from) {
			found = local
		}
	}
	return found
}

// scopes lists the declarations of a test file body with their scopes,
// found on first use: a variable is in scope from the end of its
// declaration to the end of the innermost block or statement around it.
func (b *selfExecBody) scopes() []selfExecLocal {
	if b.locals != nil {
		return b.locals
	}
	b.locals = []selfExecLocal{}
	if b.decl == nil {
		return b.locals
	}
	fields := func(list *ast.FieldList, scope ast.Node) {
		if list == nil || scope == nil {
			return
		}
		for _, field := range list.List {
			for _, id := range field.Names {
				b.locals = append(b.locals, selfExecLocal{name: id.Name, decl: field, from: scope.Pos(), to: scope.End()})
			}
		}
	}
	fields(b.decl.Recv, b.decl.Body)
	fields(b.decl.Type.Params, b.decl.Body)
	fields(b.decl.Type.Results, b.decl.Body)
	var stack []ast.Node
	scopeEnd := func() token.Pos {
		for i := len(stack) - 1; i >= 0; i-- {
			switch stack[i].(type) {
			case *ast.BlockStmt, *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt,
				*ast.TypeSwitchStmt, *ast.CaseClause, *ast.CommClause:
				return stack[i].End()
			}
		}
		return b.decl.Body.End()
	}
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						b.locals = append(b.locals, selfExecLocal{name: id.Name, decl: node, from: node.End(), to: scopeEnd()})
					}
				}
			}
		case *ast.RangeStmt:
			if node.Tok == token.DEFINE {
				for _, expr := range []ast.Expr{node.Key, node.Value} {
					if id, ok := expr.(*ast.Ident); ok {
						b.locals = append(b.locals, selfExecLocal{name: id.Name, decl: node, from: node.Body.Pos(), to: node.Body.End()})
					}
				}
			}
		case *ast.ValueSpec:
			decl, _ := stack[len(stack)-1].(*ast.GenDecl)
			for _, id := range node.Names {
				b.locals = append(b.locals, selfExecLocal{name: id.Name, decl: node, from: node.End(), to: scopeEnd(), konst: decl != nil && decl.Tok == token.CONST})
			}
		case *ast.FuncLit:
			fields(node.Type.Params, node.Body)
			fields(node.Type.Results, node.Body)
		}
		stack = append(stack, n)
		return true
	})
	return b.locals
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
//
// A name is resolved by the declaration in scope at its use, and a use is
// followed once at a time: the value a declaration is built from cannot
// lead back to the same use, and the guard keeps a mistake there from
// recursing without end.
func (idx *selfExecIndex) receiverType(b *selfExecBody, x ast.Expr) selfExecRecv {
	id, ok := ast.Unparen(x).(*ast.Ident)
	if !ok {
		return idx.valueType(b, x)
	}
	if idx.typing[id] {
		return selfExecRecv{}
	}
	idx.typing[id] = true
	defer delete(idx.typing, id)
	local := b.localAt(id.Name, id.Pos())
	if local == nil {
		return selfExecRecv{}
	}
	switch node := local.decl.(type) {
	case *ast.Field:
		return idx.typeExprType(b, node.Type)
	case *ast.ValueSpec:
		recv, _ := idx.specType(b, node, id.Name)
		return recv
	case *ast.AssignStmt:
		recv, _ := idx.assignType(b, node, id.Name)
		return recv
	}
	return selfExecRecv{}
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

// reached follows the calls from the tests of the module, the test binary
// of each directory apart, and returns the starts of the own executable on
// the way that nothing proves safe, each with the chain from the test.
func (a *selfExecAnalysis) reached() []*selfExecFinding {
	a.relevantBodies()
	for _, dir := range slices.Sorted(maps.Keys(a.index.rootsOf)) {
		// What TestMain sets before m.Run is set for the tests, not for
		// TestMain itself, which may start a child before it sets it.
		main := a.index.mains[dir]
		tests := slices.DeleteFunc(slices.Clone(a.index.rootsOf[dir]), func(root *selfExecBody) bool { return root == main })
		a.explore(dir, tests, "", a.labelSet(a.mainSets(dir)))
		if main != nil {
			a.explore(dir, []*selfExecBody{main}, "", "")
		}
	}
	return a.findings
}

const (
	selfExecRunning = iota + 1
	selfExecDone
)

// selfExecHelperKey is a start whose child is followed in a run of a test
// binary: a helper, or a child the TestMain or an init answers.
type selfExecHelperKey struct {
	call     ast.Node
	dir      string
	run      string
	answered bool
}

// explore follows the calls from roots in a run of the test binary of a
// directory, with the labels set on the way, and checks each start it
// meets.
func (a *selfExecAnalysis) explore(dir string, roots []*selfExecBody, mode, covered string) {
	parent := map[selfExecNode]selfExecNode{}
	seen := map[selfExecNode]bool{}
	type context struct {
		body *selfExecBody
		mode string
	}
	contexts := map[context]int{}
	// modes holds the runs each body is followed in: past
	// selfExecMaxContexts a body is followed in the run the walk starts
	// in, without what the guards on the way tell, as the guards of a
	// chain of functions would double the runs at each step.
	modes := map[*selfExecBody]map[string]bool{}
	var queue []selfExecNode
	for _, root := range roots {
		node := selfExecNode{body: root, mode: mode, covered: covered}
		if a.relevant[root] && !seen[node] {
			seen[node] = true
			queue = append(queue, node)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		skipped := a.skipped(node)
		for _, point := range a.points(node.body) {
			if !skipped(point.call) {
				a.check(dir, node, point, parent)
			}
		}
		for _, call := range a.facts(node.body).calls {
			if skipped(call) {
				continue
			}
			for _, callee := range a.resolve(node.body, call) {
				if !a.relevant[callee] {
					continue
				}
				next := selfExecNode{body: callee, names: a.calleeNames(node, call, callee), mode: a.guardedRun(node.body, node.mode, call.Pos()), covered: a.coveredAt(node, call.Pos())}
				if modes[callee] == nil {
					modes[callee] = map[string]bool{}
				}
				if !modes[callee][next.mode] && len(modes[callee]) >= selfExecMaxContexts {
					next.mode = mode
				}
				modes[callee][next.mode] = true
				at := context{callee, next.mode}
				if !seen[next] && contexts[at] >= selfExecMaxContexts {
					next.names = ""
				}
				if !seen[next] && contexts[at] >= 4*selfExecMaxContexts {
					next.covered = ""
				}
				if !seen[next] {
					seen[next], parent[next] = true, node
					contexts[at]++
					queue = append(queue, next)
				}
			}
		}
	}
}

// check reports a start a node reaches unless it is proven safe there: the
// path sets what it falls back from, the TestMain answers the child it
// starts, or it starts a helper whose child does not start it again.
func (a *selfExecAnalysis) check(dir string, node selfExecNode, point *selfExecPoint, parent map[selfExecNode]selfExecNode) {
	if a.reported[point.call] {
		return
	}
	if len(point.env) > 0 {
		covered := strings.Split(a.coveredAt(node, point.call.Pos()), "\x00")
		if slices.ContainsFunc(point.env, func(label string) bool { return slices.Contains(covered, label) }) {
			return
		}
	}
	unbind := a.bind(node.body, selfExecNames(node.names))
	run := a.childRun(a.run(node.mode), point)
	pattern, known, helper := a.helperPattern(point)
	unbind()
	// The child the TestMain or an init answers runs them up to the answer:
	// a start on the way is followed like any other.
	if a.answered(dir, run) {
		roots := a.inits(dir)
		if main := a.index.mains[dir]; main != nil {
			roots = append(roots, main)
		}
		if a.followChild(selfExecHelperKey{point.call, dir, run.key(), true}, roots, run) {
			return
		}
	} else if helper && a.followChild(selfExecHelperKey{point.call, dir, run.key(), false}, a.childRoots(dir, pattern, known), run) {
		return
	}
	a.reported[point.call] = true
	a.findings = append(a.findings, &selfExecFinding{point: point, chain: selfExecChain(node, parent)})
}

// followChild follows the child of a start from the roots it runs, once
// per start and run; it reports false for a start reached again in its own
// child, where each child starts the next.
func (a *selfExecAnalysis) followChild(key selfExecHelperKey, roots []*selfExecBody, run *selfExecRun) bool {
	switch a.helpers[key] {
	case selfExecDone:
		return true
	case selfExecRunning:
		return false
	}
	a.helpers[key] = selfExecRunning
	// What TestMain sets before m.Run is set for the tests of a helper, not
	// on the way to an answer, which may leave before it.
	sets := selfExecRunSets(run)
	if !key.answered {
		sets = selfExecUnion(a.mainSets(key.dir), sets)
	}
	covered := a.labelSet(sets)
	a.explore(key.dir, roots, key.run, covered)
	a.helpers[key] = selfExecDone
	return true
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
