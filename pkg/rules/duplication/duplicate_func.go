package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"golang.org/x/tools/go/packages"
)

func init() { rules.Register(NewDuplicateFuncAcrossPackagesRule()) }

// DuplicateFuncAcrossPackagesRule detects helpers copied between packages,
// either under the same name and signature or with an identical normalized
// body under another name:
//
//	// poller/poller.go
//	func withContextCause(ctx context.Context, err error) error { ... }
//
//	// sender/sender.go
//	func withContextCause(ctx context.Context, err error) error { ... }
//
// The copies are short and differ in details, so cross-file-duplicate does
// not see them; a fix lands in one and the other goes on without it. The
// signature prints types with full package paths, so a function over the
// package's own type (newStore returning its own *store) never matches its
// namesake. A one-word name (run, handle, parse) is a role every package
// fills its own way, a function without parameters is a constant in
// disguise, and a wrapper whose body only calls a function of another
// package already shares the implementation; test files and mock packages
// are left out.
type DuplicateFuncAcrossPackagesRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewDuplicateFuncAcrossPackagesRule creates the rule
func NewDuplicateFuncAcrossPackagesRule() *DuplicateFuncAcrossPackagesRule {
	return &DuplicateFuncAcrossPackagesRule{BaseRule: rules.NewBaseRule(
		"duplicate-func-across-packages",
		"duplication",
		"Detects helper functions copied between packages — two copies of one implementation that can drift apart",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the copies live in different packages.
func (r *DuplicateFuncAcrossPackagesRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DuplicateFuncAcrossPackagesRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports each copy of a helper duplicated across packages.
func (r *DuplicateFuncAcrossPackagesRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("duplicate func across packages: nil Go project context")
	}
	byKey, byBody, err := indexDuplicateFuncs(ctx)
	if err != nil {
		return nil, err
	}
	graph := newImportGraph(ctx)
	twins := keyedTwins(byKey, graph)
	maps.Copy(twins, bodyTwins(byBody, graph))
	if len(twins) == 0 {
		return nil, nil
	}
	return r.findings(ctx, twins)
}

func indexDuplicateFuncs(ctx *core.GoProjectContext) (map[string][]*types.Func, map[string][]*types.Func, error) {
	byKey := make(map[string][]*types.Func)
	byBody := make(map[string][]*types.Func)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, nil, errors.New("duplicate func across packages: package has no typed syntax")
		}
		if testDoublePackage(pkg.Package.PkgPath) {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() || file.IsGenerated() {
				continue
			}
			decls := make(map[*types.Func]*ast.FuncDecl)
			helpers.IndexFuncDecls(decls, file.GoAST, pkg.Package.TypesInfo)
			// Another module of the repository cannot call the original
			// without a new module dependency: copies match within a module.
			module := moduleOf(pkg.Package) + "\x00"
			for _, fn := range helperFuncs(file.GoAST, pkg.Package.TypesInfo) {
				key := module + helperKey(fn)
				byKey[key] = append(byKey[key], fn)
			}
			for _, fn := range bodyFuncs(file.GoAST, pkg.Package.TypesInfo) {
				fd := decls[fn]
				if fd == nil {
					continue
				}
				normalizer := newFunctionBlockNormalizer(pkg.Package.TypesInfo, fd)
				normalizer.walk(fd.Body)
				if normalizer.nodes < minimumDuplicateBodyNodes {
					continue
				}
				key := module + normalizer.b.String()
				byBody[key] = append(byBody[key], fn)
			}
		}
	}
	return byKey, byBody, nil
}

type duplicateFuncTwin struct {
	original string
	canCall  bool
	// unexported marks an original the copy can call only once exported.
	unexported bool
}

func keyedTwins(byKey map[string][]*types.Func, graph *importGraph) map[*types.Func]duplicateFuncTwin {
	twins := make(map[*types.Func]duplicateFuncTwin)
	keys := slices.Sorted(maps.Keys(byKey))
	for _, key := range keys {
		// One copy per package: the twin is always another package.
		copies := uniquePackageFuncs(byKey[key])
		if len(copies) < 2 {
			continue
		}
		sort.Slice(copies, func(i, j int) bool { return originalFuncLess(copies[i], copies[j]) })
		// Named helpers are unexported by selection, so calling across needs
		// an export, and only a package every copy can import may keep it:
		// that package is the twin of every other copy and is not reported.
		kept := slices.IndexFunc(copies, func(c *types.Func) bool { return graph.importedByAll(c.Pkg(), copies) })
		if kept >= 0 {
			for i, c := range copies {
				if i != kept {
					twins[c] = duplicateFuncTwin{original: copies[kept].Pkg().Path(), canCall: true, unexported: true}
				}
			}
			continue
		}
		// No package can keep it: the first copy is the twin of every other
		// copy, and the second is the twin of the first.
		for i, c := range copies {
			twin := copies[0].Pkg()
			if i == 0 {
				twin = copies[1].Pkg()
			}
			twins[c] = duplicateFuncTwin{original: twin.Path(), unexported: true}
		}
	}
	return twins
}

func bodyTwins(byBody map[string][]*types.Func, graph *importGraph) map[*types.Func]duplicateFuncTwin {
	twins := make(map[*types.Func]duplicateFuncTwin)
	bodyKeys := slices.Sorted(maps.Keys(byBody))
	for _, key := range bodyKeys {
		copies := uniquePackageFuncs(byBody[key])
		if len(copies) < 2 {
			continue
		}
		sort.Slice(copies, func(i, j int) bool { return originalFuncLess(copies[i], copies[j]) })
		original, canCall := copies[0], false
		for _, candidate := range copies {
			if graph.importedByAll(candidate.Pkg(), copies) {
				original, canCall = candidate, true
				break
			}
		}
		for _, copyFn := range copies {
			twin := original
			if copyFn == original {
				// A kept copy is not reported; with none to keep the first
				// copy is reported too, against the second.
				if canCall {
					continue
				}
				twin = copies[1]
			}
			twins[copyFn] = duplicateFuncTwin{
				original:   fmt.Sprintf("%s.%s", twin.Pkg().Path(), twin.Name()),
				canCall:    canCall,
				unexported: !twin.Exported(),
			}
		}
	}
	return twins
}

// importGraph answers whether a package reaches another through imports. A
// package that reaches a copy's package cannot keep the implementation: the
// copy importing it back would close a cycle. go vet and go test build each
// package with its in-package tests, so the test of any package the candidate
// reaches closes the cycle too when it imports the copy: those test files are
// read from disk for their imports, which the load without tests leaves out.
// A package whose tests cannot be read keeps no implementation either: what
// they import is unknown.
type importGraph struct {
	imports *importReach
	// known holds the loaded packages and every package they import.
	known    map[string]*packages.Package
	closures map[string]map[string]bool
	tests    map[string]testImportList
	reached  map[string]cycleReach
}

type testImportList struct {
	paths []string
	err   error
}

type cycleReach struct {
	paths map[string]bool
	// unread is set when the tests of a package on the way could not be read.
	unread bool
}

func newImportGraph(ctx *core.GoProjectContext) *importGraph {
	graph := &importGraph{
		imports:  newImportReach(ctx),
		known:    map[string]*packages.Package{},
		closures: map[string]map[string]bool{},
		tests:    map[string]testImportList{},
		reached:  map[string]cycleReach{},
	}
	var index func(pkg *packages.Package)
	index = func(pkg *packages.Package) {
		if pkg == nil || graph.known[pkg.PkgPath] != nil {
			return
		}
		graph.known[pkg.PkgPath] = pkg
		for _, dep := range pkg.Imports {
			index(dep)
		}
	}
	for _, pkg := range graph.imports.byPath {
		index(pkg)
	}
	return graph
}

func (g *importGraph) importedByAll(candidate *types.Package, copies []*types.Func) bool {
	if candidate == nil || candidate.Name() == "main" {
		return false
	}
	reach := g.reaches(candidate.Path())
	if reach.unread {
		return false
	}
	for _, copyFn := range copies {
		if copyFn.Pkg() == candidate {
			continue
		}
		if !packageImportableFrom(copyFn.Pkg().Path(), candidate.Path()) || reach.paths[copyFn.Pkg().Path()] {
			return false
		}
	}
	return true
}

// reaches returns the import paths a new import of from would close a cycle
// with: those from imports, directly or through other packages, and those the
// in-package tests of from or of a package it reaches import, directly or
// through other packages.
func (g *importGraph) reaches(from string) cycleReach {
	if reach, ok := g.reached[from]; ok {
		return reach
	}
	closure := g.closure(from)
	reach := cycleReach{paths: make(map[string]bool, len(closure))}
	addTests := func(path string) {
		tests := g.testImports(path)
		if tests.err != nil {
			reach.unread = true
			return
		}
		for _, imported := range tests.paths {
			reach.paths[imported] = true
			maps.Copy(reach.paths, g.closure(imported))
		}
	}
	addTests(from)
	for path := range closure {
		reach.paths[path] = true
		addTests(path)
	}
	g.reached[from] = reach
	return reach
}

// closure returns the loaded packages (the copies are among them) a loaded
// package or a dependency of one reaches through imports. A package only tests import is not loaded, so what
// it imports is not seen: a module that depends back on this one through such
// a package is out of reach.
func (g *importGraph) closure(path string) map[string]bool {
	if closure, ok := g.closures[path]; ok {
		return closure
	}
	var closure map[string]bool
	if pkg := g.known[path]; pkg != nil {
		closure = map[string]bool{}
		for reached := range g.imports.imports(pkg) {
			if g.imports.byPath[reached] != nil {
				closure[reached] = true
			}
		}
	}
	g.closures[path] = closure
	return closure
}

// testImports lists the imports of the in-package test files (package p, not
// p_test) of a package of the project, once per package.
func (g *importGraph) testImports(path string) testImportList {
	if tests, ok := g.tests[path]; ok {
		return tests
	}
	var tests testImportList
	if pkg := g.imports.byPath[path]; pkg != nil && len(pkg.GoFiles) > 0 {
		tests.paths, tests.err = readTestImports(filepath.Dir(pkg.GoFiles[0]), pkg.Name)
	}
	g.tests[path] = tests
	return tests
}

func readTestImports(dir, pkgName string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list tests of %s: %w", dir, err)
	}
	var paths []string
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") || strings.HasPrefix(entry.Name(), "_") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			return nil, fmt.Errorf("read imports of %s: %w", entry.Name(), err)
		}
		if file.Name.Name != pkgName {
			continue
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, fmt.Errorf("import path %s in %s: %w", spec.Path.Value, entry.Name(), err)
			}
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func packageImportableFrom(importerPath, importedPath string) bool {
	internalAt := strings.LastIndex(importedPath+"/", "/internal/")
	if internalAt < 0 {
		return true
	}
	parent := importedPath[:internalAt]
	return importerPath == parent || strings.HasPrefix(importerPath, parent+"/")
}

func (r *DuplicateFuncAcrossPackagesRule) findings(ctx *core.GoProjectContext, twins map[*types.Func]duplicateFuncTwin) ([]*core.Violation, error) {
	return rules.AnalyzeTypedRunFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fn, ok := info.Defs[fd.Name].(*types.Func)
			twin, hasTwin := twins[fn]
			if !ok || !hasTwin {
				continue
			}
			line := file.LineFor(fd)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			advice := "keep one implementation and call it from both packages"
			suggestion := "Keep one implementation and call it from both places; when neither package should import the other, move it to a shared package, and when the standard library already does it, call that instead"
			switch {
			case !twin.canCall:
				advice = "move one implementation into a package both can import"
				suggestion = "Move the shared implementation into a package both packages can import"
			case twin.unexported:
				advice = "keep one implementation, export it and call it from both packages"
			}
			message := fmt.Sprintf("Function %s duplicates %s — %s", fd.Name.Name, twin.original, advice)
			v := r.CreateViolation(file.RelPath, line, message)
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion(suggestion)
			violations = append(violations, v)
		}
		return violations
	})
}

// minimumDuplicateBodyNodes excludes accessors and one-call wrappers, whose
// matching is common by design; 20 normalized AST nodes retains the request
// predicate probe while excluding those idioms.
const minimumDuplicateBodyNodes = 20

func bodyFuncs(file *ast.File, info *types.Info) []*types.Func {
	var out []*types.Func
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || !IsDuplicateFuncBodyCandidate(fd, info) {
			continue
		}
		fn, ok := info.Defs[fd.Name].(*types.Func)
		if !ok || fn.Signature().Params().Len() == 0 {
			continue
		}
		out = append(out, fn)
	}
	return out
}

// IsDuplicateFuncBodyCandidate reports whether a function declaration meets
// the body rule's receiver, parameter, delegation, and normalized-size filters.
// It uses the declaration AST directly so file rules can share the same gate.
func IsDuplicateFuncBodyCandidate(fd *ast.FuncDecl, info *types.Info) bool {
	if fd == nil || fd.Recv != nil || fd.Body == nil || fd.Name == nil || fd.Type == nil || fd.Type.Params == nil || fd.Type.Params.NumFields() == 0 {
		return false
	}
	if info == nil || delegates(fd.Body, info, funcPackage(fd, info)) {
		return false
	}
	normalizer := newFunctionBlockNormalizer(info, fd)
	normalizer.walk(fd.Body)
	return normalizer.nodes >= minimumDuplicateBodyNodes
}

// DelegateCallee returns the function or method of another package that the
// body of fd only calls, or nil when the body does more than that one call,
// and the name the call is qualified by (an import alias, a variable), if any.
func DelegateCallee(fd *ast.FuncDecl, info *types.Info) (*types.Func, string) {
	if fd == nil || fd.Body == nil || fd.Name == nil || info == nil {
		return nil, ""
	}
	return delegateCallee(fd.Body, info, funcPackage(fd, info))
}

func funcPackage(fd *ast.FuncDecl, info *types.Info) *types.Package {
	if fn, ok := info.Defs[fd.Name].(*types.Func); ok {
		return fn.Pkg()
	}
	return nil
}

func uniquePackageFuncs(funcs []*types.Func) []*types.Func {
	sort.Slice(funcs, func(i, j int) bool {
		if funcs[i].Pkg().Path() != funcs[j].Pkg().Path() {
			return funcs[i].Pkg().Path() < funcs[j].Pkg().Path()
		}
		return funcs[i].Name() < funcs[j].Name()
	})
	seen := make(map[*types.Package]bool)
	out := funcs[:0]
	for _, fn := range funcs {
		if fn == nil || fn.Pkg() == nil || seen[fn.Pkg()] {
			continue
		}
		seen[fn.Pkg()] = true
		out = append(out, fn)
	}
	return out
}

func originalFuncLess(a, b *types.Func) bool {
	if ast.IsExported(a.Name()) != ast.IsExported(b.Name()) {
		return ast.IsExported(a.Name())
	}
	if a.Pkg().Path() != b.Pkg().Path() {
		return a.Pkg().Path() < b.Pkg().Path()
	}
	return a.Name() < b.Name()
}

// helperFuncs returns named unexported package-level helpers used by the
// signature-based index.
func helperFuncs(file *ast.File, info *types.Info) []*types.Func {
	var out []*types.Func
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Body == nil || ast.IsExported(fd.Name.Name) {
			continue
		}
		if len(helpers.IdentifierWords(fd.Name.Name)) < 2 {
			continue
		}
		fn, ok := info.Defs[fd.Name].(*types.Func)
		if !ok || fn.Signature().Params().Len() == 0 || delegates(fd.Body, info, fn.Pkg()) {
			continue
		}
		out = append(out, fn)
	}
	return out
}

// helperKey is name|signature with types printed by full package path, so
// the same parameter imported under two names gives one key.
func helperKey(fn *types.Func) string {
	return fn.Name() + "|" + types.TypeString(fn.Signature(), nil)
}

// passesFuncLit reports a call given a function literal: the logic sits in
// the literal, and the call only runs it.
func passesFuncLit(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if _, ok := ast.Unparen(arg).(*ast.FuncLit); ok {
			return true
		}
	}
	return false
}

// delegates reports a body of one statement that only calls a function or
// method of another package: the implementation is already shared.
// A call given a function literal is not shared: the literal is.
func delegates(body *ast.BlockStmt, info *types.Info, own *types.Package) bool {
	if call := soleCall(body); call == nil || passesFuncLit(call) {
		return false
	}
	callee, _ := delegateCallee(body, info, own)
	return callee != nil
}

// soleCall returns the call a body of one statement makes, or nil.
func soleCall(body *ast.BlockStmt) *ast.CallExpr {
	if len(body.List) != 1 {
		return nil
	}
	var call *ast.CallExpr
	switch s := body.List[0].(type) {
	case *ast.ReturnStmt:
		if len(s.Results) == 1 {
			call, _ = s.Results[0].(*ast.CallExpr)
		}
	case *ast.ExprStmt:
		call, _ = s.X.(*ast.CallExpr)
	}
	return call
}

func delegateCallee(body *ast.BlockStmt, info *types.Info, own *types.Package) (*types.Func, string) {
	call := soleCall(body)
	if call == nil {
		return nil, ""
	}
	fun := ast.Unparen(call.Fun)
	switch generic := fun.(type) {
	case *ast.IndexExpr:
		fun = ast.Unparen(generic.X)
	case *ast.IndexListExpr:
		fun = ast.Unparen(generic.X)
	}
	var name *ast.Ident
	var qualifier string
	switch fun := fun.(type) {
	case *ast.Ident:
		name = fun
	case *ast.SelectorExpr:
		name = fun.Sel
		if x, ok := ast.Unparen(fun.X).(*ast.Ident); ok {
			qualifier = x.Name
		}
	}
	if name == nil {
		return nil, ""
	}
	callee, ok := info.Uses[name].(*types.Func)
	if !ok || callee.Pkg() == nil || callee.Pkg() == own {
		return nil, ""
	}
	return callee, qualifier
}
