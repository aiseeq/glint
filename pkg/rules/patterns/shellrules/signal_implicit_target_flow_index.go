package shellrules

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type rangeFuncDecl struct {
	decl *ast.FuncDecl
	info *types.Info
	pkg  *signalPackage
}

// rangePackages are the packages whose syntax the analysis can enter: this
// one first, then every package of the run.
func (p *signalPackage) rangePackages() []*signalPackage {
	if p.project == nil {
		return []*signalPackage{p}
	}
	return append([]*signalPackage{p}, p.project.packages...)
}

// rangeFunc finds the declaration of fn in a package of the run, with the
// types that package was checked with.
func (p *signalPackage) rangeFunc(fn *types.Func) (rangeFuncDecl, bool) {
	fn = fn.Origin()
	if fn.Pkg() == nil {
		return rangeFuncDecl{}, false
	}
	for _, candidate := range p.rangePackages() {
		if candidate.info == nil || candidate.path != fn.Pkg().Path() {
			continue
		}
		if decl := candidate.rangeFuncDecls()[fn]; decl != nil {
			return rangeFuncDecl{decl: decl, info: candidate.info, pkg: candidate}, true
		}
	}
	return rangeFuncDecl{}, false
}

func (p *signalPackage) rangeFuncDecls() map[*types.Func]*ast.FuncDecl {
	p.rangeOnce.Do(func() {
		p.rangeDecls = make(map[*types.Func]*ast.FuncDecl)
		for _, file := range p.files {
			for _, decl := range file.Decls {
				function, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if fn, ok := p.info.Defs[function.Name].(*types.Func); ok {
					p.rangeDecls[fn] = function
				}
			}
		}
	})
	return p.rangeDecls
}

// interfaceImpls lists the methods a call of an interface method may reach:
// the interface is declared in the run and names one of its package's types,
// so only a type of a package that imports it can implement it, and the
// implementations come from the types of the run's packages.
func (s *rangeScope) interfaceImpls(fn *types.Func) ([]*types.Func, bool) {
	recv := fn.Signature().Recv()
	if recv == nil {
		return nil, false
	}
	iface, ok := recv.Type().Underlying().(*types.Interface)
	named, isNamed := types.Unalias(recv.Type()).(*types.Named)
	if !ok || !isNamed || named.Obj().Pkg() == nil || !rangeSealedInterface(named, iface) {
		return nil, false
	}
	if !s.loadedPackage(named.Obj().Pkg().Path()) {
		return nil, false
	}
	if impls, ok := s.a.impls[fn]; ok {
		return impls, true
	}
	seen := make(map[*types.Func]bool)
	var impls []*types.Func
	for _, pkg := range s.pkg.rangePackages() {
		if pkg.info == nil || s.a.linked != nil && !s.a.linked[pkg.path] {
			continue
		}
		for _, obj := range pkg.info.Defs {
			if impl := rangeImplementation(obj, iface, fn); impl != nil && !seen[impl] {
				seen[impl] = true
				impls = append(impls, impl)
			}
		}
	}
	// Defs is a map: order the implementations by declaration.
	sort.Slice(impls, func(i, j int) bool { return impls[i].Pos() < impls[j].Pos() })
	s.a.impls[fn] = impls
	return impls, true
}

func (s *rangeScope) loadedPackage(path string) bool {
	for _, pkg := range s.pkg.rangePackages() {
		if pkg.path == path && pkg.info != nil {
			return true
		}
	}
	return false
}

func rangeImplementation(obj types.Object, iface *types.Interface, fn *types.Func) *types.Func {
	name, ok := obj.(*types.TypeName)
	if !ok || name.IsAlias() || types.IsInterface(name.Type()) {
		return nil
	}
	for _, t := range []types.Type{name.Type(), types.NewPointer(name.Type())} {
		if !types.Implements(t, iface) {
			continue
		}
		selection := types.NewMethodSet(t).Lookup(fn.Pkg(), fn.Name())
		if selection == nil {
			return nil
		}
		impl, _ := selection.Obj().(*types.Func)
		return impl
	}
	return nil
}

// rangeSealedInterface reports an interface a method of which names a type
// of the interface's own package: a package that does not import it cannot
// implement it.
func rangeSealedInterface(named *types.Named, iface *types.Interface) bool {
	pkg := named.Obj().Pkg()
	for method := range iface.Methods() {
		signature := method.Signature()
		for _, tuple := range []*types.Tuple{signature.Params(), signature.Results()} {
			for v := range tuple.Variables() {
				if rangeNamesPackage(v.Type(), pkg) {
					return true
				}
			}
		}
	}
	return false
}

func rangeNamesPackage(t types.Type, pkg *types.Package) bool {
	for {
		switch u := types.Unalias(t).(type) {
		case *types.Pointer:
			t = u.Elem()
		case *types.Slice:
			t = u.Elem()
		case *types.Named:
			return u.Obj().Pkg() == pkg
		default:
			return false
		}
	}
}

// rangeParserPackages read shell text and return its structure; they are
// entered only while their own source imports nothing that can start a
// process (rangeExecImports). akit shellcmd parses with mvdan.cc/sh syntax
// and expands with expand.Format and no runner.
var rangeParserPackages = map[string]bool{
	"github.com/aiseeq/akit/shellcmd": true,
}

var rangeExecImports = map[string]bool{
	"os": true, "os/exec": true, "syscall": true, "plugin": true, "unsafe": true, "C": true,
	"golang.org/x/sys/unix": true, "golang.org/x/sys/windows": true,
	"mvdan.cc/sh/v3/interp": true,
}

func (s *rangeScope) parserCall(call *ast.CallExpr) bool {
	fn := rangeCallFunc(call, s.info)
	if fn == nil || fn.Pkg() == nil || !rangeParserPackages[fn.Pkg().Path()] || s.a.fset == nil {
		return false
	}
	file := s.a.fset.File(fn.Pos())
	if file == nil {
		return false
	}
	dir := filepath.Dir(file.Name())
	inert, ok := s.a.inert[dir]
	if !ok {
		var err error
		// A directory that cannot be read is not inert.
		inert, err = rangeReadInert(dir)
		inert = inert && err == nil
		s.a.inert[dir] = inert
	}
	return inert
}

// rangeReadInert reports a package directory whose Go files (tests aside)
// import none of rangeExecImports.
func rangeReadInert(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("read package directory: %w", err)
	}
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			return false, fmt.Errorf("parse imports of %s: %w", name, err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return false, fmt.Errorf("import path in %s: %w", name, err)
			}
			if rangeExecImports[path] {
				return false, nil
			}
		}
		found = true
	}
	return found, nil
}

// rangeRootPackage is the package the files of pkg declare, or nil.
func rangeRootPackage(info *types.Info, pkg *signalPackage) *types.Package {
	if pkg == nil {
		return nil
	}
	for _, file := range pkg.files {
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if obj := info.Defs[function.Name]; obj != nil && obj.Pkg() != nil {
				return obj.Pkg()
			}
		}
	}
	return nil
}

// rangeLinkedPackages is the import closure of root, or nil without one.
func rangeLinkedPackages(root *types.Package) map[string]bool {
	if root == nil {
		return nil
	}
	linked := make(map[string]bool)
	queue := []*types.Package{root}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if linked[pkg.Path()] {
			continue
		}
		linked[pkg.Path()] = true
		queue = append(queue, pkg.Imports()...)
	}
	return linked
}
