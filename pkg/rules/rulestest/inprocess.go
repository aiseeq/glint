package rulestest

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/types"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/gcexportdata"
	"golang.org/x/tools/go/packages"
)

// loaderEnv names the variable that sends every test load through
// packages.Load: RULESTEST_LOADER=packages runs the rule tests on the loader
// glint itself uses, to check the in-process one against it.
const loaderEnv = "RULESTEST_LOADER"

// ListPackages is the loader of the rule tests, for core.GoProjectOptions.
// It has the contract of packages.Load, and for the small throwaway module a
// rule test writes it does the same work in process: it type-checks the
// module's packages from source and reads the standard library from the same
// export data packages.Load reads, into the same file set. packages.Load
// spends about a tenth of a CPU second per test on starting go list and
// compiling the module for export data nothing reads; a suite of a thousand
// loads spent most of its time there.
//
// A module the in-process load does not mirror exactly goes to
// packages.Load: an overlay, test packages, a workspace, a requirement that
// is not replaced by a directory of the module, a nested module nobody
// replaces with, build constraints, cgo, an import from outside the modules
// and the standard library, a package that does not type-check.
func ListPackages(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
	if os.Getenv(loaderEnv) == "packages" {
		return packages.Load(cfg, patterns...)
	}
	loaded, err := loadInProcess(cfg, patterns)
	if errors.Is(err, errNotMirrored) {
		return packages.Load(cfg, patterns...)
	}
	return loaded, err
}

// errNotMirrored marks a module the in-process load does not mirror: not a
// failure, the module goes to packages.Load, which also reports its errors
// (a go.mod or a file that does not parse, a type error) the way glint sees
// them.
var errNotMirrored = errors.New("not mirrored in process")

// notMirrored declines a module for a reason.
func notMirrored(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errNotMirrored, fmt.Sprintf(format, args...))
}

// stdIndex is what the go command reports about the standard library once
// per test process: the export data file of every package and the target.
type stdIndex struct {
	export map[string]string
	goarch string
	gowork string
}

var (
	stdOnce sync.Once
	std     stdIndex
	stdErr  error
)

// standardLibrary lists the standard library once: go list -export std
// reads the export data from the build cache, as packages.Load does.
func standardLibrary(dir string) (stdIndex, error) {
	stdOnce.Do(func() {
		index := stdIndex{export: map[string]string{}}
		out, err := goCommand(dir, "list", "-e", "-export", "-f", "{{.ImportPath}}\t{{.Export}}", "std")
		if err != nil {
			stdErr = err
			return
		}
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			importPath, export, found := strings.Cut(scanner.Text(), "\t")
			if !found {
				stdErr = fmt.Errorf("go list std: unexpected line %q", scanner.Text())
				return
			}
			index.export[importPath] = export
		}
		env, err := goCommand(dir, "env", "GOARCH", "GOWORK")
		if err != nil {
			stdErr = err
			return
		}
		lines := strings.Split(strings.TrimSuffix(string(env), "\n"), "\n")
		if len(lines) != 2 {
			stdErr = fmt.Errorf("go env GOARCH GOWORK: unexpected output %q", env)
			return
		}
		index.goarch, index.gowork = lines[0], lines[1]
		std = index
	})
	return std, stdErr
}

// goCommand runs the go command in dir and returns its output.
func goCommand(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out, nil
}

// testModule is a module of the load: the main one, or one a replace
// directive points at a directory of the main one.
type testModule struct {
	module *packages.Module
	// replaced holds the directories of the modules that replace this
	// module's requirements; they are not its packages.
	replaced []string
}

// localPackage is a package of a module of the load.
type localPackage struct {
	path    string
	dir     string
	module  *packages.Module
	root    bool
	build   *build.Package
	pkg     *packages.Package
	visited bool
}

// loadInProcess loads the module of cfg.Dir in process; errNotMirrored
// declines a module it does not mirror.
func loadInProcess(cfg *packages.Config, patterns []string) ([]*packages.Package, error) {
	if len(patterns) != 1 || patterns[0] != "./..." || len(cfg.Overlay) > 0 || cfg.Tests || cfg.Fset == nil || cfg.ParseFile == nil {
		return nil, notMirrored("a load other than ./... of the files on disk")
	}
	index, err := standardLibrary(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if index.gowork != "" && index.gowork != "off" {
		return nil, notMirrored("workspace %s", index.gowork)
	}
	main, deps, err := readModules(cfg.Dir)
	if err != nil {
		return nil, err
	}
	locals := map[string]*localPackage{}
	if err := collectPackages(main, true, locals); err != nil {
		return nil, err
	}
	for _, dep := range deps {
		if err := collectPackages(dep, false, locals); err != nil {
			return nil, err
		}
	}
	if err := importsResolve(locals, index); err != nil {
		return nil, err
	}

	l := &inProcessLoad{
		cfg:     cfg,
		index:   index,
		locals:  locals,
		sizes:   types.SizesFor("gc", index.goarch),
		imports: map[string]*types.Package{},
		deps:    map[string]*packages.Package{},
	}
	paths := make([]string, 0, len(locals))
	for importPath, local := range locals {
		if local.root {
			paths = append(paths, importPath)
		}
	}
	if len(paths) == 0 {
		return nil, notMirrored("no packages")
	}
	slices.Sort(paths)
	roots := make([]*packages.Package, 0, len(paths))
	for _, importPath := range paths {
		if err := l.check(locals[importPath]); err != nil {
			return nil, err
		}
		roots = append(roots, locals[importPath].pkg)
	}
	return roots, nil
}

// readModules reads the main module of dir and the modules its replace
// directives point at directories inside it. Anything else in a go.mod - a
// requirement without such a replace, a toolchain, an exclusion, a
// retraction, a godebug, a tool, an ignore - is not mirrored.
func readModules(dir string) (main testModule, deps []testModule, err error) {
	file, err := simpleGoMod(dir)
	if err != nil {
		return testModule{}, nil, err
	}
	replaces := map[string]string{}
	for _, r := range file.Replace {
		if r.Old.Version != "" || r.New.Version != "" || !strings.HasPrefix(r.New.Path, "./") {
			return testModule{}, nil, notMirrored("replace %s => %s", r.Old.Path, r.New.Path)
		}
		replaces[r.Old.Path] = filepath.Join(dir, filepath.FromSlash(r.New.Path))
	}
	if len(replaces) != len(file.Require) {
		return testModule{}, nil, notMirrored("%d replacements for %d requirements", len(replaces), len(file.Require))
	}
	main = testModule{module: moduleOf(file, dir)}
	for _, req := range file.Require {
		depDir, replaced := replaces[req.Mod.Path]
		if !replaced {
			return testModule{}, nil, notMirrored("requirement %s is not replaced", req.Mod.Path)
		}
		depFile, err := simpleGoMod(depDir)
		if err != nil {
			return testModule{}, nil, err
		}
		if depFile.Module.Mod.Path != req.Mod.Path || len(depFile.Require) > 0 || len(depFile.Replace) > 0 {
			return testModule{}, nil, notMirrored("replacement %s is not a plain module", depDir)
		}
		dep := testModule{module: moduleOf(depFile, depDir)}
		dep.module.Version = req.Mod.Version
		dep.module.Main = false
		deps = append(deps, dep)
		main.replaced = append(main.replaced, depDir)
	}
	return main, deps, nil
}

// simpleGoMod parses the go.mod of dir when it holds only a module path, a
// go version, requirements and replacements. A go.mod that does not parse
// is left to packages.Load, which reports it.
func simpleGoMod(dir string) (*modfile.File, error) {
	goMod := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goMod)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", goMod, err)
	}
	file, parseErr := modfile.Parse(goMod, data, nil)
	if parseErr != nil {
		return nil, notMirrored("go.mod does not parse: %v", parseErr)
	}
	if file.Module == nil || file.Go == nil || file.Toolchain != nil || len(file.Godebug) > 0 ||
		len(file.Exclude) > 0 || len(file.Retract) > 0 || len(file.Tool) > 0 || len(file.Ignore) > 0 {
		return nil, notMirrored("go.mod %s holds more than a module, a go version, requirements and replacements", goMod)
	}
	return file, nil
}

// moduleOf describes the module of a go.mod the way go list does.
func moduleOf(file *modfile.File, dir string) *packages.Module {
	return &packages.Module{Path: file.Module.Mod.Path, Dir: dir, GoMod: filepath.Join(dir, "go.mod"), GoVersion: file.Go.Version, Main: true}
}

// collectPackages finds the packages of a module the way go list ./... does
// for a module of plain files: every directory with Go files, skipping
// testdata, vendor and names starting with . or _. A nested module nothing
// replaces with, Go files in a skipped directory, build constraints, cgo,
// files the build ignores and a directory of test files alone are not
// mirrored.
func collectPackages(mod testModule, root bool, locals map[string]*localPackage) error {
	ctx := build.Default
	ctx.CgoEnabled = false
	base := mod.module.Dir
	return filepath.WalkDir(base, func(dir string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		if dir != base {
			if slices.Contains(mod.replaced, dir) {
				return filepath.SkipDir
			}
			name := entry.Name()
			if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				// Which of these go list skips depends on the mode and the
				// pattern; a module with Go files there goes to packages.Load.
				holds, err := holdsGoFiles(dir)
				if err != nil {
					return err
				}
				if holds {
					return notMirrored("Go files in %s", dir)
				}
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return notMirrored("nested module %s", dir)
			}
		}
		pkg, importErr := ctx.ImportDir(dir, 0)
		var noGo *build.NoGoError
		if errors.As(importErr, &noGo) {
			// go list ./... lists a directory of test files alone as a
			// package without files; packages.Load answers for it.
			if pkg != nil && len(pkg.TestGoFiles)+len(pkg.XTestGoFiles) > 0 {
				return notMirrored("test files alone in %s", dir)
			}
			return nil
		}
		if importErr != nil {
			return notMirrored("%s: %v", dir, importErr)
		}
		constrained, err := hasConstraint(dir, pkg.GoFiles)
		if err != nil {
			return err
		}
		if len(pkg.GoFiles) == 0 || len(pkg.IgnoredGoFiles) > 0 || len(pkg.InvalidGoFiles) > 0 || len(pkg.CgoFiles) > 0 || constrained {
			return notMirrored("%s: test files alone, cgo, build constraints or files the build ignores", dir)
		}
		rel, err := filepath.Rel(base, dir)
		if err != nil {
			return err
		}
		importPath := mod.module.Path
		if rel != "." {
			importPath = path.Join(importPath, filepath.ToSlash(rel))
		}
		if _, taken := locals[importPath]; taken {
			return notMirrored("two modules hold %s", importPath)
		}
		locals[importPath] = &localPackage{path: importPath, dir: dir, module: mod.module, root: root, build: pkg}
		return nil
	})
}

// importsResolve checks that every import of the modules' packages is one of
// them or a package of the standard library.
func importsResolve(locals map[string]*localPackage, index stdIndex) error {
	for _, importPath := range slices.Sorted(maps.Keys(locals)) {
		local := locals[importPath]
		for _, imp := range local.build.Imports {
			_, isLocal := locals[imp]
			_, isStd := index.export[imp]
			if !isLocal && !isStd {
				return notMirrored("import %s of %s", imp, local.path)
			}
		}
	}
	return nil
}

// holdsGoFiles reports whether a directory tree holds a Go file.
func holdsGoFiles(dir string) (bool, error) {
	found := false
	err := filepath.WalkDir(dir, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found, err
}

// hasConstraint reports a file with a //go:build or // +build line: the
// tags go list builds with are not known here.
func hasConstraint(dir string, files []string) (bool, error) {
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return false, err
		}
		if bytes.Contains(data, []byte("//go:build")) || bytes.Contains(data, []byte("// +build")) {
			return true, nil
		}
	}
	return false, nil
}

// inProcessLoad type-checks the packages of one load.
type inProcessLoad struct {
	cfg     *packages.Config
	index   stdIndex
	locals  map[string]*localPackage
	sizes   types.Sizes
	imports map[string]*types.Package
	deps    map[string]*packages.Package
}

// check type-checks a package after the packages of the modules it
// imports. An import cycle and a package that does not parse or type-check
// are not mirrored: packages.Load reports them the way glint sees them. A
// package of a replacing module keeps only its types, as a dependency
// packages.Load reads from export data does.
func (l *inProcessLoad) check(local *localPackage) error {
	if local.pkg != nil {
		return nil
	}
	if local.visited {
		return notMirrored("import cycle through %s", local.path)
	}
	local.visited = true
	pkg := &packages.Package{
		ID:         local.path,
		Name:       local.build.Name,
		PkgPath:    local.path,
		Fset:       l.cfg.Fset,
		Module:     local.module,
		TypesSizes: l.sizes,
		Imports:    map[string]*packages.Package{},
	}
	for _, imp := range local.build.Imports {
		if dep, isLocal := l.locals[imp]; isLocal {
			if err := l.check(dep); err != nil {
				return err
			}
			pkg.Imports[imp] = dep.pkg
			continue
		}
		dep, err := l.standard(imp)
		if err != nil {
			return err
		}
		pkg.Imports[imp] = dep
	}
	var syntax []*ast.File
	var files []string
	for _, name := range local.build.GoFiles {
		filename := filepath.Join(local.dir, name)
		src, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		file, parseErr := l.cfg.ParseFile(l.cfg.Fset, filename, src)
		if parseErr != nil {
			return notMirrored("parse %s: %v", filename, parseErr)
		}
		files = append(files, filename)
		syntax = append(syntax, file)
	}
	info := &types.Info{
		Types:        map[ast.Expr]types.TypeAndValue{},
		Instances:    map[*ast.Ident]types.Instance{},
		Defs:         map[*ast.Ident]types.Object{},
		Uses:         map[*ast.Ident]types.Object{},
		Implicits:    map[ast.Node]types.Object{},
		Selections:   map[*ast.SelectorExpr]*types.Selection{},
		Scopes:       map[ast.Node]*types.Scope{},
		FileVersions: map[*ast.File]string{},
	}
	var typeErr error
	conf := types.Config{
		Importer:  importerFunc(func(p string) (*types.Package, error) { return typesOf(pkg, p) }),
		Sizes:     l.sizes,
		GoVersion: "go" + local.module.GoVersion,
		Error: func(err error) {
			if typeErr == nil {
				typeErr = err
			}
		},
	}
	checked, checkErr := conf.Check(local.path, l.cfg.Fset, syntax, info)
	if typeErr != nil {
		return notMirrored("type-check %s: %v", local.path, typeErr)
	}
	if checkErr != nil {
		return notMirrored("type-check %s: %v", local.path, checkErr)
	}
	pkg.Types = checked
	if local.root {
		pkg.GoFiles, pkg.CompiledGoFiles, pkg.Syntax, pkg.TypesInfo = files, slices.Clone(files), syntax, info
	}
	local.pkg = pkg
	return nil
}

// typesOf returns the types of an import of pkg.
func typesOf(pkg *packages.Package, importPath string) (*types.Package, error) {
	if importPath == "unsafe" {
		return types.Unsafe, nil
	}
	dep, ok := pkg.Imports[importPath]
	if !ok || dep.Types == nil {
		return nil, fmt.Errorf("import %q: not loaded", importPath)
	}
	return dep.Types, nil
}

// standard returns a package of the standard library, its types read from
// export data into the load's file set.
func (l *inProcessLoad) standard(importPath string) (*packages.Package, error) {
	if dep, ok := l.deps[importPath]; ok {
		return dep, nil
	}
	dep := &packages.Package{ID: importPath, PkgPath: importPath, Fset: l.cfg.Fset, TypesSizes: l.sizes}
	if importPath == "unsafe" {
		dep.Name, dep.Types = "unsafe", types.Unsafe
		l.deps[importPath] = dep
		return dep, nil
	}
	exportFile := l.index.export[importPath]
	if exportFile == "" {
		return nil, fmt.Errorf("import %q: go list std gave no export data", importPath)
	}
	typed, err := l.readExport(exportFile, importPath)
	if err != nil {
		return nil, err
	}
	dep.Name, dep.Types = typed.Name(), typed
	l.deps[importPath] = dep
	return dep, nil
}

// readExport reads the types of a package from its export data file.
func (l *inProcessLoad) readExport(exportFile, importPath string) (typed *types.Package, err error) {
	f, err := os.Open(exportFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	// go/packages reads the files of go list -export the same way: until their
	// format leaves the compiler's archive there is no other reader for them.
	reader, err := gcexportdata.NewReader(bufio.NewReader(f)) //nolint:staticcheck // SA1019: no replacement for go list -export files yet
	if err != nil {
		return nil, fmt.Errorf("read export data of %q: %w", importPath, err)
	}
	typed, err = gcexportdata.Read(reader, l.cfg.Fset, l.imports, importPath)
	if err != nil {
		return nil, fmt.Errorf("read export data of %q: %w", importPath, err)
	}
	return typed, nil
}

// importerFunc adapts a function to types.Importer.
type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
