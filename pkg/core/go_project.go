package core

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// GoProjectContext contains the shared typed representation of the initial Go packages.
type GoProjectContext struct {
	ProjectRoot string
	FileSet     *token.FileSet
	Program     *ssa.Program
	Packages    []*GoPackageContext
	Files       []*FileContext

	filesByPath map[string]*FileContext
}

// GoPackageContext connects a loaded typed package and its optional SSA package
// to the existing file contexts used by file-level rules.
type GoPackageContext struct {
	Package *packages.Package
	SSA     *ssa.Package
	Files   []*FileContext
}

// File resolves an absolute or project-relative path to its existing file context.
func (ctx *GoProjectContext) File(path string) (*FileContext, error) {
	if ctx == nil {
		return nil, errors.New("resolve Go project file: nil project context")
	}
	if path == "" {
		return nil, errors.New("resolve Go project file: empty path")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(ctx.ProjectRoot, path)
	}
	path = filepath.Clean(path)
	fileCtx, ok := ctx.filesByPath[path]
	if !ok {
		return nil, fmt.Errorf("resolve Go project file %q: no file context", path)
	}
	return fileCtx, nil
}

// FileForPosition maps a position in the shared file set to its file context.
func (ctx *GoProjectContext) FileForPosition(pos token.Pos) (*FileContext, error) {
	if ctx == nil || ctx.FileSet == nil {
		return nil, errors.New("map Go position: project has no file set")
	}
	position := ctx.FileSet.PositionFor(pos, false)
	if !position.IsValid() || position.Filename == "" {
		return nil, fmt.Errorf("map Go position %d: invalid or unknown position", pos)
	}
	fileCtx, err := ctx.File(position.Filename)
	if err != nil {
		return nil, fmt.Errorf("map Go position %s: %w", position, err)
	}
	return fileCtx, nil
}

type parsedProjectFile struct {
	file *ast.File
	err  error
}

type goProjectLoader struct {
	root    string
	fset    *token.FileSet
	parsed  map[string]parsedProjectFile
	onParse func(string)
	mu      sync.Mutex
}

// LoadGoProject loads all initial packages below root from the already-read file contents.
func LoadGoProject(root string, contexts []*FileContext, requireSSA bool) (*GoProjectContext, error) {
	return loadGoProject(root, contexts, requireSSA, nil)
}

func loadGoProject(root string, contexts []*FileContext, requireSSA bool, onParse func(string)) (*GoProjectContext, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("make Go project root absolute: %w", err)
	}
	absRoot = filepath.Clean(absRoot)
	fset := token.NewFileSet()
	overlay, filesByPath, goFiles, err := prepareGoProjectFiles(absRoot, contexts)
	if err != nil {
		return nil, err
	}
	loader := &goProjectLoader{
		root:    absRoot,
		fset:    fset,
		parsed:  make(map[string]parsedProjectFile),
		onParse: onParse,
	}

	moduleDirs, err := goModuleDirs(absRoot, goFiles)
	if err != nil {
		return nil, err
	}
	loaded, err := loader.loadPackages(moduleDirs, overlay)
	if err != nil {
		return nil, err
	}
	if len(loaded) == 0 {
		return nil, fmt.Errorf("load Go packages below %q: no packages found", absRoot)
	}
	sort.Slice(loaded, func(i, j int) bool {
		if loaded[i] == nil || loaded[j] == nil {
			return loaded[i] != nil
		}
		if loaded[i].PkgPath != loaded[j].PkgPath {
			return loaded[i].PkgPath < loaded[j].PkgPath
		}
		return loaded[i].ID < loaded[j].ID
	})
	if err := validateLoadedPackages(loaded, fset); err != nil {
		return nil, err
	}

	project := &GoProjectContext{
		ProjectRoot: absRoot,
		FileSet:     fset,
		Files:       append([]*FileContext(nil), goFiles...),
		filesByPath: filesByPath,
	}
	compiled, err := attachLoadedGoPackages(project, loaded, loader.parsed)
	if err != nil {
		return nil, err
	}
	if err := attachUncompiledGoFiles(project, loader, goFiles, compiled); err != nil {
		return nil, err
	}

	if requireSSA {
		if err := attachGoSSA(project, loaded); err != nil {
			return nil, err
		}
	}

	return project, nil
}

func goModuleDirs(root string, goFiles []*FileContext) ([]string, error) {
	modules := make(map[string]bool)
	for _, fileCtx := range goFiles {
		path, err := absoluteContextPath(root, fileCtx)
		if err != nil {
			return nil, err
		}
		moduleDir, found, err := nearestGoModule(root, filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("load Go project: analyzed file %q is outside a Go module", path)
		}
		modules[moduleDir] = true
	}
	moduleDirs := make([]string, 0, len(modules))
	for moduleDir := range modules {
		moduleDirs = append(moduleDirs, moduleDir)
	}
	sort.Strings(moduleDirs)
	return moduleDirs, nil
}

func nearestGoModule(root, start string) (string, bool, error) {
	for dir := start; ; dir = filepath.Dir(dir) {
		info, err := os.Stat(filepath.Join(dir, "go.mod"))
		if err == nil {
			if info.IsDir() {
				return "", false, fmt.Errorf("find Go module: %q is a directory", filepath.Join(dir, "go.mod"))
			}
			return dir, true, nil
		}
		if !os.IsNotExist(err) {
			return "", false, fmt.Errorf("find Go module from %q: %w", start, err)
		}
		if dir == root {
			return "", false, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir || !pathWithinRoot(root, parent) {
			return "", false, nil
		}
	}
}

func pathWithinRoot(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (loader *goProjectLoader) loadPackages(moduleDirs []string, overlay map[string][]byte) ([]*packages.Package, error) {
	var loaded []*packages.Package
	for _, moduleDir := range moduleDirs {
		modulePackages, err := packages.Load(&packages.Config{
			Mode:      packages.LoadSyntax | packages.NeedModule,
			Dir:       moduleDir,
			Fset:      loader.fset,
			ParseFile: loader.parseFile,
			Tests:     false,
			Overlay:   overlay,
		}, "./...")
		if err != nil {
			return nil, fmt.Errorf("load Go packages in module %q: %w", moduleDir, err)
		}
		loaded = append(loaded, modulePackages...)
	}
	return loaded, nil
}

func prepareGoProjectFiles(root string, contexts []*FileContext) (map[string][]byte, map[string]*FileContext, []*FileContext, error) {
	overlay := make(map[string][]byte)
	filesByPath := make(map[string]*FileContext)
	goFiles := make([]*FileContext, 0)
	for _, fileCtx := range contexts {
		if fileCtx == nil {
			return nil, nil, nil, errors.New("load Go project: nil file context")
		}
		path, err := absoluteContextPath(root, fileCtx)
		if err != nil {
			return nil, nil, nil, err
		}
		if _, exists := filesByPath[path]; exists {
			return nil, nil, nil, fmt.Errorf("load Go project: duplicate file context for %q", path)
		}
		filesByPath[path] = fileCtx
		if fileCtx.IsGoFile() {
			overlay[path] = fileCtx.Content
			goFiles = append(goFiles, fileCtx)
		}
	}
	sort.Slice(goFiles, func(i, j int) bool { return goFiles[i].Path < goFiles[j].Path })
	return overlay, filesByPath, goFiles, nil
}

func (loader *goProjectLoader) parseFile(callbackFset *token.FileSet, filename string, src []byte) (*ast.File, error) {
	path, err := absolutePath(loader.root, filename)
	if err != nil {
		return nil, err
	}
	loader.mu.Lock()
	defer loader.mu.Unlock()
	if callbackFset != loader.fset {
		return nil, fmt.Errorf("parse Go file %q: packages loader used an unexpected file set", path)
	}
	if result, ok := loader.parsed[path]; ok {
		return result.file, result.err
	}
	file, parseErr := parser.ParseFile(loader.fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	loader.parsed[path] = parsedProjectFile{file: file, err: parseErr}
	if loader.onParse != nil {
		loader.onParse(path)
	}
	if parseErr != nil {
		return file, fmt.Errorf("parse Go file %q: %w", path, parseErr)
	}
	return file, nil
}

func attachLoadedGoPackages(project *GoProjectContext, loaded []*packages.Package, parsed map[string]parsedProjectFile) (map[string]bool, error) {
	compiled := make(map[string]bool)
	for _, pkg := range loaded {
		if len(pkg.Syntax) != len(pkg.CompiledGoFiles) {
			return nil, fmt.Errorf("load Go package %q: got %d syntax trees for %d compiled files", pkg.ID, len(pkg.Syntax), len(pkg.CompiledGoFiles))
		}
		pkgCtx := &GoPackageContext{Package: pkg}
		for i, filename := range pkg.CompiledGoFiles {
			path, err := absolutePath(project.ProjectRoot, filename)
			if err != nil {
				return nil, err
			}
			result, ok := parsed[path]
			if !ok || result.file == nil {
				return nil, fmt.Errorf("load Go package %q: compiled file %q has no parsed AST", pkg.ID, path)
			}
			if result.file != pkg.Syntax[i] {
				return nil, fmt.Errorf("load Go package %q: compiled file %q syntax does not match parser result", pkg.ID, path)
			}
			compiled[path] = true
			if fileCtx, analyzed := project.filesByPath[path]; analyzed {
				fileCtx.SetGoAST(project.FileSet, result.file)
				pkgCtx.Files = append(pkgCtx.Files, fileCtx)
			}
		}
		sort.Slice(pkgCtx.Files, func(i, j int) bool { return pkgCtx.Files[i].Path < pkgCtx.Files[j].Path })
		project.Packages = append(project.Packages, pkgCtx)
	}
	return compiled, nil
}

func attachUncompiledGoFiles(project *GoProjectContext, loader *goProjectLoader, goFiles []*FileContext, compiled map[string]bool) error {
	for _, fileCtx := range goFiles {
		path, err := absoluteContextPath(project.ProjectRoot, fileCtx)
		if err != nil {
			return err
		}
		if compiled[path] {
			continue
		}
		file, err := loader.parseFile(project.FileSet, path, fileCtx.Content)
		if err != nil {
			return err
		}
		fileCtx.SetGoAST(project.FileSet, file)
	}
	return nil
}

func attachGoSSA(project *GoProjectContext, loaded []*packages.Package) error {
	program, ssaPackages := ssautil.Packages(loaded, ssa.InstantiateGenerics)
	if program == nil {
		return errors.New("build Go SSA: ssautil returned a nil program")
	}
	if len(ssaPackages) != len(project.Packages) {
		return fmt.Errorf("build Go SSA: got %d packages for %d initial packages", len(ssaPackages), len(project.Packages))
	}
	project.Program = program
	for i, ssaPkg := range ssaPackages {
		if ssaPkg == nil {
			return fmt.Errorf("build Go SSA for package %q: nil SSA package", loaded[i].ID)
		}
		project.Packages[i].SSA = ssaPkg
	}
	program.Build()
	return nil
}

func absoluteContextPath(root string, ctx *FileContext) (string, error) {
	path := ctx.Path
	if !filepath.IsAbs(path) && ctx.RelPath != "" {
		path = ctx.RelPath
	}
	return absolutePath(root, path)
}

func absolutePath(root, path string) (string, error) {
	if path == "" {
		return "", errors.New("resolve Go source path: empty path")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("make Go source path %q absolute: %w", path, err)
	}
	return filepath.Clean(absPath), nil
}

func validateLoadedPackages(loaded []*packages.Package, fset *token.FileSet) error {
	var packageErrors []error
	for _, pkg := range loaded {
		if pkg == nil {
			packageErrors = append(packageErrors, errors.New("load Go packages: nil package"))
			continue
		}
		for _, pkgErr := range pkg.Errors {
			packageErrors = append(packageErrors, fmt.Errorf("package %q: %s", pkg.ID, pkgErr.Error()))
		}
		if pkg.Module != nil && pkg.Module.Error != nil {
			packageErrors = append(packageErrors, fmt.Errorf("package %q module: %s", pkg.ID, pkg.Module.Error.Err))
		}
		if pkg.IllTyped {
			packageErrors = append(packageErrors, fmt.Errorf("package %q is ill-typed", pkg.ID))
		}
		if pkg.Types == nil || pkg.TypesInfo == nil || pkg.Fset == nil {
			packageErrors = append(packageErrors, fmt.Errorf("package %q has incomplete typed syntax", pkg.ID))
		} else if pkg.Fset != fset {
			packageErrors = append(packageErrors, fmt.Errorf("package %q does not use the shared file set", pkg.ID))
		}
	}
	if len(packageErrors) > 0 {
		return fmt.Errorf("load Go project: %w", errors.Join(packageErrors...))
	}
	return nil
}
