package core

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// GoProjectOptions controls how the typed project is loaded.
type GoProjectOptions struct {
	// RequireSSA builds the SSA program for rules that need it.
	RequireSSA bool
	// TolerateBrokenPackages keeps analysis running when some packages fail to
	// type-check: they are excluded from typed analysis and reported in
	// SkippedPackages instead of aborting the whole load. Needed to analyze a
	// tree that does not compile as a whole - historical commits, generated or
	// git-ignored sources, work in progress.
	TolerateBrokenPackages bool
}

// SkippedPackage describes a package excluded from typed analysis.
type SkippedPackage struct {
	ID      string
	PkgPath string
	Reason  string
}

// GoProjectContext contains the shared typed representation of the initial Go packages.
type GoProjectContext struct {
	ProjectRoot string
	FileSet     *token.FileSet
	Program     *ssa.Program
	Packages    []*GoPackageContext
	Files       []*FileContext
	// SkippedPackages lists packages excluded from typed analysis; always empty
	// unless GoProjectOptions.TolerateBrokenPackages is set.
	SkippedPackages []SkippedPackage

	filesByPath map[string]*FileContext

	// shared holds values built once for this project; loadShared holds
	// values built once for the load behind it, which other roots of the same
	// module see too.
	shared     sharedCache
	loadShared *sharedCache
}

type sharedCache struct {
	mu      sync.Mutex
	entries map[any]*sharedValue
}

type sharedValue struct {
	once  sync.Once
	value any
	err   error
}

// Shared returns the value build computes for key, building it once per
// project: several rules that need the same project-wide scan share one pass
// instead of each repeating it. key is a comparable value of a type private to
// the caller's package, so packages cannot collide. The value must not be
// modified by its users.
func Shared[T any](ctx *GoProjectContext, key any, build func() (T, error)) (T, error) {
	return sharedGet(&ctx.shared, key, build)
}

// SharedLoad is Shared for a value that depends only on the loaded packages —
// their syntax, types and SSA — never on which files this root analyzes
// (Files, GoPackageContext.Files, ProjectRoot). Several roots of one module
// share one load, so such a value is built once for all of them.
func SharedLoad[T any](ctx *GoProjectContext, key any, build func() (T, error)) (T, error) {
	if ctx.loadShared == nil {
		return sharedGet(&ctx.shared, key, build)
	}
	return sharedGet(ctx.loadShared, key, build)
}

func sharedGet[T any](cache *sharedCache, key any, build func() (T, error)) (T, error) {
	cache.mu.Lock()
	if cache.entries == nil {
		cache.entries = make(map[any]*sharedValue)
	}
	entry, ok := cache.entries[key]
	if !ok {
		entry = &sharedValue{}
		cache.entries[key] = entry
	}
	cache.mu.Unlock()

	entry.once.Do(func() { entry.value, entry.err = build() })
	if entry.err != nil {
		var zero T
		return zero, entry.err
	}
	value, ok := entry.value.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("shared project value %v: stored %T, requested %T", key, entry.value, zero)
	}
	return value, nil
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
func LoadGoProject(root string, contexts []*FileContext, opts GoProjectOptions) (*GoProjectContext, error) {
	return NewGoProjectLoader().Load(root, contexts, opts)
}

// GoProjectLoader loads Go projects for one run. The typed load of a module
// does not depend on which of its files a root analyzes, so the roots of one
// module — glint check ./cmd/a ./cmd/b ./internal/c — share a single load:
// the module is listed, parsed, type-checked and built to SSA once, and each
// root gets its own view of it.
type GoProjectLoader struct {
	onParse func(string)

	mu    sync.Mutex
	loads map[string]*moduleLoad
}

// moduleLoad is the typed load of a set of modules, shared by the projects
// built from it.
type moduleLoad struct {
	loader      *goProjectLoader
	loaded      []*packages.Package
	skipped     []SkippedPackage
	program     *ssa.Program
	ssaPackages []*ssa.Package
	shared      sharedCache
}

// NewGoProjectLoader creates a loader with no loads cached.
func NewGoProjectLoader() *GoProjectLoader {
	return &GoProjectLoader{loads: make(map[string]*moduleLoad)}
}

// Load builds the project of root from the given file contexts, reusing a load
// of the same modules made for an earlier root.
func (l *GoProjectLoader) Load(root string, contexts []*FileContext, opts GoProjectOptions) (*GoProjectContext, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("make Go project root absolute: %w", err)
	}
	absRoot = filepath.Clean(absRoot)
	overlay, filesByPath, goFiles, err := prepareGoProjectFiles(absRoot, contexts)
	if err != nil {
		return nil, err
	}
	moduleDirs, outsideModule, err := goModuleDirs(absRoot, goFiles, opts.TolerateBrokenPackages)
	if err != nil {
		return nil, err
	}
	load, err := l.moduleLoad(absRoot, moduleDirs, overlay, opts)
	if err != nil {
		return nil, err
	}
	if len(load.loaded) == 0 && !opts.TolerateBrokenPackages {
		return nil, fmt.Errorf("load Go packages below %q: no packages found", absRoot)
	}

	project := &GoProjectContext{
		ProjectRoot:     absRoot,
		FileSet:         load.loader.fset,
		Files:           append([]*FileContext(nil), goFiles...),
		SkippedPackages: append(append([]SkippedPackage(nil), load.skipped...), outsideModule...),
		filesByPath:     filesByPath,
		loadShared:      &load.shared,
	}
	compiled, err := attachLoadedGoPackages(project, load.loaded, load.loader.parsed)
	if err != nil {
		return nil, err
	}
	unparsed, err := attachUncompiledGoFiles(project, load.loader, goFiles, compiled, opts.TolerateBrokenPackages)
	if err != nil {
		return nil, err
	}
	project.SkippedPackages = append(project.SkippedPackages, unparsed...)

	if opts.RequireSSA && len(load.loaded) > 0 {
		project.Program = load.program
		for i, ssaPkg := range load.ssaPackages {
			project.Packages[i].SSA = ssaPkg
		}
	}
	return project, nil
}

// moduleLoad returns the load of moduleDirs, making it on first use. A load
// with an overlay — contents that differ from the disk — belongs to its root
// alone and is not cached.
func (l *GoProjectLoader) moduleLoad(root string, moduleDirs []string, overlay map[string][]byte, opts GoProjectOptions) (*moduleLoad, error) {
	key := fmt.Sprintf("%q ssa=%t tolerate=%t", moduleDirs, opts.RequireSSA, opts.TolerateBrokenPackages)
	if len(overlay) == 0 {
		l.mu.Lock()
		cached, ok := l.loads[key]
		l.mu.Unlock()
		if ok {
			return cached, nil
		}
	}
	load, err := newModuleLoad(root, moduleDirs, overlay, opts, l.onParse)
	if err != nil {
		return nil, err
	}
	if len(overlay) == 0 {
		l.mu.Lock()
		l.loads[key] = load
		l.mu.Unlock()
	}
	return load, nil
}

func newModuleLoad(root string, moduleDirs []string, overlay map[string][]byte, opts GoProjectOptions, onParse func(string)) (*moduleLoad, error) {
	loader := &goProjectLoader{
		root:    root,
		fset:    token.NewFileSet(),
		parsed:  make(map[string]parsedProjectFile),
		onParse: onParse,
	}
	loaded, err := loader.loadPackages(moduleDirs, overlay)
	if err != nil {
		return nil, err
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
	healthy, skipped := partitionLoadedPackages(loaded, loader.fset)
	if len(skipped) > 0 && !opts.TolerateBrokenPackages {
		return nil, brokenPackagesError(skipped)
	}
	load := &moduleLoad{loader: loader, loaded: healthy, skipped: skipped}
	if opts.RequireSSA && len(healthy) > 0 {
		if err := load.buildSSA(); err != nil {
			return nil, err
		}
	}
	return load, nil
}

func (load *moduleLoad) buildSSA() error {
	program, ssaPackages := ssautil.Packages(load.loaded, ssa.InstantiateGenerics)
	if program == nil {
		return errors.New("build Go SSA: ssautil returned a nil program")
	}
	if len(ssaPackages) != len(load.loaded) {
		return fmt.Errorf("build Go SSA: got %d packages for %d initial packages", len(ssaPackages), len(load.loaded))
	}
	for i, ssaPkg := range ssaPackages {
		if ssaPkg == nil {
			return fmt.Errorf("build Go SSA for package %q: nil SSA package", load.loaded[i].ID)
		}
	}
	program.Build()
	load.program, load.ssaPackages = program, ssaPackages
	return nil
}

// goModuleDirs resolves the modules that own the analyzed files. With tolerate
// set, a file outside any module is reported instead of aborting the load: it
// still gets a syntax tree, only type information is unavailable for it.
func goModuleDirs(root string, goFiles []*FileContext, tolerate bool) ([]string, []SkippedPackage, error) {
	modules := make(map[string]bool)
	var outside []SkippedPackage
	for _, fileCtx := range goFiles {
		path, err := absoluteContextPath(root, fileCtx)
		if err != nil {
			return nil, nil, err
		}
		moduleDir, found, err := nearestGoModule(filepath.Dir(path))
		if err != nil {
			return nil, nil, err
		}
		if !found {
			if !tolerate {
				return nil, nil, fmt.Errorf("load Go project: analyzed file %q is outside a Go module", path)
			}
			outside = append(outside, SkippedPackage{Reason: fmt.Sprintf("file %q is outside a Go module", path)})
			continue
		}
		modules[moduleDir] = true
	}
	moduleDirs := make([]string, 0, len(modules))
	for moduleDir := range modules {
		moduleDirs = append(moduleDirs, moduleDir)
	}
	sort.Strings(moduleDirs)
	return moduleDirs, outside, nil
}

// nearestGoModule walks up from a file's directory until it finds the go.mod
// that owns it. The search deliberately ignores the root of the run: scoping a
// run to a subdirectory (`glint check ./internal`) is normal, and the module
// declaring those packages almost always sits above that subdirectory.
func nearestGoModule(start string) (string, bool, error) {
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
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false, nil
		}
	}
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
		if !fileCtx.IsGoFile() {
			continue
		}
		goFiles = append(goFiles, fileCtx)
		// Only content the disk does not hold goes into the overlay: any
		// overlay makes go/packages distrust export data and type-check every
		// dependency, the standard library included, from source.
		onDisk, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil, fmt.Errorf("load Go project: read %q: %w", path, err)
		}
		if err != nil || !bytes.Equal(onDisk, fileCtx.Content) {
			overlay[path] = fileCtx.Content
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
	if callbackFset != loader.fset {
		return nil, fmt.Errorf("parse Go file %q: packages loader used an unexpected file set", path)
	}
	if result, ok := loader.parsedFile(path); ok {
		return result.file, result.err
	}
	// go/packages parses files in parallel; the lock guards only the cache,
	// the file set is safe for concurrent use.
	file, parseErr := parser.ParseFile(loader.fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	loader.mu.Lock()
	if earlier, ok := loader.parsed[path]; ok {
		// Another package parsed the same file meanwhile: every package
		// shares the first tree.
		loader.mu.Unlock()
		return earlier.file, earlier.err
	}
	loader.parsed[path] = parsedProjectFile{file: file, err: parseErr}
	loader.mu.Unlock()
	if loader.onParse != nil {
		loader.onParse(path)
	}
	if parseErr != nil {
		return file, fmt.Errorf("parse Go file %q: %w", path, parseErr)
	}
	return file, nil
}

func (loader *goProjectLoader) parsedFile(path string) (parsedProjectFile, bool) {
	loader.mu.Lock()
	defer loader.mu.Unlock()
	result, ok := loader.parsed[path]
	return result, ok
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

// attachUncompiledGoFiles parses the analyzed files that no typed package
// claimed. With tolerate set, a file that does not parse at all is reported and
// left without a syntax tree instead of failing the whole load.
func attachUncompiledGoFiles(project *GoProjectContext, loader *goProjectLoader, goFiles []*FileContext, compiled map[string]bool, tolerate bool) ([]SkippedPackage, error) {
	var unparsed []SkippedPackage
	for _, fileCtx := range goFiles {
		path, err := absoluteContextPath(project.ProjectRoot, fileCtx)
		if err != nil {
			return nil, err
		}
		if compiled[path] {
			continue
		}
		file, err := loader.parseFile(project.FileSet, path, fileCtx.Content)
		if err != nil {
			err = classifyParseError(path, err)
			if errors.Is(err, errExcludedByBuild) {
				// Not part of any build, so not a package that failed to
				// type-check either; line rules still read the file.
				continue
			}
			if !tolerate {
				return nil, err
			}
			unparsed = append(unparsed, SkippedPackage{Reason: err.Error()})
			continue
		}
		fileCtx.SetGoAST(project.FileSet, file)
	}
	return unparsed, nil
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

// partitionLoadedPackages splits loaded packages into those usable for typed
// analysis and those that are not, with the reason each one was rejected.
func partitionLoadedPackages(loaded []*packages.Package, fset *token.FileSet) ([]*packages.Package, []SkippedPackage) {
	healthy := make([]*packages.Package, 0, len(loaded))
	var skipped []SkippedPackage
	for _, pkg := range loaded {
		if pkg == nil {
			skipped = append(skipped, SkippedPackage{Reason: "load Go packages: nil package"})
			continue
		}
		var reasons []string
		for _, pkgErr := range pkg.Errors {
			reasons = append(reasons, pkgErr.Error())
		}
		if pkg.Module != nil && pkg.Module.Error != nil {
			reasons = append(reasons, "module: "+pkg.Module.Error.Err)
		}
		if pkg.IllTyped {
			reasons = append(reasons, "package is ill-typed")
		}
		if pkg.Types == nil || pkg.TypesInfo == nil || pkg.Fset == nil {
			reasons = append(reasons, "package has incomplete typed syntax")
		} else if pkg.Fset != fset {
			reasons = append(reasons, "package does not use the shared file set")
		}
		if len(reasons) > 0 {
			skipped = append(skipped, SkippedPackage{
				ID:      pkg.ID,
				PkgPath: pkg.PkgPath,
				Reason:  strings.Join(reasons, "; "),
			})
			continue
		}
		healthy = append(healthy, pkg)
	}
	return healthy, skipped
}

func brokenPackagesError(skipped []SkippedPackage) error {
	packageErrors := make([]error, 0, len(skipped))
	for _, pkg := range skipped {
		if pkg.ID == "" {
			packageErrors = append(packageErrors, errors.New(pkg.Reason))
			continue
		}
		packageErrors = append(packageErrors, fmt.Errorf("package %q: %s", pkg.ID, pkg.Reason))
	}
	return fmt.Errorf("load Go project: %w", errors.Join(packageErrors...))
}
