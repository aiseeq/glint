package patternkit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"path/filepath"
	"sync"

	"golang.org/x/tools/go/packages"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// DependencySources reads the declarations of functions whose package came
// from export data: a library function has no syntax in the project, so its
// body is parsed from its source file. A nil DependencySources reads
// nothing; it is safe for concurrent use.
//
// The file is one the go command listed for the function's package when the
// project was loaded, matched by the name its position gives. That position
// names the file as the compiler saw it, which is not always a path on disk:
// $GOROOT/src/os/file.go for the standard library, and with -trimpath
// os/file.go or example.com/mod@v1.2.3/dir/file.go for a module wherever it
// lives - the module cache, a directory a replace points at, the vendor
// directory. The listed files are paths on disk, resolved by the same go
// command and environment as the load, so no GOROOT or module cache layout
// is rebuilt here. A package missing from the load leaves the body unknown.
type DependencySources struct {
	fset *token.FileSet
	// packageFiles maps a loaded package to its Go files by base name: files
	// of one package share a directory, so a base name finds one.
	packageFiles map[*types.Package]map[string]string
	// standard holds the loaded packages of no module under a path of no dot: the standard library.
	standard map[*types.Package]bool

	mu    sync.Mutex
	files map[string]*dependencyFile
}

// dependencyFile is a dependency source parsed once; file is nil when the
// file could not be read or parsed.
type dependencyFile struct {
	once sync.Once
	fset *token.FileSet
	file *ast.File
}

type dependencySourcesKey struct{}

// DependencySourcesOf returns the dependency sources of the load behind ctx,
// shared by the rules of the run: a source file is parsed once for all of
// them.
func DependencySourcesOf(ctx *core.GoProjectContext) (*DependencySources, error) {
	return core.SharedLoad(ctx, dependencySourcesKey{}, func() (*DependencySources, error) {
		return NewDependencySources(ctx), nil
	})
}

// NewDependencySources reads the sources of the packages ctx loaded and of
// every package they import.
func NewDependencySources(ctx *core.GoProjectContext) *DependencySources {
	d := &DependencySources{
		fset:         ctx.FileSet,
		packageFiles: make(map[*types.Package]map[string]string),
		standard:     make(map[*types.Package]bool),
		files:        make(map[string]*dependencyFile),
	}
	roots := make([]*packages.Package, 0, len(ctx.Packages))
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil {
			roots = append(roots, pkg.Package)
		}
	}
	packages.Visit(roots, nil, func(pkg *packages.Package) {
		if pkg.Types == nil || len(pkg.GoFiles) == 0 {
			return
		}
		if pkg.Module == nil && helpers.IsStandardLibraryPath(pkg.PkgPath) {
			d.standard[pkg.Types] = true
		}
		byName := make(map[string]string, len(pkg.GoFiles))
		for _, file := range pkg.GoFiles {
			byName[filepath.Base(file)] = filepath.Clean(file)
		}
		d.packageFiles[pkg.Types] = byName
	})
	return d
}

// Standard reports a package of the standard library: one the load found in
// no module, under a path of no dot in its first element. The path alone
// cannot tell, since a module path needs no dot (example/lib); the module
// alone neither, since GOPATH mode loads every package without one. A GOPATH
// package under a path of no dot still reads as standard.
func (d *DependencySources) Standard(pkg *types.Package) bool {
	return d != nil && d.standard[pkg]
}

// FuncDecl returns the declaration of fn in its source file, nil when the
// position is unknown or names no file of fn's package the load listed, or
// the file cannot be read: the body is then unknown.
func (d *DependencySources) FuncDecl(fn *types.Func) *ast.FuncDecl {
	if d == nil || d.fset == nil || fn == nil || fn.Pkg() == nil || !fn.Pos().IsValid() {
		return nil
	}
	fn = fn.Origin()
	position := d.fset.PositionFor(fn.Pos(), false)
	if !position.IsValid() || position.Filename == "" {
		return nil
	}
	source, ok := d.sourcePath(fn.Pkg(), position.Filename)
	if !ok {
		return nil
	}
	parsed := d.file(source)
	if parsed.file == nil {
		return nil
	}
	for _, decl := range parsed.file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn.Name() {
			continue
		}
		// Export data keeps the line of a declaration, not always its column.
		if parsed.fset.PositionFor(fd.Name.Pos(), false).Line == position.Line {
			return fd
		}
	}
	return nil
}

// sourcePath returns the file of pkg the compiler named filename: the listed
// file of the same base name. An absolute filename is a path on disk and must
// be that file itself.
func (d *DependencySources) sourcePath(pkg *types.Package, filename string) (string, bool) {
	listed, ok := d.packageFiles[pkg][path.Base(filepath.ToSlash(filename))]
	if !ok {
		return "", false
	}
	if filepath.IsAbs(filename) && filepath.Clean(filename) != listed {
		return "", false
	}
	return listed, true
}

// file returns the source file at path, parsed on first use.
func (d *DependencySources) file(path string) *dependencyFile {
	d.mu.Lock()
	parsed, ok := d.files[path]
	if !ok {
		parsed = &dependencyFile{}
		d.files[path] = parsed
	}
	d.mu.Unlock()
	parsed.once.Do(func() { parsed.fset, parsed.file = parseDependencyFile(path) })
	return parsed
}

func parseDependencyFile(path string) (*token.FileSet, *ast.File) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil { //nolint:silent-error-handling // A dependency whose source cannot be read only leaves its body unknown.
		return nil, nil
	}
	return fset, file
}
