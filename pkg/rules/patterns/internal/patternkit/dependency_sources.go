package patternkit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sync"
)

// DependencySources reads the declarations of functions whose package came
// from export data: a library function has no syntax in the project, so its
// body is parsed from the source file its position names. A nil
// DependencySources reads nothing; it is safe for concurrent use.
type DependencySources struct {
	fset  *token.FileSet
	mu    sync.Mutex
	files map[string]*dependencyFile
}

// dependencyFile is a parsed dependency source and the file set its
// positions are in; nil when the file could not be read or parsed.
type dependencyFile struct {
	fset *token.FileSet
	file *ast.File
}

// NewDependencySources reads dependency sources by positions in fset.
func NewDependencySources(fset *token.FileSet) *DependencySources {
	return &DependencySources{fset: fset, files: make(map[string]*dependencyFile)}
}

// FuncDecl returns the declaration of fn in its source file, nil when the
// position is unknown or the file cannot be read: the body is then unknown.
func (d *DependencySources) FuncDecl(fn *types.Func) *ast.FuncDecl {
	if d == nil || d.fset == nil || fn == nil || !fn.Pos().IsValid() {
		return nil
	}
	fn = fn.Origin()
	position := d.fset.PositionFor(fn.Pos(), false)
	if !position.IsValid() || position.Filename == "" {
		return nil
	}
	parsed := d.file(filepath.Clean(position.Filename))
	if parsed == nil {
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

// file parses the source file at path once per run, nil when it cannot be
// read or parsed.
func (d *DependencySources) file(path string) *dependencyFile {
	d.mu.Lock()
	defer d.mu.Unlock()
	parsed, attempted := d.files[path]
	if !attempted {
		parsed = parseDependencyFile(path)
		d.files[path] = parsed
	}
	return parsed
}

func parseDependencyFile(path string) *dependencyFile {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil { //nolint:silent-error-handling // A dependency whose source cannot be read only leaves its body unknown.
		return nil
	}
	return &dependencyFile{fset: fset, file: file}
}
