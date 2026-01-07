package core

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
)

// FileContext contains all information about a file being analyzed
type FileContext struct {
	// Path information
	Path        string // Absolute path
	RelPath     string // Relative to project root
	ProjectRoot string // Project root directory

	// File content
	Content []byte   // Raw file content
	Lines   []string // Lines for positional access

	// Go-specific (nil for non-Go files)
	GoAST     *ast.File
	GoFileSet *token.FileSet
	GoPackage string
	GoImports []string

	// Configuration
	Config *Config
}

// NewFileContext creates a new file context
func NewFileContext(path, projectRoot string, content []byte, cfg *Config) *FileContext {
	relPath, _ := filepath.Rel(projectRoot, path)

	ctx := &FileContext{
		Path:        path,
		RelPath:     relPath,
		ProjectRoot: projectRoot,
		Content:     content,
		Lines:       strings.Split(string(content), "\n"),
		Config:      cfg,
	}

	return ctx
}

// IsGoFile returns true if this is a Go file
func (ctx *FileContext) IsGoFile() bool {
	return strings.HasSuffix(ctx.Path, ".go")
}

// IsTypeScriptFile returns true if this is a TypeScript file
func (ctx *FileContext) IsTypeScriptFile() bool {
	return strings.HasSuffix(ctx.Path, ".ts") || strings.HasSuffix(ctx.Path, ".tsx")
}

// IsJavaScriptFile returns true if this is a JavaScript file
func (ctx *FileContext) IsJavaScriptFile() bool {
	return strings.HasSuffix(ctx.Path, ".js") || strings.HasSuffix(ctx.Path, ".jsx")
}

// IsTestFile returns true if this appears to be a test file
func (ctx *FileContext) IsTestFile() bool {
	name := filepath.Base(ctx.Path)

	// Go test files
	if strings.HasSuffix(name, "_test.go") {
		return true
	}

	// JS/TS test files
	if strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") {
		return true
	}

	// Check path for test directories
	if strings.Contains(ctx.Path, "/test/") ||
		strings.Contains(ctx.Path, "/tests/") ||
		strings.Contains(ctx.Path, "/__tests__/") ||
		strings.Contains(ctx.Path, "/testdata/") {
		return true
	}

	return false
}

// GetLine returns a specific line (1-based index)
func (ctx *FileContext) GetLine(lineNum int) string {
	if lineNum < 1 || lineNum > len(ctx.Lines) {
		return ""
	}
	return ctx.Lines[lineNum-1]
}

// GetLines returns a range of lines (1-based, inclusive)
func (ctx *FileContext) GetLines(startLine, endLine int) []string {
	if startLine < 1 {
		startLine = 1
	}
	if endLine > len(ctx.Lines) {
		endLine = len(ctx.Lines)
	}
	if startLine > endLine {
		return nil
	}
	return ctx.Lines[startLine-1 : endLine]
}

// GetContext returns lines around a specific line for context
func (ctx *FileContext) GetContext(lineNum, contextLines int) []string {
	startLine := lineNum - contextLines
	endLine := lineNum + contextLines
	return ctx.GetLines(startLine, endLine)
}

// HasGoAST returns true if Go AST is available
func (ctx *FileContext) HasGoAST() bool {
	return ctx.GoAST != nil
}

// SetGoAST sets the Go AST for this file
func (ctx *FileContext) SetGoAST(fset *token.FileSet, file *ast.File) {
	ctx.GoFileSet = fset
	ctx.GoAST = file

	if file != nil {
		ctx.GoPackage = file.Name.Name

		// Extract imports
		ctx.GoImports = make([]string, 0, len(file.Imports))
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			ctx.GoImports = append(ctx.GoImports, path)
		}
	}
}

// PositionFor returns the position for a given ast.Node
func (ctx *FileContext) PositionFor(node ast.Node) token.Position {
	if ctx.GoFileSet == nil {
		return token.Position{}
	}
	return ctx.GoFileSet.Position(node.Pos())
}

// Extension returns the file extension
func (ctx *FileContext) Extension() string {
	return filepath.Ext(ctx.Path)
}

// BaseName returns the base name of the file
func (ctx *FileContext) BaseName() string {
	return filepath.Base(ctx.Path)
}

// Dir returns the directory containing the file
func (ctx *FileContext) Dir() string {
	return filepath.Dir(ctx.Path)
}
