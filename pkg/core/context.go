package core

import (
	"fmt"
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
	ctx, err := NewFileContextChecked(path, projectRoot, content, cfg)
	if err != nil {
		panic(err)
	}
	return ctx
}

// NewFileContextChecked creates a file context and reports invalid path relationships.
func NewFileContextChecked(path, projectRoot string, content []byte, cfg *Config) (*FileContext, error) {
	relPath, err := filepath.Rel(projectRoot, path)
	if err != nil {
		return nil, fmt.Errorf("make %q relative to project root %q: %w", path, projectRoot, err)
	}

	ctx := &FileContext{
		Path:        path,
		RelPath:     relPath,
		ProjectRoot: projectRoot,
		Content:     content,
		Lines:       strings.Split(string(content), "\n"),
		Config:      cfg,
	}

	return ctx, nil
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
	if strings.HasPrefix(name, "test_") && strings.HasSuffix(name, ".go") {
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

// IsSuppressed reports whether a violation of the given rule at the given
// line is suppressed by an inline comment. Two forms are recognized, on the
// violation line itself or on the line directly above it:
//
//	//nolint:<rule-name>
//	// <rule-name>: safe — <reason>
//
// The marker must appear inside a comment ("//" or "/*"); string literals
// containing the same text do not suppress. Rule names match exactly:
// "nolint:my-rule" does not suppress rule "my-rule-extended" and vice versa.
func (ctx *FileContext) IsSuppressed(line int, ruleName string) bool {
	for checkLine := line - 1; checkLine <= line; checkLine++ {
		if checkLine < 1 || checkLine > len(ctx.Lines) {
			continue
		}
		if commentHasSuppressionMarker(ctx.Lines[checkLine-1], ruleName) {
			return true
		}
	}
	return false
}

// LineSuppresses reports whether the line's comment part carries a
// suppression marker for the given rule (nolint:<rule> / <rule>: safe).
// Single canonical implementation — rules must delegate here instead of
// matching suppression strings themselves.
func LineSuppresses(line, ruleName string) bool {
	return commentHasSuppressionMarker(line, ruleName)
}

// commentHasSuppressionMarker checks the comment part of a line for
// suppression markers of the given rule.
func commentHasSuppressionMarker(line, ruleName string) bool {
	comment := commentPart(line)
	if comment == "" {
		return false
	}
	if nolintListContains(comment, ruleName) {
		return true
	}
	markers := []string{ruleName + ": safe", ruleName + ":safe"}
	for _, marker := range markers {
		idx := strings.Index(comment, marker)
		if idx < 0 {
			continue
		}
		// The character right after the rule name must not extend the name,
		// so "nolint:my-rule" never suppresses "my-rule-extended".
		end := idx + len(marker)
		if strings.HasSuffix(marker, ruleName) && end < len(comment) && isRuleNameChar(comment[end]) {
			continue
		}
		return true
	}
	return false
}

func nolintListContains(comment, ruleName string) bool {
	const prefix = "nolint:"
	idx := strings.Index(comment, prefix)
	if idx < 0 {
		return false
	}
	list := comment[idx+len(prefix):]
	if fields := strings.Fields(list); len(fields) > 0 {
		list = fields[0]
	}
	for _, name := range strings.Split(list, ",") {
		if strings.TrimSpace(name) == ruleName {
			return true
		}
	}
	return false
}

// commentPart returns the substring of the line starting at its comment
// marker ("//" or "/*"), or "" when the line has no comment. A marker inside
// a string literal is not treated as a comment start.
func commentPart(line string) string {
	inString := byte(0)
	for i := 0; i < len(line)-1; i++ {
		c := line[i]
		if inString != 0 {
			switch c {
			case '\\':
				i++
			case inString:
				inString = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			inString = c
		case '/':
			if line[i+1] == '/' || line[i+1] == '*' {
				return line[i:]
			}
		case '*':
			// Continuation line of a block comment ("  * text").
			if strings.TrimSpace(line[:i]) == "" {
				return line[i:]
			}
		}
	}
	return ""
}

// isRuleNameChar reports whether c can be part of a rule name.
func isRuleNameChar(c byte) bool {
	return c == '-' || c == '_' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
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
