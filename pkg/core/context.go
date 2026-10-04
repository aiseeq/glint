package core

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
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

	// shared holds views derived from the content (masked source and the
	// like), computed once per file for every rule that asks.
	shared sharedCache
}

// FileShared returns the value build derives from the file, building it once
// per file however many rules ask. key is a comparable value of a type private
// to the caller's package, so packages cannot collide. The value must not be
// modified by its users.
func FileShared[T any](ctx *FileContext, key any, build func() T) T {
	value, err := sharedGet(&ctx.shared, key, func() (T, error) { return build(), nil })
	if err != nil {
		// build cannot fail: only one key requested with two types gets here.
		panic(err)
	}
	return value
}

// NewFileContext creates a file context and panics on an invalid path pair.
// It exists for tests, which build contexts from literal paths; the analysis
// pipeline uses NewFileContextChecked and reports the error instead.
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
	return strings.HasSuffix(ctx.Path, ".ts") || strings.HasSuffix(ctx.Path, ".tsx") ||
		strings.HasSuffix(ctx.Path, ".mts") || strings.HasSuffix(ctx.Path, ".cts")
}

// IsJavaScriptFile returns true if this is a JavaScript file
func (ctx *FileContext) IsJavaScriptFile() bool {
	return strings.HasSuffix(ctx.Path, ".js") || strings.HasSuffix(ctx.Path, ".jsx") ||
		strings.HasSuffix(ctx.Path, ".mjs") || strings.HasSuffix(ctx.Path, ".cjs")
}

// IsShellFile returns true if this is a shell script
func (ctx *FileContext) IsShellFile() bool {
	return strings.HasSuffix(ctx.Path, ".sh")
}

// IsMakefile reports a make file: Makefile, GNUmakefile, makefile or *.mk.
func (ctx *FileContext) IsMakefile() bool {
	return isMakefileName(filepath.Base(ctx.Path))
}

func isMakefileName(name string) bool {
	switch name {
	case "Makefile", "GNUmakefile", "makefile":
		return true
	}
	return strings.HasSuffix(name, ".mk")
}

// IsDockerfile reports a container build file: Dockerfile, Dockerfile.<name>,
// <name>.dockerfile or Containerfile.
func (ctx *FileContext) IsDockerfile() bool {
	return isDockerfileName(filepath.Base(ctx.Path))
}

func isDockerfileName(name string) bool {
	switch {
	case name == "Dockerfile", name == "Containerfile":
		return true
	case strings.HasPrefix(name, "Dockerfile."), strings.HasPrefix(name, "Containerfile."):
		// Dockerfile.dockerignore is the ignore list of that Dockerfile.
		ext := strings.ToLower(filepath.Ext(name))
		return ext != ".md" && ext != ".txt" && ext != ".dockerignore"
	}
	return strings.HasSuffix(strings.ToLower(name), ".dockerfile")
}

// IsTestFile reports whether the file is test code: a Go _test.go file, a
// JS/TS *.test.* or *.spec.* file, or any file under a test directory of the
// project. Directories are matched in the project-relative path: the absolute
// one also names where the checkout lives, and a project cloned into
// /builds/test/ is not test code as a whole. A Go file named test_*.go is
// compiled into its package like any other and is not a test.
func (ctx *FileContext) IsTestFile() bool {
	name := filepath.Base(ctx.Path)

	if strings.HasSuffix(name, "_test.go") {
		return true
	}
	if strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") {
		return true
	}

	dir := "/" + filepath.ToSlash(filepath.Dir(ctx.RelPath)) + "/"
	for _, marker := range []string{"/test/", "/tests/", "/__tests__/", "/testdata/"} {
		if strings.Contains(dir, marker) {
			return true
		}
	}
	return false
}

// IsTestHelperDir reports whether dir holds a Go test-helper package, the idiom
// of net/http/httptest and testing/fstest: the package name ends in "test" and
// one of its files imports testing. Such a package is compiled like any other
// so that tests of several packages can share it, but its code is test code:
// fixtures built there are not the program's construction sites. The name
// alone is not enough — a package latest is not a test helper. It reads the
// other files of dir, so only project-wide rules may ask it; IsTestFile stays
// a property of the file alone.
func IsTestHelperDir(dir string) (bool, error) {
	if !strings.HasSuffix(filepath.Base(dir), "test") {
		return false, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("test helper dir %s: %w", dir, err)
	}
	fset := token.NewFileSet()
	named, imports := false, false
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.ImportsOnly)
		if err != nil {
			return false, fmt.Errorf("test helper dir %s: %w", dir, err)
		}
		named = named || strings.HasSuffix(f.Name.Name, "test")
		for _, im := range f.Imports {
			imports = imports || im.Path.Value == `"testing"`
		}
	}
	return named && imports, nil
}

// generatedMarker is the line the Go convention puts before the first code of
// a generated file (https://go.dev/s/generatedcode); code generators for other
// languages reuse it.
var generatedMarker = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

// IsGenerated reports whether the file is generated code: it carries the
// "// Code generated ... DO NOT EDIT." marker before its first code line.
// Nobody edits such a file by hand, so findings in it are not actionable.
func (ctx *FileContext) IsGenerated() bool {
	if ctx.GoAST != nil {
		return ast.IsGenerated(ctx.GoAST)
	}
	inBlock := false
	for _, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case inBlock:
			inBlock = !strings.Contains(trimmed, "*/")
		case generatedMarker.MatchString(strings.TrimRight(line, "\r")):
			return true
		case trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#!"):
		case strings.HasPrefix(trimmed, "/*"):
			inBlock = !strings.Contains(trimmed[2:], "*/")
		default:
			return false
		}
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
	// The list is comma-separated and may have spaces after the commas
	// (nolint:a, b). Prose after the last rule name ends the list: in
	// "nolint:a, b justified because" only "a" and "b" are rule names.
	for _, segment := range strings.Split(list, ",") {
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			return false
		}
		if fields[0] == ruleName {
			return true
		}
		if len(fields) > 1 {
			return false
		}
	}
	return false
}

// CommentPart returns the substring of a line starting at its comment marker
// ("//" or "/*"), or "" when the line has no comment. A marker inside a string
// literal is not a comment start — this is the single implementation rules
// must use when they match comment text, so that a regexp source containing
// "//" is not mistaken for a comment.
func CommentPart(line string) string {
	return commentPart(line)
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
			// Continuation line of a block comment ("  * text"). A name char
			// right after the star is a pointer dereference (*target = ...),
			// not a comment.
			if strings.TrimSpace(line[:i]) == "" && !isRuleNameChar(line[i+1]) {
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
	if node == nil || ctx.GoFileSet == nil {
		return token.Position{}
	}
	return ctx.GoFileSet.Position(node.Pos())
}

// LineFor returns the one-based source line for an AST node.
func (ctx *FileContext) LineFor(node ast.Node) int {
	if node == nil {
		return 1
	}
	return ctx.LineForPos(node.Pos())
}

// LineForPos returns the one-based source line for a position. Rules must use
// it rather than counting newlines in Content: token.Pos is an offset into the
// shared file set, not into a single file, so hand-rolled arithmetic silently
// reports the wrong line once several files share a set.
func (ctx *FileContext) LineForPos(pos token.Pos) int {
	if ctx.GoFileSet == nil || pos == token.NoPos {
		return 1
	}
	line := ctx.GoFileSet.Position(pos).Line
	if line < 1 {
		return 1
	}
	return line
}

// EnclosingFunction returns the name of the function or method declared
// around the given one-based line; "" when the line lies outside every
// declaration or the file has no Go AST. Methods report the bare method name,
// the same key rules use when they annotate findings themselves.
func (ctx *FileContext) EnclosingFunction(line int) string {
	if ctx.GoAST == nil || ctx.GoFileSet == nil {
		return ""
	}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := ctx.GoFileSet.Position(fn.Pos()).Line
		end := ctx.GoFileSet.Position(fn.End()).Line
		if line >= start && line <= end {
			return fn.Name.Name
		}
	}
	return ""
}

// AnnotateFunction records the enclosing function of a finding under
// Context["function"] unless the rule already named one, so that function
// exceptions in the configuration apply to every rule alike.
func (ctx *FileContext) AnnotateFunction(v *Violation) {
	if v == nil {
		return
	}
	if v.Context != nil {
		if _, ok := v.Context["function"]; ok {
			return
		}
	}
	if name := ctx.EnclosingFunction(v.Line); name != "" {
		v.WithContext("function", name)
	}
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
