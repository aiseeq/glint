package concurrencyrules

import (
	"bufio"
	"bytes"
	"cmp"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// escapeNote is one line of the compiler's escape analysis (go build
// -gcflags=-m): what it says about the expression at line:col of a file.
type escapeNote struct {
	line, col int
	// expr is the expression as the compiler prints it: "make([]int, n)",
	// "... argument", "func literal", or the variable of "moved to heap: x".
	expr  string
	heap  bool
	moved bool
}

// escapeNotes is the escape analysis of the packages that hold hot
// functions, by absolute file name.
type escapeNotes struct {
	fset   *token.FileSet
	sizes  types.Sizes
	byFile map[string][]escapeNote
}

// escapeNotesKey caches the escape analysis of one run per reach.
type escapeNotesKey struct{ transitive bool }

// compilerEscapes runs go build -gcflags=-m over the packages that hold hot
// functions, module by module, and collects what the compiler says goes to
// the heap and what stays on the stack. The go command replays the output
// of an unchanged package from its build cache, so a second run does not
// compile again. The compiler reads the files from disk: a file whose
// content glint got from elsewhere is analyzed as it is on disk. A build
// that fails is an error, not an empty analysis.
func compilerEscapes(ctx *core.GoProjectContext, hot map[*ast.FuncDecl]hotFunction, transitive bool) (*escapeNotes, error) {
	return core.Shared(ctx, escapeNotesKey{transitive: transitive}, func() (*escapeNotes, error) {
		byModule := map[string][]string{}
		var modules []string
		for _, pkg := range ctx.Packages {
			if pkg == nil || pkg.Package == nil || !holdsHotFunction(pkg.Package.Syntax, hot) {
				continue
			}
			dir := ctx.ProjectRoot
			if pkg.Package.Module != nil && pkg.Package.Module.Dir != "" {
				dir = pkg.Package.Module.Dir
			}
			if _, seen := byModule[dir]; !seen {
				modules = append(modules, dir)
			}
			byModule[dir] = append(byModule[dir], pkg.Package.PkgPath)
		}
		notes := &escapeNotes{fset: ctx.FileSet, sizes: types.SizesFor("gc", runtime.GOARCH), byFile: map[string][]escapeNote{}}
		for _, dir := range modules {
			args := append([]string{"build", "-o", os.DevNull, "-gcflags=-m"}, byModule[dir]...)
			cmd := exec.Command("go", args...)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				return nil, fmt.Errorf("escape analysis: go %s in %s: %w\n%s", strings.Join(args, " "), dir, err, out)
			}
			if err := notes.parse(dir, out); err != nil {
				return nil, err
			}
		}
		return notes, nil
	})
}

// holdsHotFunction reports whether a file of the package declares a hot
// function.
func holdsHotFunction(files []*ast.File, hot map[*ast.FuncDecl]hotFunction) bool {
	for _, file := range files {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				if _, isHot := hot[fn]; isHot {
					return true
				}
			}
		}
	}
	return false
}

// escapeLinePattern is a line of compiler output about a position:
// file:line:col: message. The file name is matched greedily, so a Windows
// drive letter stays part of it.
var escapeLinePattern = regexp.MustCompile(`^(.+):(\d+):(\d+): (.*)$`)

// parse collects the escape lines of go build -gcflags=-m output run in dir:
// "file:line:col: X escapes to heap", "...: moved to heap: x",
// "...: X does not escape". Inlining reports, leaking parameters and package
// headers are not about allocations and are skipped.
func (e *escapeNotes) parse(dir string, out []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		file, note, ok, err := parseEscapeLine(scanner.Text())
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if !filepath.IsAbs(file) {
			file = filepath.Join(dir, file)
		}
		e.byFile[filepath.Clean(file)] = append(e.byFile[filepath.Clean(file)], note)
	}
	return scanner.Err()
}

// parseEscapeLine reads one line of the compiler's escape output; ok is
// false for a line that is not an escape note.
func parseEscapeLine(text string) (file string, note escapeNote, ok bool, err error) {
	m := escapeLinePattern.FindStringSubmatch(text)
	if m == nil {
		return "", escapeNote{}, false, nil
	}
	if note.line, err = strconv.Atoi(m[2]); err != nil {
		return "", escapeNote{}, false, fmt.Errorf("escape analysis line %q: %w", text, err)
	}
	if note.col, err = strconv.Atoi(m[3]); err != nil {
		return "", escapeNote{}, false, fmt.Errorf("escape analysis line %q: %w", text, err)
	}
	switch msg := m[4]; {
	case strings.HasPrefix(msg, "moved to heap: "):
		note.expr, note.heap, note.moved = strings.TrimPrefix(msg, "moved to heap: "), true, true
	case strings.HasSuffix(msg, " escapes to heap"):
		note.expr, note.heap = strings.TrimSuffix(msg, " escapes to heap"), true
	case strings.HasSuffix(msg, " does not escape"):
		note.expr = strings.TrimSuffix(msg, " does not escape")
	default:
		return "", escapeNote{}, false, nil
	}
	return m[1], note, true, nil
}

// escapeSite is an expression of a hot function the compiler can speak
// about, with the column it reports it at.
type escapeSite struct {
	node ast.Node
	text string
}

// sitesOf indexes the expressions of a function body by the line and column
// the compiler reports them at: a call at its parenthesis, a composite
// literal at its brace, a conversion at its operand, anything else at its
// start.
func (e *escapeNotes) sitesOf(fn *ast.FuncDecl) map[[2]int][]escapeSite {
	sites := map[[2]int][]escapeSite{}
	add := func(pos token.Pos, node ast.Node, text string) {
		p := e.fset.Position(pos)
		key := [2]int{p.Line, p.Column}
		sites[key] = append(sites[key], escapeSite{node: node, text: text})
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			text := escapeExprText(node)
			add(node.Lparen, node, text)
			add(node.Lparen, node, "... argument")
			if len(node.Args) == 1 {
				add(node.Args[0].Pos(), node, text)
			}
		case *ast.CompositeLit:
			add(node.Lbrace, node, escapeExprText(node))
		case *ast.FuncLit:
			add(node.Pos(), node, "func literal")
		case *ast.Ident:
			add(node.Pos(), node, node.Name)
		case ast.Expr:
			add(node.Pos(), node, escapeExprText(node))
		}
		return true
	})
	return sites
}

// escapeExprText prints an expression the way the compiler does: a composite
// literal with elements as {...}.
func escapeExprText(expr ast.Expr) string {
	return strings.ReplaceAll(types.ExprString(expr), "…", "...")
}

// funcEscapes is the escape analysis of one function body.
type funcEscapes struct {
	notes *escapeNotes
	sites map[[2]int][]escapeSite
	lines []escapeNote
}

// forFunc returns the escape analysis of a function body.
func (e *escapeNotes) forFunc(fn *ast.FuncDecl) *funcEscapes {
	file := filepath.Clean(e.fset.Position(fn.Pos()).Filename)
	start, end := e.fset.Position(fn.Body.Pos()).Line, e.fset.Position(fn.Body.End()).Line
	var lines []escapeNote
	for _, note := range e.byFile[file] {
		if note.line >= start && note.line <= end {
			lines = append(lines, note)
		}
	}
	return &funcEscapes{notes: e, sites: e.sitesOf(fn), lines: lines}
}

// stays reports an allocation the compiler keeps on the stack. A make with a
// size known only at run time is not one even when the compiler says it
// does not escape: its backing array goes to the heap unless the size turns
// out tiny.
func (f *funcEscapes) stays(info *types.Info, node ast.Node) bool {
	if call, ok := node.(*ast.CallExpr); ok && len(call.Args) > 1 {
		for _, size := range call.Args[1:] {
			if info.Types[size].Value == nil {
				return false
			}
		}
	}
	for _, note := range f.lines {
		if note.heap {
			continue
		}
		for _, site := range f.sites[[2]int{note.line, note.col}] {
			if site.node == node && site.text == note.expr {
				return true
			}
		}
	}
	return false
}

// heapFindings returns what the compiler puts on the heap in the function
// body and the syntax checks of the rule did not report: a value boxed into
// an interface, a variable moved to the heap, a closure, variadic arguments,
// a conversion. A constant or a zero-size value in an interface does not
// allocate, and a note that matches no expression of the body comes from a
// function inlined into it: neither is reported.
func (f *funcEscapes) heapFindings(info *types.Info, reported map[ast.Node]bool, in string) []patternkit.FuncFinding {
	var findings []patternkit.FuncFinding
	seen := map[ast.Node]bool{}
	for _, note := range f.lines {
		if !note.heap {
			continue
		}
		for _, site := range f.sites[[2]int{note.line, note.col}] {
			if site.text != note.expr || reported[site.node] || seen[site.node] || !f.notes.allocates(info, site.node, note) {
				continue
			}
			seen[site.node] = true
			findings = append(findings, patternkit.FuncFinding{Node: site.node, Message: escapeMessage(note, site) + in + " (compiler escape analysis)"})
			break
		}
	}
	slices.SortFunc(findings, func(a, b patternkit.FuncFinding) int { return cmp.Compare(a.Node.Pos(), b.Node.Pos()) })
	return findings
}

// allocates reports whether what the compiler puts on the heap costs an
// allocation: not a constant, not a value of zero size.
func (e *escapeNotes) allocates(info *types.Info, node ast.Node, note escapeNote) bool {
	if note.moved {
		ident, ok := node.(*ast.Ident)
		if !ok || info.Defs[ident] == nil {
			return false
		}
		return e.sizes.Sizeof(info.Defs[ident].Type()) > 0
	}
	expr, ok := node.(ast.Expr)
	if !ok || note.expr == "... argument" || note.expr == "func literal" {
		return true
	}
	tv, typed := info.Types[expr]
	if !typed || tv.Value != nil {
		return false
	}
	t := tv.Type
	if unary, isUnary := expr.(*ast.UnaryExpr); isUnary && unary.Op == token.AND {
		if ptr, isPtr := t.Underlying().(*types.Pointer); isPtr {
			t = ptr.Elem()
		}
	}
	return e.sizes.Sizeof(t) > 0
}

// escapeMessage describes a heap note for a finding.
func escapeMessage(note escapeNote, site escapeSite) string {
	switch {
	case note.moved:
		return "the compiler moves " + note.expr + " to the heap"
	case note.expr == "... argument":
		if call, ok := site.node.(*ast.CallExpr); ok {
			return "the variadic arguments of " + types.ExprString(call.Fun) + " escape to the heap"
		}
	case note.expr == "func literal":
		return "a closure escapes to the heap"
	}
	return note.expr + " escapes to the heap"
}
