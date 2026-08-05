package deadcode

import (
	"fmt"
	"go/ast"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedSymbolsRule())
}

// UnusedSymbolsRule detects unexported symbols that appear unused within their file
type UnusedSymbolsRule struct {
	*rules.BaseRule

	// identCounts caches, per package directory, how often each identifier
	// appears in it. Without the cache every file reparsed all of its siblings,
	// which made the work quadratic in the size of a package — on saga this rule
	// alone took 7.7s of the 17s all file rules needed together.
	mu          sync.Mutex
	identCounts map[string]map[string]int
}

// NewUnusedSymbolsRule creates the rule
func NewUnusedSymbolsRule() *UnusedSymbolsRule {
	return &UnusedSymbolsRule{
		BaseRule: rules.NewBaseRule(
			"unused-symbol",
			"deadcode",
			"Detects unexported functions, types, and variables that appear unused within their file",
			core.SeverityLow,
		),
		identCounts: make(map[string]map[string]int),
	}
}

// ResetState drops the per-directory cache, so a second project root never
// inherits the counts of the first.
func (r *UnusedSymbolsRule) ResetState() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identCounts = make(map[string]map[string]int)
}

// symbolInfo tracks a declared symbol
type symbolInfo struct {
	kind   string // "func", "type", "const", "var"
	line   int
	node   ast.Node
	usages int
}

// AnalyzeFile checks for unused symbols
func (r *UnusedSymbolsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	// Skip test files - they often have helper functions
	if ctx.IsTestFile() {
		return nil
	}

	// Collect all unexported symbol declarations
	symbols := make(map[string]*symbolInfo)

	// First pass: collect declarations
	for _, decl := range ctx.GoAST.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			r.collectFunc(ctx, d, symbols)

		case *ast.GenDecl:
			r.collectGenDecl(ctx, d, symbols)
		}
	}

	// If no symbols to check, return early
	if len(symbols) == 0 {
		return nil
	}

	// Second pass: count usages in current file
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			if sym, exists := symbols[ident.Name]; exists {
				// Check if this is not the declaration itself
				if !r.isDeclaration(ident, sym) {
					sym.usages++
				}
			}
		}
		return true
	})

	// Third pass: check usages in sibling files (same package)
	// This catches cross-file usage within the same Go package
	if err := r.checkSiblingFileUsages(ctx, symbols); err != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "Unused-symbol analysis failed: "+err.Error())
		v.Severity = core.SeverityCritical
		v.WithCode(ctx.RelPath)
		v.WithSuggestion("Fix filesystem access or invalid sibling Go source, then rerun analysis")
		return []*core.Violation{v}
	}

	// Generate violations for unused symbols
	var violations []*core.Violation
	for _, name := range slices.Sorted(maps.Keys(symbols)) {
		sym := symbols[name]
		if sym.usages == 0 {
			v := r.CreateViolation(ctx.RelPath, sym.line,
				"Unexported "+sym.kind+" '"+name+"' appears to be unused")
			v.WithCode(ctx.GetLine(sym.line))
			v.WithSuggestion("Remove unused " + sym.kind + " or export it if intended for external use")
			v.WithContext("symbol", name)
			v.WithContext("kind", sym.kind)
			violations = append(violations, v)
		}
	}

	return violations
}

// checkSiblingFileUsages adds the usages a symbol has in the other files of its
// package. The counts come from a per-directory cache built once, rather than by
// reparsing every sibling for every file.
func (r *UnusedSymbolsRule) checkSiblingFileUsages(ctx *core.FileContext, symbols map[string]*symbolInfo) error {
	dir := filepath.Dir(ctx.Path)
	counts, err := r.directoryIdentCounts(dir)
	if err != nil {
		return fmt.Errorf("count identifiers of package %q: %w", dir, err)
	}

	own := identCountsOf(ctx.GoAST)
	for name, sym := range symbols {
		if siblings := counts[name] - own[name]; siblings > 0 {
			sym.usages += siblings
		}
	}
	return nil
}

// directoryIdentCounts returns how often each identifier appears across the Go
// files of a directory, parsing them once. Test files are counted too: an
// unexported symbol used only by tests is not dead code.
//
// Siblings go through core.SharedParser: the walker parses every analyzed file
// into the same content-keyed cache, so this sweep reuses those ASTs instead
// of parsing the whole project a second time.
func (r *UnusedSymbolsRule) directoryIdentCounts(dir string) (map[string]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if counts, ok := r.identCounts[dir]; ok {
		return counts, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read package directory %q: %w", dir, err)
	}

	counts := make(map[string]int)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read sibling file %q: %w", path, err)
		}
		_, file, err := core.SharedParser().ParseGoFile(path, content)
		if err != nil {
			return nil, fmt.Errorf("parse sibling file %q: %w", path, err)
		}
		for name, count := range identCountsOf(file) {
			counts[name] += count
		}
	}

	r.identCounts[dir] = counts
	return counts, nil
}

// identCountsOf counts every identifier occurrence in a syntax tree.
func identCountsOf(file *ast.File) map[string]int {
	counts := make(map[string]int)
	ast.Inspect(file, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			counts[ident.Name]++
		}
		return true
	})
	return counts
}

// collectFunc collects function declarations
func (r *UnusedSymbolsRule) collectFunc(ctx *core.FileContext, fn *ast.FuncDecl, symbols map[string]*symbolInfo) {
	name := fn.Name.Name

	// Skip exported functions
	if ast.IsExported(name) {
		return
	}

	// Skip main, init, and test functions
	if name == "main" || name == "init" {
		return
	}

	// Skip methods - they might implement interfaces
	if fn.Recv != nil {
		return
	}

	pos := ctx.PositionFor(fn.Name)
	symbols[name] = &symbolInfo{
		kind: "function",
		line: pos.Line,
		node: fn,
	}
}

// collectGenDecl collects type, const, and var declarations
func (r *UnusedSymbolsRule) collectGenDecl(ctx *core.FileContext, decl *ast.GenDecl, symbols map[string]*symbolInfo) {
	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			name := s.Name.Name
			if !ast.IsExported(name) {
				pos := ctx.PositionFor(s.Name)
				symbols[name] = &symbolInfo{
					kind: "type",
					line: pos.Line,
					node: s,
				}
			}

		case *ast.ValueSpec:
			for _, ident := range s.Names {
				name := ident.Name
				// Skip blank identifier and exported names
				if name == "_" || ast.IsExported(name) {
					continue
				}

				pos := ctx.PositionFor(ident)
				kind := "variable"
				if decl.Tok.String() == "const" {
					kind = "constant"
				}

				symbols[name] = &symbolInfo{
					kind: kind,
					line: pos.Line,
					node: s,
				}
			}
		}
	}
}

// isDeclaration checks if an identifier is the declaration itself
func (r *UnusedSymbolsRule) isDeclaration(ident *ast.Ident, sym *symbolInfo) bool {
	switch node := sym.node.(type) {
	case *ast.FuncDecl:
		return ident == node.Name
	case *ast.TypeSpec:
		return ident == node.Name
	case *ast.ValueSpec:
		for _, name := range node.Names {
			if ident == name {
				return true
			}
		}
	}
	return false
}
