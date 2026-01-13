package deadcode

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedSymbolsRule())
}

// UnusedSymbolsRule detects unexported symbols that appear unused within their file
type UnusedSymbolsRule struct {
	*rules.BaseRule
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
	}
}

// symbolInfo tracks a declared symbol
type symbolInfo struct {
	name   string
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
	r.checkSiblingFileUsages(ctx, symbols)

	// Generate violations for unused symbols
	var violations []*core.Violation
	for name, sym := range symbols {
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

// checkSiblingFileUsages checks for symbol usages in other files of the same package
func (r *UnusedSymbolsRule) checkSiblingFileUsages(ctx *core.FileContext, symbols map[string]*symbolInfo) {
	// Get the directory containing this file
	dir := filepath.Dir(ctx.Path)

	// List all .go files in the directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	currentFile := filepath.Base(ctx.Path)
	fset := token.NewFileSet()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Skip current file, test files, and non-Go files
		if name == currentFile || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		// Parse sibling file
		siblingPath := filepath.Join(dir, name)
		siblingAST, err := parser.ParseFile(fset, siblingPath, nil, 0)
		if err != nil {
			continue
		}

		// Check for usages of our symbols in this sibling file
		ast.Inspect(siblingAST, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok {
				if sym, exists := symbols[ident.Name]; exists {
					sym.usages++
				}
			}
			return true
		})
	}
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
		name: name,
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
					name: name,
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
					name: name,
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
