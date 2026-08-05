package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sync"
)

// Parser handles parsing of source files
type Parser struct {
	// Cache for parsed Go files
	cache   map[string]*parsedGoFile
	cacheMu sync.RWMutex
}

// parsedGoFile represents a cached parsed Go file
type parsedGoFile struct {
	FileSet *token.FileSet
	AST     *ast.File
	Err     error
}

// NewParser creates a new parser
func NewParser() *Parser {
	return &Parser{
		cache: make(map[string]*parsedGoFile),
	}
}

// ParseGoFile parses a Go file and returns its AST
func (p *Parser) ParseGoFile(path string, content []byte) (*token.FileSet, *ast.File, error) {
	// Check cache
	p.cacheMu.RLock()
	if cached, ok := p.cache[path]; ok {
		p.cacheMu.RUnlock()
		return cached.FileSet, cached.AST, cached.Err
	}
	p.cacheMu.RUnlock()

	// Parse the file
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, content, parser.ParseComments)

	// Cache the result
	p.cacheMu.Lock()
	p.cache[path] = &parsedGoFile{
		FileSet: fset,
		AST:     file,
		Err:     err,
	}
	p.cacheMu.Unlock()

	return fset, file, err
}

// ExtractFullFunctionName extracts the full function name (package.function)
func ExtractFullFunctionName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	default:
		return ""
	}
}
