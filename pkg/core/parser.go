package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"hash/fnv"
	"sync"
)

// Parser handles parsing of source files
type Parser struct {
	// Cache for parsed Go files
	cache   map[goFileCacheKey]*parsedGoFile
	cacheMu sync.RWMutex
}

// goFileCacheKey identifies a parsed file by path and content, so that parsing
// the same path with different content never returns a stale AST.
type goFileCacheKey struct {
	path        string
	contentLen  int
	contentHash uint64
}

func newGoFileCacheKey(path string, content []byte) goFileCacheKey {
	hash := fnv.New64a()
	hash.Write(content) // fnv.Write never returns an error
	return goFileCacheKey{
		path:        path,
		contentLen:  len(content),
		contentHash: hash.Sum64(),
	}
}

// parsedGoFile represents a cached parsed Go file
type parsedGoFile struct {
	FileSet *token.FileSet
	AST     *ast.File
	Err     error
}

// sharedParser is the process-wide parser. The walker and rules that parse
// files beyond their own FileContext share it, so the same content of a file
// is parsed at most once per process.
var sharedParser = NewParser()

// SharedParser returns the process-wide parser instance. Its cache keys on
// path and content, so sharing it never yields a stale AST.
func SharedParser() *Parser {
	return sharedParser
}

// NewParser creates a new parser
func NewParser() *Parser {
	return &Parser{
		cache: make(map[goFileCacheKey]*parsedGoFile),
	}
}

// ParseGoFile parses a Go file and returns its AST
func (p *Parser) ParseGoFile(path string, content []byte) (*token.FileSet, *ast.File, error) {
	key := newGoFileCacheKey(path, content)

	// Check cache
	p.cacheMu.RLock()
	if cached, ok := p.cache[key]; ok {
		p.cacheMu.RUnlock()
		return cached.FileSet, cached.AST, cached.Err
	}
	p.cacheMu.RUnlock()

	// Parse the file
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, content, parser.ParseComments)

	// Cache the result
	p.cacheMu.Lock()
	p.cache[key] = &parsedGoFile{
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
