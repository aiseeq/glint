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

// ClearCache clears the parser cache
func (p *Parser) ClearCache() {
	p.cacheMu.Lock()
	p.cache = make(map[string]*parsedGoFile)
	p.cacheMu.Unlock()
}

// CacheSize returns the number of cached files
func (p *Parser) CacheSize() int {
	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()
	return len(p.cache)
}

// GoASTVisitor is a helper for visiting Go AST nodes
type GoASTVisitor struct {
	ctx      *FileContext
	visitors map[string]func(ast.Node)
}

// NewGoASTVisitor creates a new AST visitor
func NewGoASTVisitor(ctx *FileContext) *GoASTVisitor {
	return &GoASTVisitor{
		ctx:      ctx,
		visitors: make(map[string]func(ast.Node)),
	}
}

// OnFuncDecl registers a callback for function declarations
func (v *GoASTVisitor) OnFuncDecl(fn func(*ast.FuncDecl)) *GoASTVisitor {
	v.visitors["FuncDecl"] = func(n ast.Node) {
		if fd, ok := n.(*ast.FuncDecl); ok {
			fn(fd)
		}
	}
	return v
}

// OnCallExpr registers a callback for call expressions
func (v *GoASTVisitor) OnCallExpr(fn func(*ast.CallExpr)) *GoASTVisitor {
	v.visitors["CallExpr"] = func(n ast.Node) {
		if ce, ok := n.(*ast.CallExpr); ok {
			fn(ce)
		}
	}
	return v
}

// OnAssignStmt registers a callback for assignment statements
func (v *GoASTVisitor) OnAssignStmt(fn func(*ast.AssignStmt)) *GoASTVisitor {
	v.visitors["AssignStmt"] = func(n ast.Node) {
		if as, ok := n.(*ast.AssignStmt); ok {
			fn(as)
		}
	}
	return v
}

// OnReturnStmt registers a callback for return statements
func (v *GoASTVisitor) OnReturnStmt(fn func(*ast.ReturnStmt)) *GoASTVisitor {
	v.visitors["ReturnStmt"] = func(n ast.Node) {
		if rs, ok := n.(*ast.ReturnStmt); ok {
			fn(rs)
		}
	}
	return v
}

// OnIfStmt registers a callback for if statements
func (v *GoASTVisitor) OnIfStmt(fn func(*ast.IfStmt)) *GoASTVisitor {
	v.visitors["IfStmt"] = func(n ast.Node) {
		if is, ok := n.(*ast.IfStmt); ok {
			fn(is)
		}
	}
	return v
}

// OnTypeSpec registers a callback for type specifications
func (v *GoASTVisitor) OnTypeSpec(fn func(*ast.TypeSpec)) *GoASTVisitor {
	v.visitors["TypeSpec"] = func(n ast.Node) {
		if ts, ok := n.(*ast.TypeSpec); ok {
			fn(ts)
		}
	}
	return v
}

// OnStructType registers a callback for struct types
func (v *GoASTVisitor) OnStructType(fn func(*ast.StructType)) *GoASTVisitor {
	v.visitors["StructType"] = func(n ast.Node) {
		if st, ok := n.(*ast.StructType); ok {
			fn(st)
		}
	}
	return v
}

// OnInterfaceType registers a callback for interface types
func (v *GoASTVisitor) OnInterfaceType(fn func(*ast.InterfaceType)) *GoASTVisitor {
	v.visitors["InterfaceType"] = func(n ast.Node) {
		if it, ok := n.(*ast.InterfaceType); ok {
			fn(it)
		}
	}
	return v
}

// Visit walks the AST and calls registered visitors
func (v *GoASTVisitor) Visit() {
	if !v.ctx.HasGoAST() {
		return
	}

	ast.Inspect(v.ctx.GoAST, func(n ast.Node) bool {
		if n == nil {
			return false
		}

		for _, visitor := range v.visitors {
			visitor(n)
		}

		return true
	})
}

// ExtractFunctionName extracts the function name from a CallExpr
func ExtractFunctionName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	default:
		return ""
	}
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
