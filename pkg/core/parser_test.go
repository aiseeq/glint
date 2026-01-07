package core

import (
	"go/ast"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParser(t *testing.T) {
	p := NewParser()
	assert.NotNil(t, p)
	assert.Equal(t, 0, p.CacheSize())
}

func TestParserParseGoFile(t *testing.T) {
	p := NewParser()

	content := []byte("package main\n\nfunc main() {}\n")

	fset, file, err := p.ParseGoFile("test.go", content)
	require.NoError(t, err)
	assert.NotNil(t, fset)
	assert.NotNil(t, file)
	assert.Equal(t, "main", file.Name.Name)
}

func TestParserCache(t *testing.T) {
	p := NewParser()

	content := []byte("package main\n\nfunc main() {}\n")

	// First parse
	fset1, file1, err := p.ParseGoFile("test.go", content)
	require.NoError(t, err)
	assert.Equal(t, 1, p.CacheSize())

	// Second parse should hit cache
	fset2, file2, err := p.ParseGoFile("test.go", content)
	require.NoError(t, err)
	assert.Equal(t, 1, p.CacheSize())

	// Should return same cached objects
	assert.Same(t, fset1, fset2)
	assert.Same(t, file1, file2)
}

func TestParserClearCache(t *testing.T) {
	p := NewParser()

	content := []byte("package main")
	_, _, _ = p.ParseGoFile("test.go", content)
	assert.Equal(t, 1, p.CacheSize())

	p.ClearCache()
	assert.Equal(t, 0, p.CacheSize())
}

func TestParserParseError(t *testing.T) {
	p := NewParser()

	// Invalid Go code
	content := []byte("this is not valid go code {{{")

	_, _, err := p.ParseGoFile("invalid.go", content)
	assert.Error(t, err)
}

func TestGoASTVisitor(t *testing.T) {
	content := []byte(`package main

import "fmt"

func hello() {
	fmt.Println("hello")
}

func goodbye() {
	fmt.Println("goodbye")
}
`)
	cfg := DefaultConfig()
	ctx := NewFileContext("/project/test.go", "/project", content, cfg)

	// Parse the Go file
	p := NewParser()
	fset, astFile, err := p.ParseGoFile("/project/test.go", content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)

	// Track visited functions
	var funcNames []string

	visitor := NewGoASTVisitor(ctx)
	visitor.OnFuncDecl(func(fd *ast.FuncDecl) {
		funcNames = append(funcNames, fd.Name.Name)
	})
	visitor.Visit()

	assert.Contains(t, funcNames, "hello")
	assert.Contains(t, funcNames, "goodbye")
}

func TestGoASTVisitorCallExpr(t *testing.T) {
	content := []byte(`package main

import "fmt"

func main() {
	fmt.Println("hello")
	fmt.Printf("%s", "world")
}
`)
	cfg := DefaultConfig()
	ctx := NewFileContext("/project/test.go", "/project", content, cfg)

	// Parse the Go file
	p := NewParser()
	fset, astFile, err := p.ParseGoFile("/project/test.go", content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)

	var calls []string

	visitor := NewGoASTVisitor(ctx)
	visitor.OnCallExpr(func(ce *ast.CallExpr) {
		name := ExtractFunctionName(ce)
		if name != "" {
			calls = append(calls, name)
		}
	})
	visitor.Visit()

	assert.Contains(t, calls, "Println")
	assert.Contains(t, calls, "Printf")
}

func TestExtractFunctionName(t *testing.T) {
	content := []byte(`package main

import "fmt"

func localFunc() {}

func main() {
	localFunc()
	fmt.Println("hello")
}
`)
	cfg := DefaultConfig()
	ctx := NewFileContext("/project/test.go", "/project", content, cfg)

	// Parse the Go file
	p := NewParser()
	fset, astFile, err := p.ParseGoFile("/project/test.go", content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)

	var calls []string

	visitor := NewGoASTVisitor(ctx)
	visitor.OnCallExpr(func(ce *ast.CallExpr) {
		name := ExtractFunctionName(ce)
		if name != "" {
			calls = append(calls, name)
		}
	})
	visitor.Visit()

	assert.Contains(t, calls, "localFunc")
	assert.Contains(t, calls, "Println")
}

func TestExtractFullFunctionName(t *testing.T) {
	content := []byte(`package main

import "fmt"

func localFunc() {}

func main() {
	localFunc()
	fmt.Println("hello")
}
`)
	cfg := DefaultConfig()
	ctx := NewFileContext("/project/test.go", "/project", content, cfg)

	// Parse the Go file
	p := NewParser()
	fset, astFile, err := p.ParseGoFile("/project/test.go", content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)

	var calls []string

	visitor := NewGoASTVisitor(ctx)
	visitor.OnCallExpr(func(ce *ast.CallExpr) {
		name := ExtractFullFunctionName(ce)
		if name != "" {
			calls = append(calls, name)
		}
	})
	visitor.Visit()

	assert.Contains(t, calls, "localFunc")
	assert.Contains(t, calls, "fmt.Println")
}

func TestGoASTVisitorOnNoAST(t *testing.T) {
	// Test that visitor handles missing AST gracefully
	ctx := &FileContext{
		Path:   "/project/test.go",
		GoAST:  nil,
		Config: DefaultConfig(),
	}

	var called bool
	visitor := NewGoASTVisitor(ctx)
	visitor.OnFuncDecl(func(fd *ast.FuncDecl) {
		called = true
	})
	visitor.Visit()

	assert.False(t, called, "Visitor should not call callbacks when AST is nil")
}
