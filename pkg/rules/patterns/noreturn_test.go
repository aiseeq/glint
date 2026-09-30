package patterns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const noReturnSource = `package p

import (
	"log"
	stdos "os"
	"runtime"
	"testing"
)

type logger struct{}

func (logger) Fatal(string) {}

func calls(t *testing.T, tb testing.TB, l *log.Logger, own logger, panic2 func(any)) {
	panic("x")
	stdos.Exit(1)
	log.Fatalf("x")
	log.Panicln("x")
	runtime.Goexit()
	l.Fatal("x")
	t.Fatalf("x")
	tb.FailNow()
	t.SkipNow()
	own.Fatal("x")
	log.Printf("x")
	panic2("x")
	t.Errorf("x")
}
`

func TestCallNoReturn(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", noReturnSource, parser.SkipObjectResolution)
	require.NoError(t, err)
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: stdImporter}
	_, err = conf.Check("p", fset, []*ast.File{file}, info)
	require.NoError(t, err)

	var body []ast.Stmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "calls" {
			body = fn.Body.List
		}
	}
	require.Len(t, body, 13)

	typed := []noReturnKind{
		callUnwinds, callExits, callExits, callUnwinds, callUnwinds, callExits,
		callUnwinds, callUnwinds, callUnwinds, callReturns, callReturns, callReturns, callReturns,
	}
	// Without types only the builtin and the imported package functions resolve.
	untyped := []noReturnKind{
		callUnwinds, callExits, callExits, callUnwinds, callUnwinds, callReturns,
		callReturns, callReturns, callReturns, callReturns, callReturns, callReturns, callReturns,
	}
	for i, stmt := range body {
		assert.Equal(t, typed[i], stmtNoReturn(stmt, info, file), "typed statement %d", i)
		assert.Equal(t, untyped[i], stmtNoReturn(stmt, nil, file), "untyped statement %d", i)
	}
}
