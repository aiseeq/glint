package patternkit

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsErrorTypeRecognizesStructuralErrorInterfaces(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "errors.go", `package sample
type structural interface { Error() string }
type concrete struct{}
func (concrete) Error() string { return "" }
type unrelated interface { Code() int }
`, 0)
	if !assert.NoError(t, err) {
		return
	}
	pkg, err := (&types.Config{Importer: importer.Default()}).Check("sample", fset, []*ast.File{file}, nil)
	if !assert.NoError(t, err) {
		return
	}
	assert.True(t, IsErrorType(pkg.Scope().Lookup("structural").Type()))
	assert.True(t, IsErrorType(pkg.Scope().Lookup("concrete").Type()))
	assert.False(t, IsErrorType(pkg.Scope().Lookup("unrelated").Type()))
}
