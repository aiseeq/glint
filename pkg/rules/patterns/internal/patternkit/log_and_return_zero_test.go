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

func TestIsZeroValueExprRecognizesConstantZeroExpressions(t *testing.T) {
	for _, source := range []string{`int64(0)`, `-0`, `""`, `nil`, `config{}`, `[]int{}`} {
		t.Run(source, func(t *testing.T) {
			file, err := parser.ParseExpr(source)
			if !assert.NoError(t, err) {
				return
			}
			assert.True(t, IsZeroValueExpr(file), source)
		})
	}
	for _, source := range []string{`1`, `true`, `config{Value: 1}`, `[]int{1}`, `0 * 12`, `5 - 5`, `7 * 0`} {
		t.Run(source, func(t *testing.T) {
			expr, err := parser.ParseExpr(source)
			if !assert.NoError(t, err) {
				return
			}
			assert.False(t, IsZeroValueExpr(expr), source)
		})
	}
}

func TestIsZeroValueExprUsesTypedConstantValuesSafely(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "typed.go", "package p\nconst Shift = 1 << 20\nconst ZeroShift = 0 << 3\n", 0)
	if !assert.NoError(t, err) {
		return
	}
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue)}
	_, err = (&types.Config{Importer: importer.Default()}).Check("p", fileSet, []*ast.File{file}, info)
	if !assert.NoError(t, err) {
		return
	}
	values := map[string]bool{"Shift": false, "ZeroShift": true}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				assert.Equal(t, values[name.Name], IsZeroValueExpr(value.Values[i], info), name.Name)
			}
		}
	}
	shifted, err := parser.ParseExpr("1 << 20")
	if !assert.NoError(t, err) {
		return
	}
	assert.NotPanics(t, func() { assert.False(t, IsZeroValueExpr(shifted)) })
	division, err := parser.ParseExpr("1 / 0")
	if !assert.NoError(t, err) {
		return
	}
	assert.NotPanics(t, func() { assert.False(t, IsZeroValueExpr(division)) })
	assert.NotPanics(t, func() { assert.False(t, IsZeroValueExpr(division, info)) })
}
