package helpers

import (
	"go/ast"
	"go/parser"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainsNode(t *testing.T) {
	expr, err := parser.ParseExpr(`outer(inner(), other())`)
	require.NoError(t, err)

	t.Run("match found", func(t *testing.T) {
		found := ContainsNode[*ast.CallExpr](expr, func(call *ast.CallExpr) bool {
			ident, ok := call.Fun.(*ast.Ident)
			return ok && ident.Name == "inner"
		})
		require.True(t, found)
	})

	t.Run("no match", func(t *testing.T) {
		found := ContainsNode[*ast.SelectorExpr](expr, func(*ast.SelectorExpr) bool {
			return true
		})
		require.False(t, found)
	})

	t.Run("nil root", func(t *testing.T) {
		require.False(t, ContainsNode[*ast.Ident](nil, func(*ast.Ident) bool {
			return true
		}))
	})
}
