package patternkit

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/rules/helpers"
	"go/types"
)

// CallsAny reports a call under node that pass accepts, outside func literals.
func CallsAny(node ast.Node, pass func(*ast.CallExpr) bool) bool {
	return helpers.ContainsNode[*ast.CallExpr](node, pass)
}

// TypeUnderlying returns the underlying type of t, nil for none.
func TypeUnderlying(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return t.Underlying()
}
