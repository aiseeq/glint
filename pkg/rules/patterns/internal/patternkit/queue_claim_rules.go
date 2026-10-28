package patternkit

import (
	"go/ast"
	"go/types"
)

// CallsAny reports a call under node that pass accepts, outside func literals.
func CallsAny(node ast.Node, pass func(*ast.CallExpr) bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && pass(call) {
			found = true
		}
		return !found
	})
	return found
}

// TypeUnderlying returns the underlying type of t, nil for none.
func TypeUnderlying(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return t.Underlying()
}
