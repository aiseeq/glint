package patternkit

import (
	"go/ast"
	"go/types"
)

// MentionsObject reports an expression or a statement using the object.
func MentionsObject(info *types.Info, node ast.Node, obj types.Object) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && info.ObjectOf(id) == obj {
			found = true
		}
		return !found
	})
	return found
}
