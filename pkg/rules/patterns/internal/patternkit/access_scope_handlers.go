package patternkit

import (
	"go/ast"
	"go/types"
)

// MentionsAnyObject reports an identifier of one of the objects inside node.
func MentionsAnyObject(info *types.Info, node ast.Node, objects map[types.Object]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && objects[info.ObjectOf(ident)] {
			found = true
		}
		return !found
	})
	return found
}
