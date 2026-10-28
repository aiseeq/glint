package patternkit

import (
	"go/ast"
	"go/types"
	"slices"
)

// UsesOf returns the identifiers that use one of the objects, in order.
func UsesOf(info *types.Info, root ast.Node, objs []types.Object) []*ast.Ident {
	var uses []*ast.Ident
	ast.Inspect(root, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && slices.Contains(objs, info.Uses[ident]) {
			uses = append(uses, ident)
		}
		return true
	})
	return uses
}
