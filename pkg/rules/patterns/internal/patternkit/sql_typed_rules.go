package patternkit

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// MentionsObject reports an expression or a statement using the object.
func MentionsObject(info *types.Info, node ast.Node, obj types.Object) bool {
	return helpers.ContainsNode[*ast.Ident](node, func(id *ast.Ident) bool {
		return info.ObjectOf(id) == obj
	})
}
