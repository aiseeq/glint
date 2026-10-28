package patternkit

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// MentionsAnyObject reports an identifier of one of the objects inside node.
func MentionsAnyObject(info *types.Info, node ast.Node, objects map[types.Object]bool) bool {
	return helpers.ContainsNode[*ast.Ident](node, func(ident *ast.Ident) bool {
		return objects[info.ObjectOf(ident)]
	})
}
