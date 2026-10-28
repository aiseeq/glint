package patternkit

import (
	"go/ast"
)

// ContainsNode reports whether inner lies within outer.
func ContainsNode(outer, inner ast.Node) bool {
	return outer.Pos() <= inner.Pos() && inner.End() <= outer.End()
}
