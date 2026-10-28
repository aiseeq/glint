package patternkit

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
)

// InsideNodes reports whether node lies inside one of the nodes.
func InsideNodes(nodes []ast.Node, node ast.Node) bool {
	for _, n := range nodes {
		if n.Pos() <= node.Pos() && node.End() <= n.End() {
			return true
		}
	}
	return false
}

// HotRaisesSeverity is the severity of a finding whose cost is small in
// ordinary code and matters in a function marked //glint:hot: medium there,
// low elsewhere.
func HotRaisesSeverity(fn *ast.FuncDecl) core.Severity {
	if HasDirective(fn.Doc, HotFunctionDirective) {
		return core.SeverityMedium
	}
	return core.SeverityLow
}
