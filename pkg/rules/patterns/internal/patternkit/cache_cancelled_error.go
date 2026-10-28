package patternkit

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// LooksAtContextError reports a function that reads the context's own error:
// ctx.Err(), context.Canceled, context.DeadlineExceeded.
func LooksAtContextError(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return !found
		}
		switch sel.Sel.Name {
		case "Err":
			found = types.TypeString(info.TypeOf(sel.X), nil) == "context.Context"
		case "Canceled", "DeadlineExceeded":
			found = helpers.IsIdentNamed(sel.X, "context")
		}
		return !found
	})
	return found
}
