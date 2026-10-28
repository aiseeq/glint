package patternkit

import (
	"go/ast"
	"go/types"
)

// SelectedField returns the field a selector expression selects, nil for
// anything else.
func SelectedField(expr ast.Expr, info *types.Info) *types.Var {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return nil
	}
	field, _ := selection.Obj().(*types.Var)
	return field
}
