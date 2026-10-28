package patternkit

import (
	"go/ast"
	"go/types"
)

// DecimalGuards are the decimal methods that compare a value with zero or
// with another value.
var DecimalGuards = map[string]bool{
	"IsZero": true, "Sign": true, "Equal": true, "Equals": true, "Cmp": true, "Compare": true,
	"GreaterThan": true, "GreaterThanOrEqual": true, "LessThan": true, "LessThanOrEqual": true,
	"IsPositive": true, "IsNegative": true,
}

// StaticFunc returns the function a call names, nil for anything else.
func StaticFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		callee, _ := info.Uses[fun].(*types.Func)
		return callee
	case *ast.SelectorExpr:
		callee, _ := info.Uses[fun.Sel].(*types.Func)
		return callee
	}
	return nil
}
