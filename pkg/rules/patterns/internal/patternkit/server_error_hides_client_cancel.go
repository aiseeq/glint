package patternkit

import (
	"go/ast"
	"go/constant"
	"go/types"
)

// ConstantInt resolves an expression to its integer constant value, if it has one.
func ConstantInt(info *types.Info, expr ast.Expr) (int64, bool) {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil {
		return 0, false
	}
	value := constant.ToInt(tv.Value)
	if value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(value)
}
