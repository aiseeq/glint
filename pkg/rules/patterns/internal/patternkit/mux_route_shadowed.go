package patternkit

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
)

// StringConstant returns the value of a constant string expression; without
// type information, of a string literal.
func StringConstant(info *types.Info, expr ast.Expr) (string, bool) {
	if info == nil {
		lit, ok := ast.Unparen(expr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(lit.Value)
		return text, err == nil
	}
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}
