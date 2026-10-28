package patternkit

import (
	"go/ast"
	"go/types"
)

// IsDecimalZero reports decimal.Zero or decimal.NewFromInt(0).
func IsDecimalZero(info *types.Info, expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		obj := info.ObjectOf(e.Sel)
		return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == ShopspringDecimalPath && obj.Name() == "Zero"
	case *ast.CallExpr:
		fn := StaticFunc(info, e)
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != ShopspringDecimalPath || len(e.Args) != 1 {
			return false
		}
		lit, ok := e.Args[0].(*ast.BasicLit)
		return ok && lit.Value == "0"
	}
	return false
}
