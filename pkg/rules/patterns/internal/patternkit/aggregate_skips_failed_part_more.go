package patternkit

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func IsLenCall(expr ast.Expr) bool {
	return LenArgument(expr) != nil
}

// LenArgument returns x of len(x), or nil.
func LenArgument(expr ast.Expr) ast.Expr {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || !helpers.IsIdentNamed(call.Fun, "len") || len(call.Args) != 1 {
		return nil
	}
	return call.Args[0]
}
