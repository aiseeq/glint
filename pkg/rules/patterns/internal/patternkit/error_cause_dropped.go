package patternkit

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// ErrNilCheckName returns the identifier compared with nil in `X != nil`, or "".
func ErrNilCheckName(cond ast.Expr) string {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return ""
	}
	ident, ok := bin.X.(*ast.Ident)
	if !ok || !helpers.IsNilIdent(bin.Y) || !IsErrorVarName(ident.Name) {
		return ""
	}
	return ident.Name
}
