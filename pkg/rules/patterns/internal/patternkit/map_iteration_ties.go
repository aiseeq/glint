package patternkit

import (
	"go/ast"
	"go/token"
	"go/types"
)

func IsComparison(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
		return true
	}
	return false
}

func TypeOrNil(info *types.Info, expr ast.Expr) types.Type {
	if t := info.TypeOf(expr); t != nil {
		return t
	}
	return types.Typ[types.Invalid]
}
