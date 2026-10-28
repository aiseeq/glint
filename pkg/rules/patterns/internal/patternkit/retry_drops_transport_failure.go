package patternkit

import (
	"go/ast"
)

// EndsWithReturn reports whether the loop body cannot reach a next iteration.
func EndsWithReturn(body *ast.BlockStmt) bool {
	return TrailingReturn(body) != nil
}

// TrailingReturn returns the return statement a block ends with, if any.
func TrailingReturn(block *ast.BlockStmt) *ast.ReturnStmt {
	if block == nil || len(block.List) == 0 {
		return nil
	}
	ret, _ := block.List[len(block.List)-1].(*ast.ReturnStmt)
	return ret
}

// ReturnsIdent reports whether the return hands the named value to the caller,
// either directly or inside a wrapping call.
func ReturnsIdent(ret *ast.ReturnStmt, name string) bool {
	for _, result := range ret.Results {
		if MentionsIdent(result, name) {
			return true
		}
	}
	return false
}

// MentionsIdent reports whether the expression reads the named variable.
func MentionsIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}
