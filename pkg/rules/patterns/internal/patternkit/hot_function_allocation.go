package patternkit

import (
	"go/ast"
	"go/types"
	"strings"
)

// HotFunctionDirective marks a function as a hot path: a line of its doc
// comment, spelled like a compiler directive (no space after the slashes).
const HotFunctionDirective = "//glint:hot"

// HasDirective reports whether a line of the comment group is the directive.
func HasDirective(doc *ast.CommentGroup, directive string) bool {
	if doc == nil {
		return false
	}
	for _, c := range doc.List {
		if strings.TrimSpace(c.Text) == directive {
			return true
		}
	}
	return false
}

// BuiltinCallName returns the name of the builtin a call invokes, "" for
// any other call.
func BuiltinCallName(info *types.Info, call *ast.CallExpr) string {
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return ""
	}
	if builtin, isBuiltin := info.Uses[ident].(*types.Builtin); isBuiltin {
		return builtin.Name()
	}
	return ""
}
