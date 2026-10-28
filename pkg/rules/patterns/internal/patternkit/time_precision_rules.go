package patternkit

import (
	"go/ast"
	"go/types"
)

// ParamObject returns the parameter of a declaration at an argument index,
// nil past the last fixed parameter.
func ParamObject(decl TypedFuncDecl, index int) types.Object {
	i := 0
	for _, field := range decl.Decl.Type.Params.List {
		if _, variadic := field.Type.(*ast.Ellipsis); variadic {
			return nil
		}
		for _, name := range field.Names {
			if i == index {
				return decl.Info.Defs[name]
			}
			i++
		}
	}
	return nil
}
