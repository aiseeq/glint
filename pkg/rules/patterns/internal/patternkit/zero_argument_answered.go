package patternkit

import (
	"go/ast"
	"go/types"
)

// ParamObjects returns the parameter variables of a declaration in order.
func ParamObjects(fn TypedFuncDecl) []*types.Var {
	var params []*types.Var
	for _, field := range fn.Decl.Type.Params.List {
		if _, variadic := field.Type.(*ast.Ellipsis); variadic {
			break
		}
		for _, name := range field.Names {
			v, _ := fn.Info.Defs[name].(*types.Var)
			params = append(params, v)
		}
		if len(field.Names) == 0 {
			params = append(params, nil)
		}
	}
	return params
}
