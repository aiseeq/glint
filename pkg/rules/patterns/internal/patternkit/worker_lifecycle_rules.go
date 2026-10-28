package patternkit

import (
	"go/ast"
	"go/types"
)

// RequestParam returns the *http.Request parameter of a handler
// (http.ResponseWriter, *http.Request); nil for another function.
func RequestParam(info *types.Info, fn *ast.FuncDecl) types.Object {
	var writer bool
	var request types.Object
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			obj := info.ObjectOf(name)
			if obj == nil {
				continue
			}
			if IsNamedType(obj.Type(), "net/http", "ResponseWriter") {
				writer = true
			}
			if IsPointerToNamedType(obj.Type(), "net/http", "Request") {
				request = obj
			}
		}
	}
	if !writer {
		return nil
	}
	return request
}

// ParamAt returns the object of the i-th parameter of a declaration.
func ParamAt(decl TypedFuncDecl, i int) types.Object {
	n := 0
	for _, field := range decl.Decl.Type.Params.List {
		for _, name := range field.Names {
			if n == i {
				return decl.Info.ObjectOf(name)
			}
			n++
		}
	}
	return nil
}
