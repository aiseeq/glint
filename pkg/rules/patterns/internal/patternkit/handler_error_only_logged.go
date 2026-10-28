package patternkit

import (
	"go/ast"
	"go/types"
)

// TakesResponseWriter reports a function with an http.ResponseWriter
// parameter.
func TakesResponseWriter(info *types.Info, ftype *ast.FuncType) bool {
	for _, field := range ftype.Params.List {
		if IsNamedType(info.TypeOf(field.Type), "net/http", "ResponseWriter") {
			return true
		}
	}
	return false
}
