package patternkit

import (
	"go/ast"
	"go/types"
)

// IsPkgFunc reports a call of the function name of package path.
func IsPkgFunc(info *types.Info, call *ast.CallExpr, path, name string) bool {
	fn := StaticFunc(info, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == path && fn.Name() == name
}
