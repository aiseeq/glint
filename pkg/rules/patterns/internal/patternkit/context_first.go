package patternkit

import (
	"go/ast"
)

func QualifiedFuncName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	if typeName := ReceiverTypeName(fn.Recv); typeName != "" {
		return typeName + "." + fn.Name.Name
	}
	return fn.Name.Name
}
