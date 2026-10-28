package patternkit

import (
	"go/ast"
)

func ReceiverName(fn *ast.FuncDecl) (string, bool) {
	if len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return "", false
	}
	name := fn.Recv.List[0].Names[0].Name
	if name == "" || name == "_" {
		return "", false
	}
	return name, true
}
