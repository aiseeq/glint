package helpers

import (
	"go/ast"
	"go/types"
)

// IndexFuncDecls records in index the function and method declarations of
// file under the objects info defines for them, so a call resolved through
// info.Uses finds the declaration whatever its order or file.
func IndexFuncDecls(index map[*types.Func]*ast.FuncDecl, file *ast.File, info *types.Info) {
	if file == nil || info == nil {
		return
	}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name == nil {
			continue
		}
		if fn, ok := info.Defs[fd.Name].(*types.Func); ok {
			index[fn] = fd
		}
	}
}
