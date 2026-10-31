package helpers

import (
	"go/ast"
	"go/types"
)

// FuncValues reports functions a package references outside call position.
// Call sites come from every file of the package because info.Uses covers
// the whole package: a call from another file is no function value.
func FuncValues(files []*ast.File, info *types.Info) map[*types.Func]bool {
	values := make(map[*types.Func]bool)
	if info == nil {
		return values
	}
	callees := make(map[*ast.Ident]bool)
	for _, file := range files {
		if file == nil {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident := CalleeIdent(call.Fun); ident != nil {
				callees[ident] = true
			}
			return true
		})
	}
	for ident, obj := range info.Uses {
		fn, ok := obj.(*types.Func)
		if ok && !callees[ident] {
			values[fn.Origin()] = true
		}
	}
	return values
}

// CalleeIdent returns the identifier naming the function a call invokes.
func CalleeIdent(fun ast.Expr) *ast.Ident {
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		return f
	case *ast.SelectorExpr:
		return f.Sel
	case *ast.IndexExpr:
		return CalleeIdent(f.X)
	case *ast.IndexListExpr:
		return CalleeIdent(f.X)
	}
	return nil
}
