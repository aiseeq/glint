package patternkit

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"golang.org/x/tools/go/packages"
)

// CalleeFunc resolves the function a call refers to, if it is a plain function
// or method. Parentheses and the index of a generic instantiation are stepped
// through, so Do[int](x) resolves like Do(x).
func CalleeFunc(pkg *packages.Package, call *ast.CallExpr) *types.Func {
	var ident *ast.Ident
	fun := ast.Unparen(call.Fun)
	for {
		switch node := fun.(type) {
		case *ast.IndexExpr:
			fun = ast.Unparen(node.X)
			continue
		case *ast.IndexListExpr:
			fun = ast.Unparen(node.X)
			continue
		}
		break
	}
	switch node := fun.(type) {
	case *ast.Ident:
		ident = node
	case *ast.SelectorExpr:
		ident = node.Sel
	default:
		return nil
	}
	obj := pkg.TypesInfo.Uses[ident]
	if obj == nil {
		obj = pkg.TypesInfo.Defs[ident]
	}
	fn, _ := obj.(*types.Func)
	return fn
}

// IsGoTestFile reports whether the file is a _test.go one. This rule does not
// need it (the typed load has no test files); other rules of the package do.
func IsGoTestFile(ctx *core.GoProjectContext, file *ast.File) bool {
	if ctx.FileSet == nil {
		return false
	}
	name := ctx.FileSet.Position(file.Pos()).Filename
	return strings.HasSuffix(name, "_test.go")
}
