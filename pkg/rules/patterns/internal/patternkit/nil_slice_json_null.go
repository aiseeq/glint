package patternkit

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
)

// TypedFunc is a function declaration with the types of its package.
type TypedFunc struct {
	File *core.FileContext
	Info *types.Info
	Decl *ast.FuncDecl
}

// ProjectFuncDecls returns the function declarations of the analyzed
// production files.
func ProjectFuncDecls(ctx *core.GoProjectContext) []TypedFunc {
	var funcs []TypedFunc
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			for _, decl := range file.GoAST.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
					funcs = append(funcs, TypedFunc{File: file, Info: pkg.Package.TypesInfo, Decl: fn})
				}
			}
		}
	}
	return funcs
}

// ImplementedMethods returns the methods of project interfaces a method
// implements.
func ImplementedMethods(method *types.Func, interfaces []*types.TypeName) []*types.Func {
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	recv := sig.Recv().Type()
	var found []*types.Func
	for _, typeName := range interfaces {
		iface, ok := typeName.Type().Underlying().(*types.Interface)
		if !ok || !types.Implements(recv, iface) {
			continue
		}
		for m := range iface.Methods() {
			if m.Name() == method.Name() {
				found = append(found, m)
			}
		}
	}
	return found
}
