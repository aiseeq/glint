package patternkit

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
)

// PackageFuncs indexes the package's own functions: "Func" for plain ones, "Type.Method" for methods.
func PackageFuncs(pkg *core.GoPackageContext) map[string]*ast.FuncDecl {
	decls := map[string]*ast.FuncDecl{}
	for _, file := range pkg.Files {
		if file == nil || file.GoAST == nil || file.IsTestFile() {
			continue
		}
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			key := fn.Name.Name
			if fn.Recv != nil {
				recv := ReceiverTypeName(fn.Recv)
				if recv == "" {
					continue
				}
				key = recv + "." + fn.Name.Name
			}
			decls[key] = fn
		}
	}
	return decls
}

// ReceiverTypeName renders the bare type name of a method receiver, pointer or not.
func ReceiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if index, ok := expr.(*ast.IndexExpr); ok { // обобщённый тип: Cache[T]
		expr = index.X
	}
	if index, ok := expr.(*ast.IndexListExpr); ok {
		expr = index.X
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

// NamedOf unwraps pointers and returns the named type, if any.
func NamedOf(typ types.Type) *types.Named {
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return nil
	}
	return named
}
