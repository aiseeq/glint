package patterns

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/types/typeutil"
)

// isPackageFuncCall reports whether call invokes the package-level function
// pkgPath.name for one of names. With type information the callee is resolved
// by go/types; without it only a selector on an identifier the file imports as
// pkgPath is recognized — a name the file does not import is not guessed.
func isPackageFuncCall(file *ast.File, info *types.Info, call *ast.CallExpr, pkgPath string, names ...string) bool {
	name, ok := packageFuncName(file, info, call, pkgPath)
	if !ok {
		return false
	}
	for _, want := range names {
		if name == want {
			return true
		}
	}
	return false
}

// packageFuncName returns the name of the package-level function of pkgPath
// that call invokes.
func packageFuncName(file *ast.File, info *types.Info, call *ast.CallExpr, pkgPath string) (string, bool) {
	if info != nil {
		fn := typeutil.StaticCallee(info, call)
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != pkgPath {
			return "", false
		}
		if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
			return "", false
		}
		return fn.Name(), true
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || file == nil || importAliases(file)[pkg.Name] != pkgPath {
		return "", false
	}
	return sel.Sel.Name, true
}

// isNamedType reports whether t (not a pointer to it) is the named type
// pkgPath.name.
func isNamedType(t types.Type, pkgPath, name string) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == pkgPath && named.Obj().Name() == name
}

// isPointerToNamedType reports whether t is *pkgPath.name.
func isPointerToNamedType(t types.Type, pkgPath, name string) bool {
	if t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	return ok && isNamedType(ptr.Elem(), pkgPath, name)
}

// firstResultType returns the type of the first value an expression yields:
// the expression's own type, or the first element of a multi-value call.
func firstResultType(info *types.Info, expr ast.Expr) types.Type {
	if info == nil {
		return nil
	}
	t := info.TypeOf(expr)
	if tuple, ok := t.(*types.Tuple); ok {
		if tuple.Len() == 0 {
			return nil
		}
		return tuple.At(0).Type()
	}
	return t
}

// isContextTypeExpr reports whether a type expression names context.Context:
// by its type when info is available, otherwise by the file's import of
// "context".
func isContextTypeExpr(file *ast.File, info *types.Info, expr ast.Expr) bool {
	if info != nil {
		return isNamedType(info.TypeOf(expr), "context", "Context")
	}
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Context" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && file != nil && importAliases(file)[pkg.Name] == "context"
}

// contextParams reports whether the signature takes a context.Context at all
// (accepts) and whether one is bound to a name the body can use (live). A
// context declared as `_` or left unnamed is accepted but not live: the
// function deliberately discards the caller's context.
func contextParams(file *ast.File, info *types.Info, funcType *ast.FuncType) (accepts, live bool) {
	if funcType == nil || funcType.Params == nil {
		return false, false
	}
	for _, param := range funcType.Params.List {
		if !isContextTypeExpr(file, info, param.Type) {
			continue
		}
		accepts = true
		for _, name := range param.Names {
			if name.Name != "_" {
				live = true
			}
		}
	}
	return accepts, live
}
