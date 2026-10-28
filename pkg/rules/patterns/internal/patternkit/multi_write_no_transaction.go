package patternkit

import (
	"go/ast"
	"go/types"
	"regexp"
)

// MultiWriteStoreType is the default store_types: the receiver types that
// count as a store.
var MultiWriteStoreType = regexp.MustCompile(`(?i)(repo|repository|store|dao)(interface|impl)?$`)

// ReturnsError reports whether the call's last result is an error.
func ReturnsError(call *ast.CallExpr, info *types.Info) bool {
	signature, ok := info.TypeOf(call.Fun).(*types.Signature)
	return ok && LastResultIsError(signature)
}

// LastResultIsError reports whether the signature's last result is an error.
func LastResultIsError(signature *types.Signature) bool {
	if signature == nil || signature.Results().Len() == 0 {
		return false
	}
	return IsErrorType(signature.Results().At(signature.Results().Len() - 1).Type())
}

// IsPackageLevelVar reports whether the variable is declared at package level:
// a sentinel error such as ErrNotFound.
func IsPackageLevelVar(obj *types.Var) bool {
	return obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope()
}

// IsContextArg reports whether the argument is a context.Context.
func IsContextArg(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == "Context" && obj.Pkg() != nil && obj.Pkg().Path() == "context"
}

// MutationCalleeName returns the called function name without the receiver.
func MutationCalleeName(fun ast.Expr) string {
	switch v := fun.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

// TypeBaseName returns the named type behind pointers and aliases.
func TypeBaseName(t types.Type) string {
	for {
		switch v := t.(type) {
		case *types.Pointer:
			t = v.Elem()
		case *types.Named:
			return v.Obj().Name()
		default:
			return ""
		}
	}
}
