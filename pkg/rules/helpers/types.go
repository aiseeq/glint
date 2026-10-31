package helpers

import (
	"go/ast"
	"go/types"
)

// DeclaredStructType returns the underlying struct declared by spec.
func DeclaredStructType(spec *ast.TypeSpec, info *types.Info) (*types.Struct, bool) {
	obj, ok := info.Defs[spec.Name].(*types.TypeName)
	if !ok {
		return nil, false
	}
	structType, ok := obj.Type().Underlying().(*types.Struct)
	return structType, ok
}

// StructUnder returns the underlying struct after dereferencing one pointer.
func StructUnder(t types.Type) (*types.Struct, bool) {
	if t == nil {
		return nil, false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}
