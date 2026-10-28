package patternkit

import (
	"go/types"
)

// ImplementsError reports whether a result slot carries an error. An
// expression go/types records no type for - the blank identifier on the left
// of a plain = - carries nothing.
func ImplementsError(t types.Type) bool {
	return t != nil && types.AssignableTo(t, types.Universe.Lookup("error").Type())
}

func DerefStruct(t types.Type) (*types.Struct, bool) {
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}
