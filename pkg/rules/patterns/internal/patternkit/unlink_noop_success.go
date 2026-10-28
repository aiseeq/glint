package patternkit

import (
	"go/types"
)

// StructUnder returns the struct under a type or a pointer to it.
func StructUnder(t types.Type) *types.Struct {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	st, _ := t.Underlying().(*types.Struct)
	return st
}
