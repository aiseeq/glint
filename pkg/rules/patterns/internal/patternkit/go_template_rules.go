package patternkit

import (
	"go/types"
)

// ElementType returns what a range over t yields, nil when unknown.
func ElementType(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	switch u := t.Underlying().(type) {
	case *types.Slice:
		return u.Elem()
	case *types.Array:
		return u.Elem()
	case *types.Map:
		return u.Elem()
	case *types.Chan:
		return u.Elem()
	}
	return nil
}
