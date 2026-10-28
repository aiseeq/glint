package patternkit

import (
	"go/types"
)

// IsBooleanType reports whether t is a boolean type: bool, an untyped boolean
// constant or a named type whose underlying type is bool.
func IsBooleanType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsBoolean != 0
}
