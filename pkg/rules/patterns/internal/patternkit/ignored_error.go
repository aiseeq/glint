package patternkit

import (
	"go/types"
)

func IsErrorType(t types.Type) bool {
	if t == nil {
		return false
	}
	if types.Identical(t, types.Universe.Lookup("error").Type()) {
		return true
	}
	// Error is a structural interface contract. This also recognizes named
	// interfaces and concrete types that implement the same method.
	errorType, ok := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return types.AssignableTo(t, errorType) || types.Implements(t, errorType)
}
