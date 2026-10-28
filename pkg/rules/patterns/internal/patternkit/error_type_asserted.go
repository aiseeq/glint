package patternkit

import (
	"go/types"
)

// IsErrorInterface reports the predeclared error interface.
func IsErrorInterface(t types.Type) bool {
	return t != nil && types.Identical(t, types.Universe.Lookup("error").Type())
}
