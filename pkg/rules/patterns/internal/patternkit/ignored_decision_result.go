package patternkit

import (
	"go/types"
)

func IsBoolType(t types.Type) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Bool
}
