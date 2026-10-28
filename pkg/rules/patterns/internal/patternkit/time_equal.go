package patternkit

import (
	"go/types"
)

// IsTimeTimeType reports whether t is time.Time itself - not a pointer to it.
func IsTimeTimeType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "time" && named.Obj().Name() == "Time"
}
