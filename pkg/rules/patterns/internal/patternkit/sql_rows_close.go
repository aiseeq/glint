package patternkit

import (
	"go/types"
)

// rowsCursorMethods are the methods every SQL row cursor has; *sql.Row lacks
// Close and Next, url.Values lacks them all.
var rowsCursorMethods = []string{"Close", "Next", "Scan", "Err"}

// IsRowsType reports whether t is *database/sql.Rows or a cursor type with
// the same methods.
func IsRowsType(t types.Type) bool {
	if t == nil {
		return false
	}
	if IsPointerToNamedType(t, "database/sql", "Rows") {
		return true
	}
	for _, method := range rowsCursorMethods {
		obj, _, _ := types.LookupFieldOrMethod(t, true, nil, method)
		if _, isMethod := obj.(*types.Func); !isMethod {
			return false
		}
	}
	return true
}
