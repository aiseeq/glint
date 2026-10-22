package helpers

import (
	"go/ast"
	"reflect"
	"strconv"
)

// FieldTag returns the parsed tag of a struct field, empty for a field
// without one; a tag the compiler would reject reads as empty.
func FieldTag(field *ast.Field) reflect.StructTag {
	if field.Tag == nil {
		return ""
	}
	raw, err := strconv.Unquote(field.Tag.Value)
	if err == nil {
		return reflect.StructTag(raw)
	}
	return ""
}
