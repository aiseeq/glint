package deadcode

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// receiverTypeName extracts the type name of a method receiver. It unwraps
// pointer receivers and generic receivers (Box[T], Pair[K, V]), so the
// finding names the method as "Box.Close" rather than ".Close".
func receiverTypeName(field *ast.Field) string {
	return helpers.ReceiverTypeName(field.Type)
}
