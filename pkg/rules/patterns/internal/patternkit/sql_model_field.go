package patternkit

import (
	"github.com/aiseeq/glint/pkg/sqlschema"
)

// Shape returns the shape of the statement, reading it without the operands
// that are not literals when it does not parse with them as parameters.
func (l SqlLiteral) Shape(schema *sqlschema.Schema) (*sqlschema.Shape, bool) {
	if shape, ok := schema.Shape(l.Text); ok {
		return shape, true
	}
	if l.Bare == "" {
		return nil, false
	}
	return schema.Shape(l.Bare)
}
