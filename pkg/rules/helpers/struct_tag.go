package helpers

import (
	"go/ast"
	"reflect"
	"strconv"
	"strings"
)

// ConfigTags mark a struct field as a configuration value: whoever runs the
// program writes it and expects it to take effect. json is left out, it
// marks payloads as often as configuration - a client of a third-party API
// declares the whole response and reads a part of it.
var ConfigTags = []string{"yaml", "toml", "mapstructure", "env", "ini", "koanf", "envconfig"}

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

// TagKeys returns the keys the tag gives its field under the named tags: the
// name before the first comma, without an empty name and "-".
func TagKeys(tag reflect.StructTag, names []string) []string {
	var keys []string
	for _, name := range names {
		content, found := tag.Lookup(name)
		if !found {
			continue
		}
		if key, _, _ := strings.Cut(content, ","); key != "" && key != "-" {
			keys = append(keys, key)
		}
	}
	return keys
}
