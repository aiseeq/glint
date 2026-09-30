package core

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// checkKnownKeys rejects mapping keys the configuration schema does not
// declare. yaml.v3 ignores unknown keys, so a typo such as "exeptions:" or
// "min_severty:" used to be read as "not set" and the setting silently did
// nothing. The check walks the document against the Go type it decodes into;
// KnownFields on the decoder is not enough, because the custom UnmarshalYAML
// methods decode their nodes with a fresh, non-strict decoder.
func checkKnownKeys(node *yaml.Node, typ reflect.Type, path string) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode || node.Kind == yaml.AliasNode {
		for _, child := range node.Content {
			if err := checkKnownKeys(child, typ, path); err != nil {
				return err
			}
		}
		if node.Kind == yaml.AliasNode {
			return checkKnownKeys(node.Alias, typ, path)
		}
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	switch typ.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return nil // a type mismatch is the decoder's error to report
		}
		fields := yamlFields(typ)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			field, ok := fields[key]
			if !ok {
				return fmt.Errorf("line %d: unknown key %q in %s", node.Content[i].Line, key, describePath(path))
			}
			if err := checkKnownKeys(node.Content[i+1], field, joinKeyPath(path, key)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if node.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if err := checkKnownKeys(node.Content[i+1], typ.Elem(), joinKeyPath(path, node.Content[i].Value)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode {
			return nil
		}
		for i, item := range node.Content {
			if err := checkKnownKeys(item, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	// Interface values (rule settings) have no schema here: each rule owns
	// the shape of its settings.
	return nil
}

// yamlFields maps the YAML key of every exported struct field to its type.
func yamlFields(typ reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(field.Name)
		}
		fields[name] = field.Type
	}
	return fields
}

func joinKeyPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func describePath(path string) string {
	if path == "" {
		return "the top level"
	}
	return path
}
