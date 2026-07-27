package deadcode

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedConfigFieldRule())
}

// configTags are the tags of a configuration file: a value written by whoever
// runs the program, expecting it to take effect. Payload tags (json) are left
// out on purpose — a client of a third-party API legitimately declares the whole
// response and reads a part of it.
var configTags = []string{"yaml", "toml", "mapstructure", "env", "ini"}

// decodeFuncs fill a Go value from bytes: whatever they write into is a
// configuration or a payload the program receives.
var decodeFuncs = []string{"Unmarshal", "UnmarshalStrict", "Decode", "DecodeFile", "ReadConfig"}

// encodeFuncs turn a Go value into bytes: the encoder reads every exported
// field, so those fields are used even when no statement mentions them.
var encodeFuncs = []string{"Marshal", "MarshalIndent", "Encode", "NewEncoder"}

// UnusedConfigFieldRule detects struct fields that are parsed from configuration
// or from a payload but never mentioned anywhere in the code:
//
//	type RuleConfig struct {
//	    Enabled  bool   `yaml:"enabled"`
//	    Severity string `yaml:"severity"`  // parsed, never read
//	}
//
// Such a field makes the configuration lie: the user writes `severity: high`,
// the loader accepts it without complaint, and nothing changes. The failure is
// silent by construction — there is no error to see and no behaviour to notice.
//
// Only types that are actually decoded are examined: the rule follows the types
// reaching Unmarshal/Decode through their fields. Types that are also encoded
// are left alone, because there the encoder reads the field on the program's
// behalf.
type UnusedConfigFieldRule struct {
	*rules.BaseRule
}

// NewUnusedConfigFieldRule creates the rule
func NewUnusedConfigFieldRule() *UnusedConfigFieldRule {
	return &UnusedConfigFieldRule{
		BaseRule: rules.NewBaseRule(
			"unused-config-field",
			"deadcode",
			"Detects struct fields parsed from config or payloads that no code ever uses — the setting silently does nothing",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: deciding that nothing uses a field needs the whole
// project, not one file.
func (r *UnusedConfigFieldRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *UnusedConfigFieldRule) RequiresSSA() bool { return false }

// taggedField is a struct field that carries a serialization tag.
type taggedField struct {
	obj       *types.Var
	fileCtx   *core.FileContext
	line      int
	typeName  string
	fieldName string
	tagKey    string
	tagValue  string
}

// AnalyzeGoProject finds the decoded types, then reports their tagged fields
// that no compiled file mentions.
func (r *UnusedConfigFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused config field: nil Go project context")
	}

	decoded := make(map[*types.Named]bool)
	encoded := make(map[*types.Named]bool)
	used := make(map[*types.Var]bool)

	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("unused config field: package has no typed syntax")
		}
		for _, file := range pkg.Package.Syntax {
			collectSerializedTypes(file, pkg.Package.TypesInfo, decoded, encoded)
			collectFieldUses(file, pkg.Package.TypesInfo, used)
		}
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		info := pkg.Package.TypesInfo
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			for _, field := range collectTaggedFields(fileCtx, info, decoded, encoded) {
				if used[field.obj] {
					continue
				}
				violations = append(violations, r.report(field))
			}
		}
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *UnusedConfigFieldRule) report(field taggedField) *core.Violation {
	v := r.CreateViolation(field.fileCtx.RelPath, field.line,
		fmt.Sprintf("Field %s.%s is filled from %s:%q but no code ever uses it — the setting silently does nothing",
			field.typeName, field.fieldName, field.tagKey, field.tagValue))
	v.WithCode(strings.TrimSpace(field.fileCtx.GetLine(field.line)))
	v.WithSuggestion(fmt.Sprintf("Use %s where the setting is meant to take effect, or delete the field so the configuration stops accepting %q",
		field.fieldName, field.tagValue))
	v.WithContext("pattern", "unused_config_field")
	v.WithContext("field", field.typeName+"."+field.fieldName)
	return v
}

// collectSerializedTypes records the types that reach a decoder or an encoder,
// following their fields: a config struct is decoded as a whole, and its nested
// sections come from the same file.
func collectSerializedTypes(file *ast.File, info *types.Info, decoded, encoded map[*types.Named]bool) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call.Fun)
		if name == "" {
			return true
		}

		var target map[*types.Named]bool
		switch {
		case slices.Contains(decodeFuncs, name):
			target = decoded
		case slices.Contains(encodeFuncs, name):
			target = encoded
		default:
			return true
		}
		for _, arg := range call.Args {
			addReachableStructs(target, info.TypeOf(arg))
		}
		return true
	})
}

func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

// addReachableStructs walks a type and records every named struct it can reach
// through pointers, slices, maps and fields.
func addReachableStructs(set map[*types.Named]bool, t types.Type) {
	switch typ := t.(type) {
	case *types.Pointer:
		addReachableStructs(set, typ.Elem())
	case *types.Slice:
		addReachableStructs(set, typ.Elem())
	case *types.Array:
		addReachableStructs(set, typ.Elem())
	case *types.Map:
		addReachableStructs(set, typ.Elem())
	case *types.Named:
		if set[typ] {
			return
		}
		structType, ok := typ.Underlying().(*types.Struct)
		if !ok {
			return
		}
		set[typ] = true
		for i := range structType.NumFields() {
			addReachableStructs(set, structType.Field(i).Type())
		}
	case *types.Struct:
		for i := range typ.NumFields() {
			addReachableStructs(set, typ.Field(i).Type())
		}
	}
}

// collectTaggedFields returns the tagged fields of the file's decoded struct
// types. A type that is also encoded is skipped: its fields are read by the
// encoder, not ignored.
func collectTaggedFields(fileCtx *core.FileContext, info *types.Info, decoded, encoded map[*types.Named]bool) []taggedField {
	var fields []taggedField

	ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok || structType.Fields == nil {
			return true
		}
		named, ok := declaredNamedType(spec, info)
		if !ok || !decoded[named] || encoded[named] {
			return true
		}

		for _, field := range structType.Fields.List {
			if field.Tag == nil {
				continue
			}
			key, value, ok := configTag(field.Tag.Value)
			if !ok {
				continue
			}
			for _, name := range field.Names {
				obj, ok := info.Defs[name].(*types.Var)
				if !ok {
					continue
				}
				fields = append(fields, taggedField{
					obj:       obj,
					fileCtx:   fileCtx,
					line:      fileCtx.LineFor(name),
					typeName:  spec.Name.Name,
					fieldName: name.Name,
					tagKey:    key,
					tagValue:  value,
				})
			}
		}
		return true
	})

	return fields
}

func declaredNamedType(spec *ast.TypeSpec, info *types.Info) (*types.Named, bool) {
	obj, ok := info.Defs[spec.Name].(*types.TypeName)
	if !ok {
		return nil, false
	}
	named, ok := obj.Type().(*types.Named)
	return named, ok
}

// configTag returns the first configuration tag of the raw tag literal.
// A value of "-" means the field is deliberately excluded, so it does not count.
func configTag(raw string) (key, value string, ok bool) {
	unquoted := strings.Trim(raw, "`")
	tag := reflect.StructTag(unquoted)

	for _, name := range configTags {
		content, found := tag.Lookup(name)
		if !found {
			continue
		}
		value = strings.Split(content, ",")[0]
		if value == "-" || value == "" {
			continue
		}
		return name, value, true
	}
	return "", "", false
}

// collectFieldUses marks every field the file mentions: read or written through
// a selector, or named as a key in a composite literal.
func collectFieldUses(file *ast.File, info *types.Info, used map[*types.Var]bool) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			selection, ok := info.Selections[node]
			if !ok || selection.Kind() != types.FieldVal {
				return true
			}
			if field, ok := selection.Obj().(*types.Var); ok {
				used[field] = true
			}
		case *ast.CompositeLit:
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				ident, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if field, ok := info.Uses[ident].(*types.Var); ok {
					used[field] = true
				}
			}
		}
		return true
	})
}
