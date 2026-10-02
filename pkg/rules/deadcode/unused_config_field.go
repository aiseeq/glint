package deadcode

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"reflect"
	"regexp"
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

// UnusedConfigFieldRule detects struct fields that are parsed from configuration
// or from a payload but never read anywhere in the code:
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
// A json payload field is left out, except a bool that flags the item unsafe
// or invalid (is_scam, failed): decoding it and never reading it lets the
// flagged items through. Only types that are actually decoded are examined: the rule follows the types
// reaching a decoder (Unmarshal, Decode, env Parse/Process and the like, taking
// the target as an untyped value) through their fields. A field only written —
// a default in a composite literal, an assignment — is still unused: the value
// from the configuration overwrites it and nothing reads it. Types that are also encoded
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

// AnalyzeGoProject finds the decoded types, then reports the tagged fields of
// the analyzed files that no compiled file reads. Writing a field — a default
// in a composite literal, an assignment — does not use it: the setting still
// does nothing.
func (r *UnusedConfigFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused config field: nil Go project context")
	}
	access, err := projectFieldAccess(ctx)
	if err != nil {
		return nil, fmt.Errorf("unused config field: %w", err)
	}

	// Test files are outside the typed load; a field used only by its
	// white-box test must still count as used.
	mentions, err := projectMentions(ctx)
	if err != nil {
		return nil, fmt.Errorf("unused config field: %w", err)
	}

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, field := range collectTaggedFields(fileCtx, info, access.decoded, access.encoded) {
			pos := field.obj.Pos()
			if access.read[pos] || access.hashed[pos] {
				continue
			}
			if mentions.mentioned(field.fileCtx, field.fieldName) {
				continue
			}
			violations = append(violations, r.report(field))
		}
		return violations
	})
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
				key, value, ok = safetyFlagTag(field)
			}
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

// safetyFlag names a payload flag that marks an item unsafe or invalid: an
// item carrying it must not be taken as a valid one.
var safetyFlag = regexp.MustCompile(`(?i)^(?:is_?)?(?:scam|spam|suspicious|phishing|fraud|malicious|honeypot|blacklisted|blocked|failed|reverted|deleted)$`)

// safetyFlagTag returns the json tag of a bool payload field that flags the
// item unsafe or invalid (is_scam, failed, reverted). Payload fields are left
// out of the rule, but a decoded safety flag nobody reads lets the flagged
// items through as valid ones.
func safetyFlagTag(field *ast.Field) (key, value string, ok bool) {
	if typ, isIdent := field.Type.(*ast.Ident); !isIdent || typ.Name != "bool" {
		return "", "", false
	}
	content, found := reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Lookup("json")
	if !found {
		return "", "", false
	}
	value = strings.Split(content, ",")[0]
	if !safetyFlag.MatchString(value) {
		return "", "", false
	}
	return "json", value, true
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
