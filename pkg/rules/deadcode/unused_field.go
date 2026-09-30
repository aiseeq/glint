package deadcode

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedFieldRule())
}

// UnusedFieldRule detects unexported struct fields that the package never reads:
//
//	type Cache struct {
//	    entries map[string]string
//	    hits    int      // counted on every Get, read by nobody
//	}
//
// A field only ever written is a computation whose result is discarded: the
// value costs memory per instance and, worse, tells the next reader that
// something keeps track of hits when nothing does.
//
// Unexported fields of the analyzed packages are considered, and on top of them
// the exported fields of a settings type — one whose name ends in Opts, Options,
// Config or Settings. An ordinary exported field belongs to the package's API and
// its reader may live outside the analyzed tree; a setting is different, because
// a setting nobody reads does nothing no matter who sets it, and setting it in a
// composite literal is what hides it from the compiler and from deadcode tools.
// Tagged fields belong to unused-config-field, which knows about values arriving
// from outside. Embedded and blank fields carry no name to use.
type UnusedFieldRule struct {
	*rules.BaseRule
}

// NewUnusedFieldRule creates the rule
func NewUnusedFieldRule() *UnusedFieldRule {
	return &UnusedFieldRule{
		BaseRule: rules.NewBaseRule(
			"unused-field",
			"deadcode",
			"Detects unexported struct fields that are never read — dead state kept up to date for nobody",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: the readers of a field may live in any file.
func (r *UnusedFieldRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *UnusedFieldRule) RequiresSSA() bool { return false }

// declaredField is a field of an analyzed struct type this rule judges.
type declaredField struct {
	obj       *types.Var
	named     *types.Named
	fileCtx   *core.FileContext
	line      int
	typeName  string
	fieldName string
	setting   bool
}

// AnalyzeGoProject reports the fields of the analyzed files that no compiled
// file reads. Every loaded package counts as a reader, whether or not its own
// files are analyzed.
func (r *UnusedFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused field: nil Go project context")
	}
	access, err := collectProjectFieldAccess(ctx)
	if err != nil {
		return nil, fmt.Errorf("unused field: %w", err)
	}

	// Test files are outside the typed load; a field read only by its
	// white-box test must still count as read.
	mentions := newTestMentions(ctx.Files)

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, field := range collectCheckedFields(fileCtx, info) {
			pos := field.obj.Pos()
			if access.read[pos] || access.hashed[pos] {
				continue
			}
			// An encoder reads every exported field on the program's behalf,
			// so a setting of a type that is marshalled is not dead.
			if field.setting && field.named != nil && access.encoded[field.named] {
				continue
			}
			if mentions.mentioned(field.fileCtx, field.fieldName) {
				continue
			}
			violations = append(violations, r.report(field, access.written[pos]))
		}
		return violations
	})
}

func (r *UnusedFieldRule) report(field declaredField, written bool) *core.Violation {
	state := "is never used"
	if written {
		state = "is kept up to date but never read"
	}
	message := fmt.Sprintf("Field %s.%s %s — the work maintaining it produces nothing",
		field.typeName, field.fieldName, state)
	if field.setting {
		message = fmt.Sprintf("Setting %s.%s is set but never read — the option does nothing, and the behaviour behind it is unreachable",
			field.typeName, field.fieldName)
	}
	v := r.CreateViolation(field.fileCtx.RelPath, field.line, message)
	v.WithCode(strings.TrimSpace(field.fileCtx.GetLine(field.line)))
	v.WithSuggestion(fmt.Sprintf("Use %s where its value is meant to matter, or delete the field and the code that fills it",
		field.fieldName))
	v.WithContext("pattern", "unused_field")
	v.WithContext("field", field.typeName+"."+field.fieldName)
	return v
}

// settingTypeSuffixes name the structs that carry behaviour switches.
var settingTypeSuffixes = []string{"Opts", "Options", "Config", "Settings"}

// isSettingType reports whether the type name says the struct holds settings.
func isSettingType(name string) bool {
	for _, suffix := range settingTypeSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// collectCheckedFields returns the untagged, named fields this rule judges: the
// unexported ones of any struct, and every field of a settings struct.
func collectCheckedFields(fileCtx *core.FileContext, info *types.Info) []declaredField {
	var fields []declaredField

	ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok || structType.Fields == nil {
			return true
		}
		if _, ok := declaredStructType(spec, info); !ok {
			return true
		}
		named, _ := declaredNamedType(spec, info)

		setting := isSettingType(spec.Name.Name)
		for _, field := range structType.Fields.List {
			if field.Tag != nil || len(field.Names) == 0 {
				continue // tagged fields and embedded ones are other rules' business
			}
			for _, name := range field.Names {
				if name.Name == "_" || (name.IsExported() && !setting) {
					continue
				}
				obj, ok := info.Defs[name].(*types.Var)
				if !ok {
					continue
				}
				fields = append(fields, declaredField{
					obj:       obj,
					named:     named,
					fileCtx:   fileCtx,
					line:      fileCtx.LineFor(name),
					typeName:  spec.Name.Name,
					fieldName: name.Name,
					setting:   setting && name.IsExported(),
				})
			}
		}
		return true
	})

	return fields
}

// declaredStructType returns the checked struct behind a type declaration.
func declaredStructType(spec *ast.TypeSpec, info *types.Info) (*types.Struct, bool) {
	obj, ok := info.Defs[spec.Name].(*types.TypeName)
	if !ok {
		return nil, false
	}
	structType, ok := obj.Type().Underlying().(*types.Struct)
	return structType, ok
}
