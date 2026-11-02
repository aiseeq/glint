package deadcode

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNeverAssignedFieldRule())
}

// NeverAssignedFieldRule detects a dependency field that code reads but nothing
// ever assigns:
//
//	type Composer struct {
//	    logger  logging.Logger
//	    manager Manager
//	}
//
//	func newComposer(m Manager) *Composer {
//	    return &Composer{manager: m}   // logger stays nil
//	}
//
//	func (c *Composer) apply() {
//	    c.logger.Info("applied")       // nil dereference on the first call
//	}
//
// This is the mirror image of unused-field, and the dangerous half: unused-field
// finds state kept up to date for nobody, this rule finds state everybody trusts
// that nobody fills. It is exactly what a constructor loses when a field
// assignment is deleted while the field and its readers survive — the code still
// compiles and panics the first time the path runs.
//
// Only fields whose nil value can crash are considered — interface, map,
// channel, function, and pointer. A missing int or string is a wrong value; a
// missing interface is a crash. A slice is left out: ranging over a nil slice,
// taking its length and appending to it all work.
//
// A pointer field counts only where the read dereferences it (p.field.X,
// *p.field): an always-nil pointer that every caller nil-checks — the shape of
// an optional filter — misleads but does not crash, and belongs to
// unused-field's territory rather than here. A map field counts only where
// something stores into it (p.field[k] = v): reading a nil map yields the zero
// value, storing into one panics. A function field counts only when called;
// passing, returning, copying, or comparing it with nil is safe. An interface
// field counts when a method or nested selector is used through it, or when a
// type assertion without a comma-ok result is made; a comma-ok assertion and
// passing, returning, copying, or comparing it with nil are safe. A nil
// channel still counts on any use because it blocks or panics.
//
// A write of nil or (*T)(nil) gives the field no value. A literal of the type
// outside the functions that return it (its constructors) is reported when it
// leaves nil a field the constructors fill and the code uses that way: the
// value built around the constructor crashes where the constructed one works.
//
// Not flagged: fields written anywhere in the loaded packages, including
// positional composite literals (T{a, b, c}), which name no field and are
// therefore treated as writing all of them; tagged fields, and the exported
// fields of a type handed to a decoder (json.Unmarshal and the like), which
// reflection fills without any assignment appearing in the source.
type NeverAssignedFieldRule struct {
	*rules.BaseRule
}

// NewNeverAssignedFieldRule creates the rule
func NewNeverAssignedFieldRule() *NeverAssignedFieldRule {
	return &NeverAssignedFieldRule{
		BaseRule: rules.NewBaseRule(
			"never-assigned-field",
			"deadcode",
			"Detects nil-able struct fields that are used but never assigned — a guaranteed nil dereference",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile is a no-op: the writer of a field may live in any file.
func (r *NeverAssignedFieldRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NeverAssignedFieldRule) RequiresSSA() bool { return false }

// nilUse says which access to a nil field crashes.
type nilUse int

const (
	nilUseRead  nilUse = iota // chan: any use blocks or panics
	nilUseDeref               // pointer or interface: going through it
	nilUseStore               // map: storing into it
	nilUseCall                // func: calling it
)

// nilableField is a field of an analyzed struct whose zero value is nil.
type nilableField struct {
	obj       *types.Var
	named     *types.Named
	fileCtx   *core.FileContext
	line      int
	typeName  string
	fieldName string
	use       nilUse
}

// AnalyzeGoProject reports the nil-able fields of the analyzed files that are
// used in a way that crashes on nil but never written.
func (r *NeverAssignedFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("never assigned field: nil Go project context")
	}
	access, err := projectFieldAccess(ctx)
	if err != nil {
		return nil, fmt.Errorf("never assigned field: %w", err)
	}

	// Test files are outside the typed load; a test assigning the field
	// (fixture wiring) means it is not "never assigned".
	mentions, err := projectMentions(ctx)
	if err != nil {
		return nil, fmt.Errorf("never assigned field: %w", err)
	}

	testHelpers, err := testHelperPackages(ctx)
	if err != nil {
		return nil, fmt.Errorf("never assigned field: %w", err)
	}
	ctors := collectConstructorFields(ctx, testHelpers)
	fixtures := make(map[*core.FileContext]bool)
	for pkg := range testHelpers {
		for _, fileCtx := range pkg.Files {
			fixtures[fileCtx] = true
		}
	}

	return rules.AnalyzeTypedRunFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		// a fixture of a test-helper package fills only what its test needs,
		// as a literal in a _test.go file does
		if !fixtures[fileCtx] {
			violations = r.bypassingLiterals(fileCtx, info, ctors)
		}
		for _, field := range collectNilableFields(fileCtx, info) {
			pos := field.obj.Pos()
			if access.valueWritten[pos] || !crashingUse(field.use, access, pos) {
				continue
			}
			if field.obj.Exported() && field.named != nil && access.decoded[field.named] {
				continue // a decoder fills exported fields by name
			}
			if field.obj.Embedded() && mentions.mentionedAsField(field.fileCtx, field.fieldName) ||
				!field.obj.Embedded() && mentions.mentioned(field.fileCtx, field.fieldName) {
				continue
			}
			violations = append(violations, r.report(field))
		}
		return violations
	})
}

// crashingUse reports whether the field is used the way its nil value crashes.
func crashingUse(use nilUse, access *fieldAccess, pos token.Pos) bool {
	switch use {
	case nilUseDeref:
		return access.dereferenced[pos]
	case nilUseStore:
		return access.storedInto[pos]
	case nilUseCall:
		return access.called[pos]
	default:
		return access.read[pos]
	}
}

func (r *NeverAssignedFieldRule) report(field nilableField) *core.Violation {
	v := r.CreateViolation(field.fileCtx.RelPath, field.line,
		fmt.Sprintf("Field %s.%s is used but never assigned — it is nil on every instance, so the first use panics",
			field.typeName, field.fieldName))
	v.WithCode(strings.TrimSpace(field.fileCtx.GetLine(field.line)))
	v.WithSuggestion(fmt.Sprintf("Assign %s in the constructor, or delete the field and the code that uses it",
		field.fieldName))
	v.WithContext("pattern", "never_assigned_field")
	v.WithContext("field", field.typeName+"."+field.fieldName)
	return v
}

// collectNilableFields returns the file's struct fields whose zero value is nil.
func collectNilableFields(fileCtx *core.FileContext, info *types.Info) []nilableField {
	var fields []nilableField

	ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok || structType.Fields == nil {
			return true
		}
		named, _ := declaredNamedType(spec, info)

		for _, field := range structType.Fields.List {
			// Тегированные поля заполняет рефлексия (json.Unmarshal, sql.Scan, yaml):
			// явного присваивания там нет по построению.
			if field.Tag != nil {
				continue
			}
			use, ok := nilUseOf(info.TypeOf(field.Type))
			if !ok {
				continue
			}
			if len(field.Names) == 0 {
				if named == nil {
					continue
				}
				structFields, ok := named.Underlying().(*types.Struct)
				if !ok {
					continue
				}
				for obj := range structFields.Fields() {
					if obj.Name() != embeddedFieldName(field.Type) {
						continue
					}
					fields = append(fields, nilableField{
						obj:       obj,
						named:     named,
						fileCtx:   fileCtx,
						line:      fileCtx.LineFor(field),
						typeName:  spec.Name.Name,
						fieldName: obj.Name(),
						use:       use,
					})
					break
				}
				continue
			}
			for _, name := range field.Names {
				if name.Name == "_" {
					continue
				}
				obj, ok := info.Defs[name].(*types.Var)
				if !ok {
					continue
				}
				fields = append(fields, nilableField{
					obj:       obj,
					named:     named,
					fileCtx:   fileCtx,
					line:      fileCtx.LineFor(name),
					typeName:  spec.Name.Name,
					fieldName: name.Name,
					use:       use,
				})
			}
		}
		return true
	})

	return fields
}

func embeddedFieldName(expr ast.Expr) string {
	switch typ := expr.(type) {
	case *ast.Ident:
		return typ.Name
	case *ast.SelectorExpr:
		return typ.Sel.Name
	case *ast.StarExpr:
		return embeddedFieldName(typ.X)
	case *ast.IndexExpr:
		return embeddedFieldName(typ.X)
	case *ast.IndexListExpr:
		return embeddedFieldName(typ.X)
	case *ast.ParenExpr:
		return embeddedFieldName(typ.X)
	default:
		return ""
	}
}

// nilUseOf reports whether a missing assignment of a field of type t can turn
// a use into a panic rather than into a merely wrong value, and which use.
func nilUseOf(t types.Type) (nilUse, bool) {
	if t == nil {
		return 0, false
	}
	switch t.Underlying().(type) {
	case *types.Pointer:
		return nilUseDeref, true
	case *types.Map:
		return nilUseStore, true
	case *types.Interface:
		return nilUseDeref, true
	case *types.Signature:
		return nilUseCall, true
	case *types.Chan:
		return nilUseRead, true
	}
	return 0, false
}
