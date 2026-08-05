package deadcode

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
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
// Only fields whose type can be nil are considered — interface, map, channel,
// function, and pointer. A missing int or string is a wrong value; a missing
// interface is a crash. Fields of basic types are also routinely filled by
// reflection (json.Unmarshal, sql.Scan), where the absence of an explicit
// assignment is normal and this rule would only produce noise.
//
// A pointer field counts as read only where the read dereferences it
// (p.field.X, *p.field): an always-nil pointer that every caller nil-checks —
// the shape of an optional filter — misleads but does not crash, and belongs to
// unused-field's territory rather than here.
//
// Not flagged: fields written anywhere in the analyzed packages, including
// positional composite literals (T{a, b, c}), which name no field and are
// therefore treated as writing all of them; and tagged fields, which reflection
// fills without any assignment appearing in the source.
type NeverAssignedFieldRule struct {
	*rules.BaseRule
}

// NewNeverAssignedFieldRule creates the rule
func NewNeverAssignedFieldRule() *NeverAssignedFieldRule {
	return &NeverAssignedFieldRule{
		BaseRule: rules.NewBaseRule(
			"never-assigned-field",
			"deadcode",
			"Detects nil-able struct fields that are read but never assigned — a guaranteed nil dereference",
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

// nilableField is a field of an analyzed struct whose zero value is nil.
type nilableField struct {
	pos       token.Pos
	fileCtx   *core.FileContext
	line      int
	typeName  string
	fieldName string
	pointer   bool // требует разыменования, чтобы упасть
}

// AnalyzeGoProject reports the nil-able fields that are read but never written.
func (r *NeverAssignedFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("never assigned field: nil Go project context")
	}

	var declared []nilableField
	read := make(map[token.Pos]bool)
	dereferenced := make(map[token.Pos]bool)
	written := make(map[token.Pos]bool)

	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("never assigned field: package has no typed syntax")
		}
		info := pkg.Package.TypesInfo

		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			declared = append(declared, collectNilableFields(fileCtx, info)...)
		}
		for _, file := range pkg.Package.Syntax {
			collectFieldAccess(file, info, read, dereferenced, written)
		}
	}

	// Test files are outside the typed load; a test assigning the field
	// (fixture wiring) means it is not "never assigned".
	mentions := newTestMentions(ctx.Files)

	var violations []*core.Violation
	for _, field := range declared {
		if written[field.pos] {
			continue
		}
		if field.pointer && !dereferenced[field.pos] {
			continue // nil-checked optional, not a crash
		}
		if !read[field.pos] {
			continue
		}
		if mentions.mentioned(field.fileCtx, field.fieldName) {
			continue
		}
		if field.fileCtx.IsSuppressed(field.line, r.Name()) {
			continue
		}
		violations = append(violations, r.report(field))
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *NeverAssignedFieldRule) report(field nilableField) *core.Violation {
	v := r.CreateViolation(field.fileCtx.RelPath, field.line,
		fmt.Sprintf("Field %s.%s is read but never assigned — it is nil on every instance, so the first read panics",
			field.typeName, field.fieldName))
	v.WithCode(strings.TrimSpace(field.fileCtx.GetLine(field.line)))
	v.WithSuggestion(fmt.Sprintf("Assign %s in the constructor, or delete the field and the code that reads it",
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

		for _, field := range structType.Fields.List {
			// Тегированные поля заполняет рефлексия (json.Unmarshal, sql.Scan, yaml):
			// явного присваивания там нет по построению.
			if field.Tag != nil || len(field.Names) == 0 || !isNilableType(info.TypeOf(field.Type)) {
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
					pos:       obj.Pos(),
					fileCtx:   fileCtx,
					line:      fileCtx.LineFor(name),
					typeName:  spec.Name.Name,
					fieldName: name.Name,
					pointer:   isPointerType(info.TypeOf(field.Type)),
				})
			}
		}
		return true
	})

	return fields
}

// isNilableType reports whether the zero value of the type is nil, i.e. whether
// a missing assignment turns the first read into a panic rather than into a
// merely wrong value.
func isNilableType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch t.Underlying().(type) {
	case *types.Interface, *types.Pointer, *types.Map, *types.Slice, *types.Chan, *types.Signature:
		return true
	}
	return false
}

// isPointerType reports whether the field is a pointer, whose nil value only
// crashes where it is dereferenced.
func isPointerType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := t.Underlying().(*types.Pointer)
	return ok
}

// collectFieldAccess records, by declaration position, which fields the packages
// read, which they dereference, and which they write. Positions rather than
// *types.Var: a field of an instantiated generic type is a different object than
// its declaration.
func collectFieldAccess(file *ast.File, info *types.Info, read, dereferenced, written map[token.Pos]bool) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					if pos, ok := fieldPos(info, sel); ok {
						written[pos] = true
					}
				}
			}
		case *ast.UnaryExpr:
			// &s.field hands the address out: assume the callee writes through it.
			if node.Op == token.AND {
				if sel, ok := node.X.(*ast.SelectorExpr); ok {
					if pos, ok := fieldPos(info, sel); ok {
						written[pos] = true
					}
				}
			}
		case *ast.StarExpr:
			// *p.field — явное разыменование
			if sel, ok := node.X.(*ast.SelectorExpr); ok {
				if pos, ok := fieldPos(info, sel); ok {
					dereferenced[pos] = true
				}
			}
		case *ast.CompositeLit:
			markLiteralWrites(node, info, written)
		case *ast.SelectorExpr:
			if pos, ok := fieldPos(info, node); ok {
				read[pos] = true
			}
			// p.field.X / p.field.Method() — обращение сквозь поле разыменовывает его
			if inner, ok := node.X.(*ast.SelectorExpr); ok {
				if pos, ok := fieldPos(info, inner); ok {
					dereferenced[pos] = true
				}
			}
		}
		return true
	})
}

// markLiteralWrites records the fields a composite literal fills. A literal
// without keys is positional and fills every field, so nothing in that struct
// can be reported from it.
func markLiteralWrites(lit *ast.CompositeLit, info *types.Info, written map[token.Pos]bool) {
	structType, ok := structUnder(info.TypeOf(lit))
	if !ok {
		return
	}

	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			// Positional literal: every field of the struct is written here.
			for i := 0; i < structType.NumFields(); i++ {
				written[structType.Field(i).Pos()] = true
			}
			return
		}
		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if v, ok := info.Uses[ident].(*types.Var); ok && v.IsField() {
			written[v.Pos()] = true
		}
	}
}

// structUnder returns the struct behind a (possibly pointer or named) type.
func structUnder(t types.Type) (*types.Struct, bool) {
	if t == nil {
		return nil, false
	}
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}

// fieldPos returns the declaration position of the field a selector refers to.
func fieldPos(info *types.Info, sel *ast.SelectorExpr) (token.Pos, bool) {
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return token.NoPos, false
	}
	v, ok := selection.Obj().(*types.Var)
	if !ok {
		return token.NoPos, false
	}
	return v.Pos(), true
}
