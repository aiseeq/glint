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

// declaredField is an unexported field of an analyzed struct type.
type declaredField struct {
	obj       *types.Var
	owner     *types.Struct
	named     *types.Named
	fileCtx   *core.FileContext
	line      int
	typeName  string
	fieldName string
	setting   bool
}

// AnalyzeGoProject reports the unexported fields no compiled file reads.
func (r *UnusedFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused field: nil Go project context")
	}

	var declared []declaredField
	// Ключ — позиция объявления поля, а не *types.Var: у generic-типа обращение внутри
	// метода даёт поле инстанцированной структуры (другой *types.Var), и сравнение по
	// указателю теряло все чтения generic-полей.
	read := make(map[token.Pos]bool)
	written := make(map[token.Pos]bool)
	compared := make(map[*types.Struct]bool)
	// An encoder reads every exported field on the program's behalf, so a
	// setting of a type that is marshalled is not dead.
	decoded := make(map[*types.Named]bool)
	encoded := make(map[*types.Named]bool)

	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("unused field: package has no typed syntax")
		}
		info := pkg.Package.TypesInfo

		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			declared = append(declared, collectCheckedFields(fileCtx, info)...)
		}
		for _, file := range pkg.Package.Syntax {
			collectFieldReads(file, info, read, written)
			collectComparedStructs(file, info, compared)
			collectSerializedTypes(file, info, decoded, encoded)
		}
	}

	// Test files are outside the typed load; a field read only by its
	// white-box test must still count as read.
	mentions := newTestMentions(ctx.Files)

	var violations []*core.Violation
	for _, field := range declared {
		if read[field.obj.Pos()] || compared[field.owner] {
			continue
		}
		if field.setting && field.named != nil && encoded[field.named] {
			continue
		}
		if mentions.mentioned(field.fileCtx, field.fieldName) {
			continue
		}
		violations = append(violations, r.report(field, written[field.obj.Pos()]))
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
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
		owner, ok := declaredStructType(spec, info)
		if !ok {
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
					owner:     owner,
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

// collectComparedStructs records the structs whose value is used as a whole:
// as a map key, or in an equality test. The runtime then reads every field to
// hash or compare it, so no field of such a struct is dead.
func collectComparedStructs(file *ast.File, info *types.Info, compared map[*types.Struct]bool) {
	markStruct := func(t types.Type) {
		if t == nil {
			return
		}
		if structType, ok := t.Underlying().(*types.Struct); ok {
			compared[structType] = true
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if binary, ok := n.(*ast.BinaryExpr); ok && (binary.Op == token.EQL || binary.Op == token.NEQ) {
			markStruct(info.TypeOf(binary.X))
			markStruct(info.TypeOf(binary.Y))
		}
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		if mapType, ok := underlyingMap(info.TypeOf(expr)); ok {
			markStruct(mapType.Key())
		}
		return true
	})
}

// underlyingMap returns the map behind a type, seeing through pointers.
func underlyingMap(t types.Type) (*types.Map, bool) {
	if t == nil {
		return nil, false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	mapType, ok := t.Underlying().(*types.Map)
	return mapType, ok
}

// collectFieldReads separates the mentions that consume a field's value from the
// ones that only set it.
func collectFieldReads(file *ast.File, info *types.Info, read, written map[token.Pos]bool) {
	writeOnly := writtenSelectors(file)

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			selection, ok := info.Selections[node]
			if !ok || selection.Kind() != types.FieldVal {
				return true
			}
			field, ok := selection.Obj().(*types.Var)
			if !ok {
				return true
			}
			if writeOnly[node] {
				written[field.Pos()] = true
				return true
			}
			read[field.Pos()] = true
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
					written[field.Pos()] = true
				}
			}
		}
		return true
	})
}

// writtenSelectors returns the selectors a statement updates: plain assignments
// and the counter forms (x.n++, x.n += 1). Updating a counter keeps it current
// but consumes nothing — a counter nobody ever looks at is exactly the case this
// rule is about. A read on the right-hand side is a separate selector node and
// still counts as a read.
func writtenSelectors(file *ast.File) map[*ast.SelectorExpr]bool {
	targets := make(map[*ast.SelectorExpr]bool)

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					targets[sel] = true
				}
			}
		case *ast.IncDecStmt:
			if sel, ok := node.X.(*ast.SelectorExpr); ok {
				targets[sel] = true
			}
		}
		return true
	})

	return targets
}
