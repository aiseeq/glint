package patterns

import (
	"go/ast"
	"go/types"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// sqlInsertStart is how an INSERT statement begins.
var sqlInsertStart = regexp.MustCompile(`(?i)^\s*insert\s+into\s`)

// minBoundFields is how many fields of one model an INSERT must bind by hand
// to count as the model's write: a statement binding two values is a side
// table, not the model.
const minBoundFields = 8

// unpersistedModelFields reports the hand-mapped writes of a model (an INSERT
// binding tx.ID, tx.Amount, ... one by one) that leave out fields the rest of
// the project sets, when the repository package never mentions them at all -
// neither in a write nor in a read. A model without db tags gives the tagged
// check nothing to compare; the field is set by a handler, saved without it,
// and the next load hands back the zero value.
func (r *SQLModelFieldSkippedRule) unpersistedModelFields(ctx *core.GoProjectContext) []*core.Violation {
	assigned := make(map[*types.Var]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file == nil || file.GoAST == nil || file.IsTestFile() {
				continue
			}
			collectAssignedFields(file.GoAST, info, assigned)
		}
	}
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		violations = append(violations, r.packageUnpersisted(pkg, assigned)...)
	}
	return violations
}

// collectAssignedFields records the struct fields a file sets: x.F = v and
// T{F: v}.
func collectAssignedFields(file *ast.File, info *types.Info, assigned map[*types.Var]bool) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if field := selectedField(lhs, info); field != nil {
					assigned[field] = true
				}
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok {
				if field, ok := info.Uses[key].(*types.Var); ok && field.IsField() {
					assigned[field] = true
				}
			}
		}
		return true
	})
}

// selectedField returns the field a selector expression selects, nil for
// anything else.
func selectedField(expr ast.Expr, info *types.Info) *types.Var {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return nil
	}
	field, _ := selection.Obj().(*types.Var)
	return field
}

// modelWrite is an INSERT call binding fields of one model by hand.
type modelWrite struct {
	file  *core.FileContext
	call  *ast.CallExpr
	model *types.Named
}

// packageUnpersisted checks the hand-mapped model writes of one package.
func (r *SQLModelFieldSkippedRule) packageUnpersisted(pkg *core.GoPackageContext, assigned map[*types.Var]bool) []*core.Violation {
	info := pkg.Package.TypesInfo
	mentioned := make(map[*types.Var]bool)
	var writes []modelWrite
	for _, file := range pkg.Files {
		if file == nil || file.GoAST == nil || file.IsTestFile() {
			continue
		}
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if field := selectedField(sel, info); field != nil {
					mentioned[field] = true
				}
			}
			return true
		})
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			queries := namedStrings(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if model := insertModel(call, queries, info); model != nil {
					writes = append(writes, modelWrite{file: file, call: call, model: model})
				}
				return true
			})
		}
	}
	var violations []*core.Violation
	for _, write := range writes {
		st, ok := write.model.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		var lost []string
		for i := range st.NumFields() {
			field := st.Field(i)
			if field.Embedded() || !field.Exported() || !assigned[field] || mentioned[field] || !scalarField(field.Type()) {
				continue
			}
			// A db tag is the tagged check's: db:"-" says the field is not
			// kept, a column tag is read by name without a selector.
			if _, tagged := reflect.StructTag(st.Tag(i)).Lookup("db"); tagged {
				continue
			}
			lost = append(lost, field.Name())
		}
		if len(lost) == 0 {
			continue
		}
		sort.Strings(lost)
		line := write.file.LineFor(write.call)
		if write.file.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(write.file.RelPath, line,
			"The INSERT binds the fields of "+write.model.Obj().Name()+" by hand but leaves out "+strings.Join(lost, ", ")+", which the code sets and this repository never stores or reads back — the next load returns them empty")
		v.WithCode(strings.TrimSpace(write.file.GetLine(line)))
		v.WithSuggestion("Add the columns (a migration), bind the fields in the INSERT and scan them back, or stop setting fields that are not kept")
		v.WithContext("pattern", "model_field_never_persisted")
		violations = append(violations, v)
	}
	return violations
}

// insertModel returns the model whose fields an INSERT call binds one by one
// (at least minBoundFields of them, directly or through a one-argument
// conversion), nil for any other call.
func insertModel(call *ast.CallExpr, queries map[string]ast.Expr, info *types.Info) *types.Named {
	for i, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && queries[ident.Name] != nil {
			arg = queries[ident.Name]
		}
		if !isStringOrConcat(arg) {
			continue
		}
		literals := sqlTexts(arg, sqlInsertStart.MatchString)
		if len(literals) != 1 {
			continue
		}
		counts := make(map[*types.Named]int)
		for _, bound := range call.Args[i+1:] {
			sel, ok := copiedField(bound, info)
			if !ok {
				continue
			}
			if named := namedStructOf(info.TypeOf(sel.X)); named != nil {
				counts[named]++
			}
		}
		// One statement writes one model: the type most of its arguments
		// come from, at least minBoundFields of them.
		var model *types.Named
		for named, count := range counts {
			if count >= minBoundFields && (model == nil || count > counts[model] || count == counts[model] && named.String() < model.String()) {
				model = named
			}
		}
		return model
	}
	return nil
}

// namedStructOf returns the named struct type of a value, through a pointer.
func namedStructOf(t types.Type) *types.Named {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil
	}
	if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
		return nil
	}
	return named
}

// scalarField reports a field type a column holds: a basic type, a time or a
// decimal value, or a pointer to one. A slice, a map or a nested struct is a
// relation the model carries, not a column.
func scalarField(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if _, basic := t.Underlying().(*types.Basic); basic {
		return true
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && (named.Obj().Name() == "Time" || named.Obj().Name() == "Decimal" || named.Obj().Name() == "UUID")
}
