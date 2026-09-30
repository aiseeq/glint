package deadcode

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// constructorFields maps a struct type to the fields its constructors give a
// value — keyed in a literal of the type, or assigned through a selector, in a
// function that returns the type or a pointer to it — to the fields its own
// methods go through (h.errorHandler.Handle(), *h.cfg, h.hook()), and to the
// fields a method compares with nil: those are optional.
type constructorFields struct {
	set      map[*types.Named]map[*types.Var]bool
	used     map[*types.Named]map[*types.Var]bool
	optional map[*types.Named]map[*types.Var]bool
}

// collectConstructorFields reads every type-checked file of the project.
func collectConstructorFields(ctx *core.GoProjectContext) constructorFields {
	fields := constructorFields{
		set:      make(map[*types.Named]map[*types.Var]bool),
		used:     make(map[*types.Named]map[*types.Var]bool),
		optional: make(map[*types.Named]map[*types.Var]bool),
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				fields.collectMethodUses(fn, info)
				results := resultTypes(fn, info)
				if len(results) == 0 {
					continue
				}
				assigned := assignedFields(fn.Body, info)
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					lit, ok := n.(*ast.CompositeLit)
					if !ok {
						return true
					}
					named := literalNamed(lit, info)
					if named == nil || !results[named] {
						return true
					}
					set := fields.set[named]
					if set == nil {
						set = make(map[*types.Var]bool)
						fields.set[named] = set
					}
					for field := range literalFields(lit, info) {
						set[field] = true
					}
					for field := range assigned {
						if structHasField(named, field) {
							set[field] = true
						}
					}
					return true
				})
			}
		}
	}
	return fields
}

// collectMethodUses records the fields of the receiver a method goes through
// — selecting from or calling a method of the field, dereferencing it, calling
// it — and the fields it compares with nil.
func (c constructorFields) collectMethodUses(fn *ast.FuncDecl, info *types.Info) {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return
	}
	recv := info.Defs[fn.Recv.List[0].Names[0]]
	if recv == nil {
		return
	}
	named := structNamed(recv.Type())
	if named == nil {
		return
	}
	mark := func(into map[*types.Named]map[*types.Var]bool, expr ast.Expr) {
		sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
		if !ok {
			return
		}
		base, ok := ast.Unparen(sel.X).(*ast.Ident)
		if !ok || info.Uses[base] != recv {
			return
		}
		selection, ok := info.Selections[sel]
		if !ok || selection.Kind() != types.FieldVal {
			return
		}
		field, ok := selection.Obj().(*types.Var)
		if !ok {
			return
		}
		if into[named] == nil {
			into[named] = make(map[*types.Var]bool)
		}
		into[named][field.Origin()] = true
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			mark(c.used, node.X)
		case *ast.StarExpr:
			mark(c.used, node.X)
		case *ast.CallExpr:
			mark(c.used, node.Fun)
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				if helpers.IsNilValue(node.Y, info) {
					mark(c.optional, node.X)
				}
				if helpers.IsNilValue(node.X, info) {
					mark(c.optional, node.Y)
				}
			}
		}
		return true
	})
}

// bypassingLiterals reports the literals of a file that build a type outside
// its constructors and leave nil a dependency the constructors fill and the
// type's own methods go through.
func (r *NeverAssignedFieldRule) bypassingLiterals(fileCtx *core.FileContext, info *types.Info,
	ctors constructorFields) []*core.Violation {
	var violations []*core.Violation
	for _, decl := range fileCtx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		results := resultTypes(fn, info)
		assigned := assignedFields(fn.Body, info)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			named := literalNamed(lit, info)
			if named == nil || results[named] || len(ctors.set[named]) == 0 {
				return true
			}
			set := literalFields(lit, info)
			if set == nil {
				return true // positional: every field is given
			}
			var missing []string
			for field := range ctors.set[named] {
				if set[field] || assigned[field] || !ctors.used[named][field] || ctors.optional[named][field] {
					continue
				}
				// A nil map reads as empty; only a store into it panics.
				if use, nilable := nilUseOf(field.Type()); nilable && use != nilUseStore {
					missing = append(missing, field.Name())
				}
			}
			if len(missing) == 0 {
				return true
			}
			slices.Sort(missing)
			line := fileCtx.LineFor(lit)
			v := r.CreateViolation(fileCtx.RelPath, line,
				fmt.Sprintf("Literal of %s leaves %s nil — its constructor fills them and its methods use them, so the first use panics",
					named.Obj().Name(), strings.Join(missing, ", ")))
			v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
			v.WithSuggestion("Build the value with its constructor, or fill every dependency the constructor fills")
			v.WithContext("pattern", "literal_bypasses_constructor")
			v.WithContext("field", named.Obj().Name()+"."+strings.Join(missing, ","))
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

// resultTypes returns the named struct types a function returns, by value or
// by pointer.
func resultTypes(fn *ast.FuncDecl, info *types.Info) map[*types.Named]bool {
	if fn.Type.Results == nil {
		return nil
	}
	results := make(map[*types.Named]bool)
	for _, field := range fn.Type.Results.List {
		if named := structNamed(info.TypeOf(field.Type)); named != nil {
			results[named] = true
		}
	}
	return results
}

// literalNamed returns the named struct type a composite literal builds.
func literalNamed(lit *ast.CompositeLit, info *types.Info) *types.Named {
	return structNamed(info.TypeOf(lit))
}

// structNamed returns the named struct type behind t or behind a pointer t.
func structNamed(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return nil
	}
	return named.Origin()
}

// literalFields returns the fields a keyed literal gives a value other than
// nil, or nil for a positional literal, which gives every field.
func literalFields(lit *ast.CompositeLit, info *types.Info) map[*types.Var]bool {
	set := make(map[*types.Var]bool)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil
		}
		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if field, ok := info.Uses[ident].(*types.Var); ok && field.IsField() && !helpers.IsNilValue(kv.Value, info) {
			set[field.Origin()] = true
		}
	}
	return set
}

// assignedFields returns the fields a body gives a value through a selector:
// base.errorHandler = handler.
func assignedFields(body *ast.BlockStmt, info *types.Info) map[*types.Var]bool {
	assigned := make(map[*types.Var]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if len(assign.Lhs) == len(assign.Rhs) && helpers.IsNilValue(assign.Rhs[i], info) {
				continue
			}
			if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
				if field, ok := selection.Obj().(*types.Var); ok {
					assigned[field.Origin()] = true
				}
			}
		}
		return true
	})
	return assigned
}

// structHasField reports a field declared directly in the named struct.
func structHasField(named *types.Named, field *types.Var) bool {
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := range st.NumFields() {
		if st.Field(i).Origin() == field {
			return true
		}
	}
	return false
}
