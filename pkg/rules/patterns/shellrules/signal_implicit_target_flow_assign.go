package shellrules

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// propagate carries the value through assignments, range clauses and struct
// literals of the scope until nothing new is tracked.
func (s *rangeScope) propagate() {
	for range rangeFixpointLimit {
		version, generation := s.version, s.a.generation
		ast.Inspect(s.body, s.propagateNode)
		if s.version == version && s.a.generation == generation {
			return
		}
	}
	s.escapes = true
}

func (s *rangeScope) propagateNode(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.AssignStmt:
		s.assign(n.Lhs, n.Rhs, n.Tok)
	case *ast.ValueSpec:
		lhs := make([]ast.Expr, len(n.Names))
		for i, name := range n.Names {
			lhs[i] = name
		}
		s.assign(lhs, n.Values, token.DEFINE)
	case *ast.RangeStmt:
		c := s.class(n.X)
		if c == rangeNone {
			return true
		}
		s.markUses(n.X, s.propagated)
		if n.Key != nil && c == rangeWhole {
			s.assignTo(n.Key, rangeWhole)
		}
		if n.Value != nil {
			s.assignTo(n.Value, c)
		}
	case *ast.CompositeLit:
		s.registerFields(n)
	}
	return true
}

func (s *rangeScope) assign(lhs, rhs []ast.Expr, tok token.Token) {
	if len(lhs) == len(rhs) {
		for i := range lhs {
			c := s.class(rhs[i])
			if c == rangeNone {
				continue
			}
			if tok != token.ASSIGN && tok != token.DEFINE {
				c = rangeWhole
			}
			s.markUses(rhs[i], s.propagated)
			s.assignTo(lhs[i], c)
		}
		return
	}
	c := rangeNone
	for _, value := range rhs {
		c = max(c, s.class(value))
	}
	if c == rangeNone {
		return
	}
	for _, value := range rhs {
		s.markUses(value, s.propagated)
	}
	for _, target := range lhs {
		s.assignTo(target, rangeWhole)
	}
}

// assignTo stores a value of class c in lhs. A store the analysis cannot
// keep within the code it follows (a package-level variable, memory behind
// an unknown pointer, a map or slice element) makes the scope escape.
func (s *rangeScope) assignTo(lhs ast.Expr, c rangeClass) {
	switch target := ast.Unparen(lhs).(type) {
	case *ast.Ident:
		if target.Name == "_" {
			return
		}
		obj := s.info.ObjectOf(target)
		if obj == nil {
			s.escapes = true
			return
		}
		s.propagated[target] = true
		if !s.ownsName(obj) {
			s.escapes = true
			return
		}
		s.setClass(obj, c)
	case *ast.SelectorExpr:
		selection := s.info.Selections[target]
		if selection == nil || selection.Kind() != types.FieldVal {
			s.escapes = true
			return
		}
		s.registerSelection(selection, c)
		s.writeInto(target.X, selection.Indirect())
	default:
		s.escapes = true
	}
}

// ownsName reports a variable whose value stays in the code under analysis:
// a local of the body, a parameter or a named result of a reached function.
func (s *rangeScope) ownsName(obj types.Object) bool {
	if _, ok := s.params[obj]; ok {
		return true
	}
	return s.results[obj] || s.declaredInBody(obj)
}

func (s *rangeScope) declaredInBody(obj types.Object) bool {
	if obj.Parent() != nil && obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
		return false
	}
	return obj.Pos().IsValid() && s.body.Pos() <= obj.Pos() && obj.Pos() < s.body.End()
}

// registerSelection marks the field a selection ends at, and every embedded
// field on its way, as holding the value.
func (s *rangeScope) registerSelection(selection *types.Selection, c rangeClass) {
	t := selection.Recv()
	index := selection.Index()
	for i, at := range index {
		st, ok := helpers.StructUnder(t)
		if !ok || at >= st.NumFields() {
			return
		}
		field := st.Field(at)
		if i == len(index)-1 {
			s.a.setField(field, c)
			return
		}
		s.a.setField(field, rangeHolder)
		t = field.Type()
	}
}

// writeInto checks where a field write through x lands: x's fields on the
// way hold the value, and the memory must be a local of the body or behind a
// parameter, which the caller then checks.
func (s *rangeScope) writeInto(x ast.Expr, indirect bool) {
	for {
		switch e := x.(type) {
		case *ast.ParenExpr:
			x = e.X
		case *ast.StarExpr:
			indirect, x = true, e.X
		case *ast.SelectorExpr:
			selection := s.info.Selections[e]
			if selection == nil || selection.Kind() != types.FieldVal {
				s.escapes = true
				return
			}
			s.registerSelection(selection, rangeHolder)
			indirect, x = indirect || selection.Indirect(), e.X
		case *ast.IndexExpr:
			if _, isArray := s.info.TypeOf(e.X).Underlying().(*types.Array); !isArray {
				indirect = true
			}
			x = e.X
		case *ast.Ident:
			s.propagated[e] = true
			s.storeAt(s.info.Uses[e], indirect, rangeHolder)
			return
		default:
			s.escapes = true
			return
		}
	}
}

// storeAt checks a write of class c into the memory obj names (indirect:
// the memory obj points to).
func (s *rangeScope) storeAt(obj types.Object, indirect bool, c rangeClass) {
	if obj == nil {
		s.escapes = true
		return
	}
	if index, ok := s.params[obj]; ok {
		if indirect {
			s.addWritten(index, c)
		}
		return
	}
	if !s.declaredInBody(obj) && !(s.results[obj] && !indirect) {
		s.escapes = true
		return
	}
	if indirect && !s.freshPointer(obj) {
		s.escapes = true
	}
}

// freshPointer reports a local every assignment of which allocates: &T{},
// new(T), make(...) or a literal. Memory behind it is reached only through it.
func (s *rangeScope) freshPointer(obj types.Object) bool {
	fresh := true
	check := func(lhs, rhs []ast.Expr) {
		for i, target := range lhs {
			id, ok := ast.Unparen(target).(*ast.Ident)
			if !ok || s.info.ObjectOf(id) != obj {
				continue
			}
			if len(lhs) != len(rhs) || !s.allocates(rhs[i]) {
				fresh = false
			}
		}
	}
	ast.Inspect(s.body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			check(n.Lhs, n.Rhs)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, len(n.Names))
			for i, name := range n.Names {
				lhs[i] = name
			}
			if len(n.Values) > 0 {
				check(lhs, n.Values)
			}
		case *ast.RangeStmt:
			for _, target := range []ast.Expr{n.Key, n.Value} {
				if id, ok := target.(*ast.Ident); ok && s.info.ObjectOf(id) == obj {
					fresh = false
				}
			}
		case *ast.UnaryExpr:
			// &p lets a callee replace the pointer.
			if id, ok := ast.Unparen(n.X).(*ast.Ident); ok && n.Op == token.AND && s.info.Uses[id] == obj {
				fresh = false
			}
		}
		return fresh
	})
	return fresh
}

func (s *rangeScope) allocates(e ast.Expr) bool {
	switch e := ast.Unparen(e).(type) {
	case *ast.CompositeLit:
		return true
	case *ast.UnaryExpr:
		_, literal := ast.Unparen(e.X).(*ast.CompositeLit)
		return e.Op == token.AND && literal
	case *ast.CallExpr:
		id, ok := ast.Unparen(e.Fun).(*ast.Ident)
		if !ok {
			return false
		}
		builtin, ok := s.info.Uses[id].(*types.Builtin)
		return ok && (builtin.Name() == "new" || builtin.Name() == "make")
	}
	return false
}

// registerFields marks the fields a struct literal fills with the value.
func (s *rangeScope) registerFields(lit *ast.CompositeLit) {
	st, ok := helpers.StructUnder(s.info.TypeOf(lit))
	if !ok {
		return
	}
	for i, element := range lit.Elts {
		value := element
		var field *types.Var
		if kv, ok := element.(*ast.KeyValueExpr); ok {
			value = kv.Value
			if id, ok := kv.Key.(*ast.Ident); ok {
				field, _ = s.info.Uses[id].(*types.Var)
			}
		} else if i < st.NumFields() {
			field = st.Field(i)
		}
		c := s.class(value)
		if c == rangeNone {
			continue
		}
		if field == nil {
			s.escapes = true
			continue
		}
		s.a.setField(field, c)
	}
}

// writeThrough records that a call stored a value of class c in the memory
// e points to: a pointer, a slice, or a value passed by address (addressed).
func (s *rangeScope) writeThrough(e ast.Expr, c rangeClass, addressed bool) {
	e = ast.Unparen(e)
	if unary, ok := e.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		e, addressed = ast.Unparen(unary.X), true
	}
	if slice, ok := e.(*ast.SliceExpr); ok {
		e = ast.Unparen(slice.X)
	}
	if addressed {
		if c == rangeWhole {
			s.assignTo(e, rangeWhole)
			return
		}
		s.writeInto(e, false)
		return
	}
	switch target := e.(type) {
	case *ast.Ident:
		obj := s.info.Uses[target]
		s.propagated[target] = true
		s.storeAt(obj, true, c)
		if obj != nil && c == rangeWhole && s.ownsName(obj) {
			s.setClass(obj, rangeWhole)
		}
	case *ast.SelectorExpr:
		// The pointer is a field: the field now leads to the value.
		s.assignTo(target, c)
	default:
		s.escapes = true
	}
}
