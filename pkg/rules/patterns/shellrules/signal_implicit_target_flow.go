package shellrules

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// The range analysis follows a []string table value through the code it
// reaches: assignments, struct fields, calls of functions whose syntax is
// loaded. A table string is data only when every use is proven not to reach a
// shell; a use it cannot follow makes the result unknown.

// rangeClass is how an expression carries the range value.
type rangeClass uint8

const (
	rangeNone rangeClass = iota
	// rangeHolder is a struct, or a pointer, slice or map of structs, some of
	// whose fields hold the value: only reading such a field gives it.
	rangeHolder
	// rangeWhole is the value itself or anything computed from it.
	rangeWhole
)

const (
	rangeDepthLimit    = 8
	rangeFixpointLimit = 32
)

// rangeFieldKey names a struct field across the typings of one package: a test
// package is typed again over the same syntax, so the position is shared.
type rangeFieldKey struct {
	pkg, name string
	pos       token.Pos
}

func rangeFieldOf(v *types.Var) rangeFieldKey {
	key := rangeFieldKey{name: v.Name(), pos: v.Pos()}
	if v.Pkg() != nil {
		key.pkg = v.Pkg().Path()
	}
	return key
}

// rangeAnalysis is the state one table shares across the functions it
// reaches. Fields are tracked by type, not by instance: once a field of T
// holds the value, every T is a holder, so a write through one alias is seen
// through all of them.
type rangeAnalysis struct {
	fset       *token.FileSet
	fields     map[rangeFieldKey]rangeClass
	generation int
	cache      map[rangeCallKey]rangeCallResult
	impls      map[*types.Func][]*types.Func
	// summaries are the stores through parameters of a function entered
	// with given classes, kept across runs so that they only grow.
	summaries map[rangeSummaryKey]map[int]rangeClass
	// linked are the packages of the binary the table runs in: the root's
	// package and its imports. Only their types can implement an interface
	// there.
	linked map[string]bool
	// inert caches rangeReadInert by package directory.
	inert map[string]bool
}

type rangeSummaryKey struct {
	fn      *types.Func
	classes string
}

// rangeCallKey names the analysis of a function entered with given classes.
// Only a result the depth limit did not cut is kept: it holds at any depth.
type rangeCallKey struct {
	fn         *types.Func
	classes    string
	generation int
}

type rangeCallResult struct {
	flow rangeFlowResult
	// written maps a parameter (-1 the receiver) to what the callee stored in
	// the memory it points to: holder for a field, whole for the content.
	written map[int]rangeClass
}

func analyzeRangeObject(body ast.Node, object types.Object, info *types.Info, pkg *signalPackage, fset *token.FileSet) rangeFlowResult {
	a := &rangeAnalysis{
		fset: fset, fields: make(map[rangeFieldKey]rangeClass), impls: make(map[*types.Func][]*types.Func),
		summaries: make(map[rangeSummaryKey]map[int]rangeClass),
		linked:    rangeLinkedPackages(rangeRootPackage(info, pkg)),
		inert:     make(map[string]bool),
	}
	a.cache = make(map[rangeCallKey]rangeCallResult)
	for range rangeFixpointLimit {
		generation, exact := a.generation, len(a.cache)
		root := a.newScope(body, info, pkg, 0, nil)
		root.objects[object] = rangeWhole
		flow := root.run()
		// A field found to hold the value late changes what earlier code
		// read: run again until the fields settle. A function cut off by
		// the depth limit on one path may have been analyzed in full on a
		// shorter one since: run again while that adds results.
		settled := a.generation == generation && (!flow.limited || len(a.cache) == exact)
		if flow.executes || settled {
			return flow
		}
	}
	return rangeFlowResult{unknown: true}
}

func (a *rangeAnalysis) setField(v *types.Var, class rangeClass) {
	key := rangeFieldOf(v)
	if class > a.fields[key] {
		a.fields[key] = class
		a.generation++
	}
}

func (a *rangeAnalysis) fieldClass(v *types.Var) rangeClass {
	return a.fields[rangeFieldOf(v)]
}

// typeCarries reports a type whose values may hold the range value in a
// field: a struct with such a field, or a pointer, slice, array, map or
// channel of one.
func (a *rangeAnalysis) typeCarries(t types.Type, seen map[*types.Named]bool) bool {
	if len(a.fields) == 0 || t == nil {
		return false
	}
	switch u := types.Unalias(t).(type) {
	case *types.Pointer:
		return a.typeCarries(u.Elem(), seen)
	case *types.Slice:
		return a.typeCarries(u.Elem(), seen)
	case *types.Array:
		return a.typeCarries(u.Elem(), seen)
	case *types.Chan:
		return a.typeCarries(u.Elem(), seen)
	case *types.Map:
		return a.typeCarries(u.Key(), seen) || a.typeCarries(u.Elem(), seen)
	case *types.Named:
		if seen[u] {
			return false
		}
		if seen == nil {
			seen = make(map[*types.Named]bool)
		}
		seen[u] = true
		return a.typeCarries(u.Underlying(), seen)
	case *types.Struct:
		for field := range u.Fields() {
			if a.fields[rangeFieldOf(field)] != rangeNone {
				return true
			}
		}
	}
	return false
}

// rangeScope is one function body under analysis: the root holding the range
// statement or a function a call reached.
type rangeScope struct {
	a      *rangeAnalysis
	info   *types.Info
	pkg    *signalPackage
	body   ast.Node
	callee bool
	depth  int
	// stack holds the functions being analyzed; a recursive call within
	// them with no more than the classes they were entered with is covered.
	stack   map[*types.Func]*rangeScope
	entered string
	objects map[types.Object]rangeClass
	params  map[types.Object]int
	results map[types.Object]bool
	version int

	escapes    bool
	written    map[int]rangeClass
	flow       rangeFlowResult
	handled    map[*ast.Ident]bool
	propagated map[*ast.Ident]bool
	parents    map[ast.Node]ast.Node
}

func (a *rangeAnalysis) newScope(body ast.Node, info *types.Info, pkg *signalPackage, depth int, stack map[*types.Func]*rangeScope) *rangeScope {
	return &rangeScope{
		a: a, info: info, pkg: pkg, body: body, depth: depth, stack: stack,
		objects: make(map[types.Object]rangeClass),
		params:  make(map[types.Object]int),
		results: make(map[types.Object]bool),
		written: make(map[int]rangeClass),
	}
}

// addWritten records a store through a parameter. It only grows, and a
// recursive call reads it as the function's summary, so growth is a change
// every scope sees.
func (s *rangeScope) addWritten(index int, c rangeClass) {
	if c > s.written[index] {
		s.written[index] = c
		s.a.generation++
	}
}

func (s *rangeScope) run() rangeFlowResult {
	if s.depth >= rangeDepthLimit {
		return rangeFlowResult{unknown: true, limited: true}
	}
	s.parents = rangeParents(s.body)
	for range rangeFixpointLimit {
		version, generation := s.version, s.a.generation
		s.escapes = false
		s.propagated = make(map[*ast.Ident]bool)
		s.propagate()
		s.analyzeCalls()
		if s.version == version && s.a.generation == generation {
			s.markUnknown()
			s.flow.unknown = s.flow.unknown || s.escapes
			return s.flow
		}
	}
	return rangeFlowResult{unknown: true}
}

func rangeParents(body ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

func (s *rangeScope) setClass(obj types.Object, class rangeClass) {
	if class > s.objects[obj] {
		s.objects[obj] = class
		s.version++
	}
}

// class is how e carries the range value: by what it is computed from, and at
// least as a holder when its type has a field that holds the value.
func (s *rangeScope) class(e ast.Expr) rangeClass {
	if e == nil {
		return rangeNone
	}
	if tv, ok := s.info.Types[e]; ok && !tv.IsValue() {
		return rangeNone
	}
	c := s.derivedClass(e)
	if c == rangeWhole || rangeFreshLiteral(e) {
		// A literal is new memory: it holds only what its elements put in.
		return c
	}
	if s.a.typeCarries(s.valueType(e), nil) {
		return rangeHolder
	}
	return c
}

func rangeFreshLiteral(e ast.Expr) bool {
	if unary, ok := e.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		e = ast.Unparen(unary.X)
	}
	_, ok := e.(*ast.CompositeLit)
	return ok
}

func (s *rangeScope) valueType(e ast.Expr) types.Type {
	if id, ok := e.(*ast.Ident); ok {
		if v, ok := s.info.Uses[id].(*types.Var); ok {
			return v.Type()
		}
		return nil
	}
	return s.info.TypeOf(e)
}

func (s *rangeScope) derivedClass(e ast.Expr) rangeClass {
	switch e := e.(type) {
	case *ast.Ident:
		if v, ok := s.info.Uses[e].(*types.Var); ok {
			return s.objects[v]
		}
		return rangeNone
	case *ast.BasicLit, *ast.FuncLit:
		// A closure's body belongs to the scope and is analyzed in place.
		return rangeNone
	case *ast.ParenExpr:
		return s.class(e.X)
	case *ast.StarExpr:
		return s.class(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return s.class(e.X)
		}
	case *ast.SelectorExpr:
		return s.selectorClass(e)
	case *ast.IndexExpr:
		if x := s.class(e.X); x == rangeHolder && s.class(e.Index) == rangeNone {
			return x
		}
	case *ast.CompositeLit:
		return s.literalClass(e)
	case *ast.CallExpr:
		if tv, ok := s.info.Types[e.Fun]; ok && tv.IsType() && len(e.Args) == 1 {
			return s.class(e.Args[0])
		}
	}
	return s.childrenClass(e)
}

// childrenClass is whole when any direct operand carries the value.
func (s *rangeScope) childrenClass(e ast.Expr) rangeClass {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found || n == e {
			return !found
		}
		if child, ok := n.(ast.Expr); ok {
			if s.class(child) != rangeNone {
				found = true
			}
			return false
		}
		return true
	})
	if found {
		return rangeWhole
	}
	return rangeNone
}

func (s *rangeScope) selectorClass(e *ast.SelectorExpr) rangeClass {
	selection := s.info.Selections[e]
	if selection == nil {
		// A qualified identifier: a package-level variable is never tracked.
		return s.derivedClass(e.Sel)
	}
	x := s.class(e.X)
	switch selection.Kind() {
	case types.FieldVal:
		if x == rangeWhole {
			return rangeWhole
		}
		if x == rangeNone {
			return rangeNone
		}
		field, _ := selection.Obj().(*types.Var)
		if field == nil {
			return rangeWhole
		}
		return s.a.fieldClass(field)
	case types.MethodVal:
		// A bound method carries its receiver.
		if x != rangeNone {
			return rangeWhole
		}
	}
	return rangeNone
}

func (s *rangeScope) literalClass(lit *ast.CompositeLit) rangeClass {
	c := rangeNone
	for _, element := range lit.Elts {
		if kv, ok := element.(*ast.KeyValueExpr); ok {
			if _, isStruct := helpers.StructUnder(s.info.TypeOf(lit)); !isStruct {
				c = max(c, s.class(kv.Key))
			}
			element = kv.Value
		}
		c = max(c, s.class(element))
	}
	if c == rangeNone {
		return c
	}
	if _, isStruct := helpers.StructUnder(s.info.TypeOf(lit)); isStruct {
		return rangeHolder
	}
	return rangeWhole
}

// markUses explains every use of a tracked name inside e: a call, an
// assignment or a return accounts for it.
func (s *rangeScope) markUses(e ast.Node, into map[*ast.Ident]bool) {
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && s.class(id) != rangeNone {
			into[id] = true
		}
		return true
	})
}
