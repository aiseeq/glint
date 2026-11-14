package shellrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// rangeCallSite is a call with how its receiver and arguments carry the value.
type rangeCallSite struct {
	call     *ast.CallExpr
	receiver ast.Expr
	// addressed: a pointer method called on an addressable value.
	addressed  bool
	methodExpr bool
	recvClass  rangeClass
	args       []rangeClass
}

func (s *rangeScope) callSite(call *ast.CallExpr) rangeCallSite {
	site := rangeCallSite{call: call, args: make([]rangeClass, len(call.Args))}
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if selection := s.info.Selections[selector]; selection != nil {
			switch selection.Kind() {
			case types.MethodVal:
				site.receiver, site.recvClass = selector.X, s.class(selector.X)
				site.addressed = rangePointerMethodOnValue(selection, s.info.TypeOf(selector.X))
			case types.MethodExpr:
				site.methodExpr = true
			}
		}
	}
	for i, arg := range call.Args {
		site.args[i] = s.class(arg)
	}
	return site
}

func rangePointerMethodOnValue(selection *types.Selection, x types.Type) bool {
	fn, ok := selection.Obj().(*types.Func)
	if !ok || x == nil {
		return false
	}
	recv := fn.Signature().Recv()
	if recv == nil {
		return false
	}
	_, pointerRecv := recv.Type().Underlying().(*types.Pointer)
	_, pointerX := x.Underlying().(*types.Pointer)
	return pointerRecv && !pointerX
}

func (site rangeCallSite) dependent() bool {
	if site.recvClass != rangeNone {
		return true
	}
	for _, c := range site.args {
		if c != rangeNone {
			return true
		}
	}
	return false
}

// key encodes the classes a callee is entered with.
func (site rangeCallSite) key() string {
	out := make([]byte, 0, len(site.args)+1)
	out = append(out, byte(site.recvClass))
	for _, c := range site.args {
		out = append(out, byte(c))
	}
	return string(out)
}

// argument is the expression a callee parameter (-1 the receiver) took.
func (site rangeCallSite) argument(index int) (ast.Expr, bool, bool) {
	if site.methodExpr {
		index++
	}
	if index == -1 {
		return site.receiver, site.addressed, site.receiver != nil
	}
	if index < 0 || index >= len(site.call.Args) {
		return nil, false, false
	}
	return site.call.Args[index], false, true
}

func (s *rangeScope) analyzeCalls() {
	s.flow, s.handled = rangeFlowResult{}, make(map[*ast.Ident]bool)
	ast.Inspect(s.body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			s.analyzeCall(call)
		}
		return true
	})
}

func (s *rangeScope) analyzeCall(call *ast.CallExpr) {
	site := s.callSite(call)
	if !site.dependent() {
		return
	}
	if site.recvClass != rangeNone {
		s.markUses(site.receiver, s.handled)
	}
	for i, arg := range call.Args {
		if site.args[i] != rangeNone {
			s.markUses(arg, s.handled)
		}
	}
	if tv, ok := s.info.Types[call.Fun]; ok && tv.IsType() {
		return
	}
	if s.builtinCall(site) {
		return
	}
	if _, ok := shellExecutionScript(call, s.info); ok {
		s.flow.executes = true
		return
	}
	if s.dataCall(site) || s.followCall(site) {
		return
	}
	s.flow.unknown = true
}

func (s *rangeScope) builtinCall(site rangeCallSite) bool {
	id, ok := ast.Unparen(site.call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	builtin, ok := s.info.Uses[id].(*types.Builtin)
	if !ok {
		return false
	}
	args := site.call.Args
	switch builtin.Name() {
	case "panic":
		// The value leaves with the panic to whoever recovers it.
		s.flow.unknown = true
	case "copy":
		if len(args) == 2 && site.args[1] != rangeNone {
			s.writeThrough(args[0], rangeWhole, false)
		}
	case "append":
		// Appending to a reslice writes into the array it shares.
		if len(args) > 1 {
			if _, ok := ast.Unparen(args[0]).(*ast.SliceExpr); ok {
				s.writeThrough(args[0], rangeWhole, false)
			}
		}
	}
	return true
}

// dataCall reports a call that only computes on the value, and records what
// it writes the value into: a memory writer it is called on, a pointer
// argument.
func (s *rangeScope) dataCall(site rangeCallSite) bool {
	call := site.call
	if !rangeDataCall(call, s.info) && !s.formatMethod(call) && !s.parserCall(call) {
		return false
	}
	// A subtest's function takes only the *testing.T; it is analyzed in
	// place.
	if !isSubtest(call, s.info) && !s.dataCallbacks(call) {
		return false
	}
	writes := false
	for _, c := range site.args {
		writes = writes || c != rangeNone
	}
	if !writes {
		return true
	}
	if site.receiver != nil && rangeMemoryWriter(s.info.TypeOf(site.receiver)) {
		s.writeThrough(site.receiver, rangeWhole, site.addressed)
	}
	for i, arg := range call.Args {
		if site.args[i] != rangeNone {
			continue
		}
		if _, pointer := s.info.TypeOf(arg).Underlying().(*types.Pointer); pointer {
			s.writeThrough(arg, rangeWhole, false)
		}
	}
	return true
}

// formatMethod is Error() or String() called through an interface: it
// formats the value it is called on.
func (s *rangeScope) formatMethod(call *ast.CallExpr) bool {
	fn := rangeCallFunc(call, s.info)
	if fn == nil || len(call.Args) != 0 || fn.Name() != "Error" && fn.Name() != "String" {
		return false
	}
	recv := fn.Signature().Recv()
	return recv != nil && types.IsInterface(recv.Type())
}

// dataCallbacks reports that every function a data call takes is itself a
// data function: a closure given to strings.Map or regexp would run with the
// value outside the analysis.
func (s *rangeScope) dataCallbacks(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		t := s.info.TypeOf(arg)
		if t == nil {
			continue
		}
		if _, isFunc := t.Underlying().(*types.Signature); !isFunc {
			continue
		}
		var object types.Object
		switch fun := ast.Unparen(arg).(type) {
		case *ast.Ident:
			object = s.info.Uses[fun]
		case *ast.SelectorExpr:
			object = s.info.Uses[fun.Sel]
		}
		fn, _ := object.(*types.Func)
		if !rangeDataFunc(fn) {
			return false
		}
	}
	return true
}

// followCall analyzes the function a call reaches when its syntax is loaded,
// or every implementation of an interface method declared in the project.
func (s *rangeScope) followCall(site rangeCallSite) bool {
	fn := rangeCallFunc(site.call, s.info)
	if fn == nil {
		return false
	}
	if decl, ok := s.pkg.rangeFunc(fn); ok {
		s.follow(site, fn, decl)
		return true
	}
	impls, ok := s.interfaceImpls(fn)
	if !ok {
		return false
	}
	for _, impl := range impls {
		if decl, ok := s.pkg.rangeFunc(impl); ok {
			s.follow(site, impl, decl)
		} else if !rangeDataFunc(impl) {
			s.flow.unknown = true
		}
	}
	return true
}

func (s *rangeScope) follow(site rangeCallSite, fn *types.Func, decl rangeFuncDecl) {
	classes := site.key()
	if active, ok := s.stack[fn]; ok {
		// A recursive call with no more than the classes the function was
		// entered with does nothing the analysis of that body does not; it
		// stores what that body stores through its parameters.
		if !rangeClassesCovered(classes, active.entered) {
			s.flow.unknown = true
			return
		}
		s.applyWritten(site, fn, active.written)
		return
	}
	key := rangeCallKey{fn: fn, classes: classes, generation: s.a.generation}
	result, ok := s.a.cache[key]
	if !ok {
		result = s.enter(site, fn, decl, classes)
		if !result.flow.limited {
			s.a.cache[key] = result
		}
	}
	s.flow.executes = s.flow.executes || result.flow.executes
	s.flow.unknown = s.flow.unknown || result.flow.unknown
	s.flow.limited = s.flow.limited || result.flow.limited
	s.applyWritten(site, fn, result.written)
}

// applyWritten carries a callee's stores through its parameters to the
// arguments of the call.
func (s *rangeScope) applyWritten(site rangeCallSite, fn *types.Func, written map[int]rangeClass) {
	for index, c := range written {
		arg, addressed, ok := site.argument(index)
		if !ok || index >= 0 && fn.Signature().Variadic() && index >= fn.Signature().Params().Len()-1 {
			s.escapes = true
			continue
		}
		s.writeThrough(arg, c, addressed)
	}
}

func rangeClassesCovered(classes, entered string) bool {
	if len(classes) != len(entered) {
		return false
	}
	for i := range len(classes) {
		if classes[i] > entered[i] {
			return false
		}
	}
	return true
}

func (s *rangeScope) enter(site rangeCallSite, fn *types.Func, decl rangeFuncDecl, classes string) rangeCallResult {
	if decl.decl.Body == nil {
		return rangeCallResult{flow: rangeFlowResult{unknown: true}}
	}
	stack := make(map[*types.Func]*rangeScope, len(s.stack)+1)
	maps.Copy(stack, s.stack)
	callee := s.a.newScope(decl.decl.Body, decl.info, decl.pkg, s.depth+1, stack)
	callee.callee, callee.entered = true, classes
	summary := rangeSummaryKey{fn: fn, classes: classes}
	if s.a.summaries[summary] == nil {
		s.a.summaries[summary] = make(map[int]rangeClass)
	}
	callee.written = s.a.summaries[summary]
	stack[fn] = callee
	if !callee.bind(site, decl.decl, fn) {
		return rangeCallResult{flow: rangeFlowResult{unknown: true}}
	}
	flow := callee.run()
	return rangeCallResult{flow: flow, written: callee.written}
}

// bind gives the callee's parameters the classes of the call's arguments.
func (s *rangeScope) bind(site rangeCallSite, decl *ast.FuncDecl, fn *types.Func) bool {
	signature, ok := fn.Type().(*types.Signature)
	if !ok || decl.Type.Params == nil {
		return false
	}
	args := site.args
	recvClass := site.recvClass
	if site.methodExpr {
		if len(args) == 0 {
			return false
		}
		recvClass, args = args[0], args[1:]
	}
	if decl.Recv != nil {
		for _, field := range decl.Recv.List {
			for _, name := range field.Names {
				if obj := s.info.Defs[name]; obj != nil {
					s.params[obj] = -1
					s.setClass(obj, recvClass)
				}
			}
		}
	}
	s.bindNames(decl.Type.Params, func(obj types.Object, index int) { s.params[obj] = index })
	s.bindNames(decl.Type.Results, func(obj types.Object, _ int) { s.results[obj] = true })
	variadic := signature.Variadic() && !site.call.Ellipsis.IsValid()
	for i, class := range args {
		if class == rangeNone {
			continue
		}
		name, found := rangeParameterName(decl.Type.Params, i, variadic)
		if !found {
			return false
		}
		if name == nil || name.Name == "_" {
			continue
		}
		obj := s.info.Defs[name]
		if obj == nil {
			return false
		}
		if variadic && i >= signature.Params().Len()-1 {
			class = rangeWhole
		}
		s.setClass(obj, class)
	}
	return true
}

func (s *rangeScope) bindNames(fields *ast.FieldList, bind func(types.Object, int)) {
	if fields == nil {
		return
	}
	index := 0
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			if obj := s.info.Defs[name]; obj != nil {
				bind(obj, index)
			}
			index++
		}
	}
}

// markUnknown makes the result unknown when a use of the value is neither
// followed (a call, an assignment, a return to the caller) nor harmless.
func (s *rangeScope) markUnknown() {
	s.markReturns()
	ast.Inspect(s.body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || s.handled[id] || s.propagated[id] || s.fieldName(id) {
			return true
		}
		if _, isVar := s.info.Uses[id].(*types.Var); !isVar || s.class(id) == rangeNone {
			return true
		}
		if !s.harmlessUse(id) {
			s.flow.unknown = true
		}
		return true
	})
}

// fieldName is the field of a selector or of a struct literal key: the
// selector or literal stands for the use.
func (s *rangeScope) fieldName(id *ast.Ident) bool {
	switch parent := s.parents[id].(type) {
	case *ast.SelectorExpr:
		return parent.Sel == id
	case *ast.KeyValueExpr:
		if parent.Key != id {
			return false
		}
		lit, ok := s.parents[parent].(*ast.CompositeLit)
		if !ok {
			return false
		}
		_, isStruct := helpers.StructUnder(s.info.TypeOf(lit))
		return isStruct
	}
	return false
}

// harmlessUse reports a use that only reads the value to decide: a
// comparison, a condition, a switch tag, a case, a counter, or a field that
// holds nothing of it.
func (s *rangeScope) harmlessUse(id *ast.Ident) bool {
	var node ast.Node = id
	// keyed: the value indexes what it reaches; a write there stores it as
	// a key.
	keyed := false
	for {
		parent := s.parents[node]
		switch p := parent.(type) {
		case *ast.SelectorExpr:
			selection := s.info.Selections[p]
			if p.X != node || selection == nil || selection.Kind() != types.FieldVal {
				return false
			}
			if s.class(p) == rangeNone {
				return true
			}
		case *ast.IndexExpr:
			keyed = keyed || p.Index == node
		case *ast.ParenExpr, *ast.StarExpr, *ast.UnaryExpr, *ast.IndexListExpr, *ast.SliceExpr, *ast.TypeAssertExpr:
		case *ast.BinaryExpr:
			if rangeComparison(p.Op) {
				return true
			}
		case *ast.IfStmt:
			return p.Cond == node
		case *ast.ForStmt:
			return p.Cond == node
		case *ast.SwitchStmt:
			return p.Tag == node
		case *ast.CaseClause:
			for _, value := range p.List {
				if value == node {
					return true
				}
			}
			return false
		case *ast.IncDecStmt:
			return !keyed
		case *ast.AssignStmt:
			// A target is overwritten, not read: what the right side
			// carries was propagated.
			for _, target := range p.Lhs {
				if target == node {
					return !keyed
				}
			}
			return false
		default:
			return false
		}
		node = parent
	}
}

func rangeComparison(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
		return true
	}
	return false
}

// markReturns explains a value a reached function returns: its caller's call
// expression carries it on. A return from the root or from a closure takes
// the value where the analysis does not follow.
func (s *rangeScope) markReturns() {
	ast.Inspect(s.body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			ast.Inspect(n.Body, func(inner ast.Node) bool {
				if ret, ok := inner.(*ast.ReturnStmt); ok {
					s.returnValues(ret, false)
				}
				return true
			})
			return false
		case *ast.ReturnStmt:
			s.returnValues(n, s.callee)
		}
		return true
	})
}

func (s *rangeScope) returnValues(ret *ast.ReturnStmt, toCaller bool) {
	for _, result := range ret.Results {
		if s.class(result) == rangeNone {
			continue
		}
		if !toCaller {
			s.flow.unknown = true
			return
		}
		s.markUses(result, s.handled)
	}
}
