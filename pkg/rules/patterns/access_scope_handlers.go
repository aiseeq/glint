package patterns

import (
	"go/ast"
	"go/types"
	"sort"
	"strings"
)

// viewerScope is what the handlers of a project know about the viewer's
// scope: the slice fields that carry it (the tenant ids of the signed-in
// user) and the functions that check or filter by them.
type viewerScope struct {
	fields   map[*types.Var]bool
	checkers map[*types.Func]bool
	packages map[*types.Package]bool // the packages that read a scope field
}

// collectViewerScope finds the scope fields of a project: a slice field
// handed to a reader of another package (ListRecent(ctx, 20, v.TenantIDs),
// directly, through a local variable or inside a literal) that a function
// returning bool also reads, the way an access check does, or that is
// compared with nil (nil for every scope). The checkers are
// the functions outside the handlers that read a scope field, and those that
// call a checker.
func collectViewerScope(decls map[*types.Func]typedFuncDecl) viewerScope {
	scope := viewerScope{fields: map[*types.Var]bool{}, checkers: map[*types.Func]bool{}, packages: map[*types.Package]bool{}}
	passed := map[*types.Var]bool{}
	readByBool := map[*types.Var]bool{}
	for fn, d := range decls {
		if d.decl.Body == nil {
			continue
		}
		locals := sliceFieldLocals(d.info, d.decl.Body)
		ast.Inspect(d.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isForeignReader(d.info, call, fn.Pkg()) {
				return true
			}
			for _, arg := range call.Args {
				for field := range sliceFieldsIn(d.info, arg, locals) {
					passed[field] = true
				}
			}
			return true
		})
		if returnsBool(fn) {
			for field := range sliceFieldsIn(d.info, d.decl.Body, nil) {
				readByBool[field] = true
			}
		}
		ast.Inspect(d.decl.Body, func(n ast.Node) bool {
			if bin, ok := n.(*ast.BinaryExpr); ok && (isNilIdent(bin.Y) || isNilIdent(bin.X)) {
				for field := range sliceFieldsIn(d.info, bin, nil) {
					readByBool[field] = true // nil means every scope: a scope check
				}
			}
			return true
		})
	}
	for field := range passed {
		if readByBool[field] {
			scope.fields[field] = true
		}
	}
	if len(scope.fields) == 0 {
		return scope
	}
	for fn, d := range decls {
		if d.decl.Body == nil || !scope.mentionsField(d.info, d.decl.Body) {
			continue
		}
		scope.packages[fn.Pkg()] = true
		if !isHandlerSignature(fn) {
			scope.checkers[fn] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for fn, d := range decls {
			if scope.checkers[fn] || d.decl.Body == nil || isHandlerSignature(fn) {
				continue
			}
			if scope.callsChecker(d.info, d.decl.Body) {
				scope.checkers[fn] = true
				changed = true
			}
		}
	}
	return scope
}

// isHandlerSignature reports a function taking an http.ResponseWriter.
func isHandlerSignature(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	for i := range sig.Params().Len() {
		if types.TypeString(sig.Params().At(i).Type(), nil) == "net/http.ResponseWriter" {
			return true
		}
	}
	return false
}

// returnsBool reports a function with a bool result.
func returnsBool(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	for i := range sig.Results().Len() {
		if basic, ok := sig.Results().At(i).Type().Underlying().(*types.Basic); ok && basic.Kind() == types.Bool {
			return true
		}
	}
	return false
}

// isForeignReader reports a call of a method of another package that hands
// out records: Get/List/Find... returning a slice, a map or a pointer.
func isForeignReader(info *types.Info, call *ast.CallExpr, pkg *types.Package) bool {
	callee := staticFunc(info, call)
	if callee == nil || callee.Pkg() == nil || callee.Pkg() == pkg || !readMethodName.MatchString(callee.Name()) || !returnsRecords(callee) {
		return false
	}
	sig, ok := callee.Type().(*types.Signature)
	return ok && sig.Recv() != nil
}

// sliceFieldLocals maps the local variables assigned straight from a slice
// field (ids := v.TenantIDs) to that field.
func sliceFieldLocals(info *types.Info, body *ast.BlockStmt) map[types.Object]*types.Var {
	locals := map[types.Object]*types.Var{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			field := sliceField(info, rhs)
			ident, ok := assign.Lhs[i].(*ast.Ident)
			if field != nil && ok {
				if obj := info.ObjectOf(ident); obj != nil {
					locals[obj] = field
				}
			}
		}
		return true
	})
	return locals
}

// sliceField returns the field a selector expression reads when it is a
// slice field.
func sliceField(info *types.Info, expr ast.Expr) *types.Var {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	field, ok := info.Uses[sel.Sel].(*types.Var)
	if !ok || !field.IsField() {
		return nil
	}
	if _, ok := field.Type().Underlying().(*types.Slice); !ok {
		return nil
	}
	return field
}

// sliceFieldsIn returns the slice fields an expression reads, directly or
// through the given locals.
func sliceFieldsIn(info *types.Info, node ast.Node, locals map[types.Object]*types.Var) map[*types.Var]bool {
	fields := map[*types.Var]bool{}
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if field := sliceField(info, x); field != nil {
				fields[field] = true
			}
		case *ast.Ident:
			if field, ok := locals[info.ObjectOf(x)]; ok {
				fields[field] = true
			}
		}
		return true
	})
	return fields
}

// mentionsField reports a read of a scope field inside node.
func (s viewerScope) mentionsField(info *types.Info, node ast.Node) bool {
	for field := range sliceFieldsIn(info, node, nil) {
		if s.fields[field] {
			return true
		}
	}
	return false
}

// callsChecker reports a call of a checker inside node.
func (s viewerScope) callsChecker(info *types.Info, node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if callee := staticFunc(info, call); callee != nil && s.checkers[callee.Origin()] {
				found = true
			}
		}
		return !found
	})
	return found
}

// handlerReadsOutsideScope returns the reader calls of a handler that get
// neither the viewer's scope nor a check of what they take or return: no
// argument reads a scope field (or a variable assigned from one, or a
// checker's result), the reader takes no parameter of the scope's type, and
// no expression of the handler puts the scope or a checker next to the
// reader's arguments or results (checkOrder(v, o), allowed(v, t.ID) in a
// loop over the result, v.TenantIDs = ids).
func (s viewerScope) handlerReadsOutsideScope(info *types.Info, fn *ast.FuncDecl) []*ast.CallExpr {
	if len(s.fields) == 0 || fn.Body == nil || handlerRequestParam(typedFunc{info: info, decl: fn}) == nil {
		return nil
	}
	self, ok := info.Defs[fn.Name].(*types.Func)
	if !ok || !s.packages[self.Pkg()] {
		return nil
	}
	scoped := s.scopedLocals(info, fn.Body)
	looked := dependencyResults(info, fn)
	var calls []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isForeignReader(info, call, self.Pkg()) || s.takesScopeType(staticFunc(info, call)) || !s.tenantOwned(staticFunc(info, call)) {
			return true
		}
		for _, arg := range call.Args {
			// A key that another lookup of the handler returned (the
			// transaction's project, the transaction a redeemed link names)
			// inherits that lookup's scope: the check belongs there.
			if s.scopeIn(info, arg, scoped) || mentionsAnyObject(info, arg, looked) {
				return true
			}
		}
		if returnsResult(info, fn, call) {
			return true // the caller gets the records and filters them
		}
		if !s.checkedNearby(info, fn.Body, readerRelated(info, fn, call), scoped) {
			calls = append(calls, call)
		}
		return true
	})
	sort.Slice(calls, func(i, j int) bool { return calls[i].Pos() < calls[j].Pos() })
	return calls
}

// dependencyResults returns the local variables assigned from a call of a
// dependency of the handler's receiver (a.links.Redeem(...), a.orders.Get(...)).
func dependencyResults(info *types.Info, fn *ast.FuncDecl) map[types.Object]bool {
	results := map[types.Object]bool{}
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return results
	}
	receiver := info.Defs[fn.Recv.List[0].Names[0]]
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		method, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		dep, ok := ast.Unparen(method.X).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if root, ok := ast.Unparen(dep.X).(*ast.Ident); !ok || receiver == nil || info.Uses[root] != receiver {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
				if obj := info.ObjectOf(ident); obj != nil {
					results[obj] = true
				}
			}
		}
		return true
	})
	return results
}

// returnsResult reports a reader call whose result the function returns.
func returnsResult(info *types.Info, fn *ast.FuncDecl, call *ast.CallExpr) bool {
	results := map[types.Object]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || ast.Unparen(assign.Rhs[0]) != call {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
				// The error is passed up from every call; only records count.
				if obj := info.ObjectOf(ident); obj != nil && types.TypeString(obj.Type(), nil) != "error" {
					results[obj] = true
				}
			}
		}
		return false
	})
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if ret, ok := n.(*ast.ReturnStmt); ok {
			for _, result := range ret.Results {
				if ast.Unparen(result) == call || mentionsAnyObject(info, result, results) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// tenantOwned reports a reader whose records belong to a scope: their type
// is the scope's own entity (Tenant for TenantIDs), carries its id
// (TenantID), or carries the id of a type that does (an OrderID, the order
// holding the TenantID). Users, settings and reference tables have none:
// their pages are guarded by the viewer's level, not filtered by scope.
func (s viewerScope) tenantOwned(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Results().Len() == 0 {
		return false
	}
	elem := sig.Results().At(0).Type()
	for range 3 {
		switch t := elem.Underlying().(type) {
		case *types.Pointer:
			elem = t.Elem()
		case *types.Slice:
			elem = t.Elem()
		case *types.Map:
			elem = t.Elem()
		}
	}
	named, ok := types.Unalias(elem).(*types.Named)
	return ok && s.ownsScope(named, 1)
}

// ownsScope reports a named type that is a scope entity or carries the id of
// one; depth is how many id links to follow to another type.
func (s viewerScope) ownsScope(named *types.Named, depth int) bool {
	st, _ := named.Underlying().(*types.Struct)
	for field := range s.fields {
		entity, found := strings.CutSuffix(field.Name(), "IDs")
		if !found {
			entity, found = strings.CutSuffix(field.Name(), "Ids")
		}
		if !found || entity == "" {
			continue
		}
		if named.Obj().Name() == entity {
			return true
		}
		for i := 0; st != nil && i < st.NumFields(); i++ {
			if st.Field(i).Name() == entity+"ID" || st.Field(i).Name() == entity+"Id" {
				return true
			}
		}
	}
	if depth == 0 || st == nil {
		return false
	}
	for i := range st.NumFields() {
		name := st.Field(i).Name()
		target, found := strings.CutSuffix(name, "ID")
		if !found {
			target, found = strings.CutSuffix(name, "Id")
		}
		if !found || target == "" {
			continue
		}
		if linked := typeNamedIn(named.Obj().Pkg(), target); linked != nil && linked != named && s.ownsScope(linked, depth-1) {
			return true
		}
	}
	return false
}

// typeNamedIn finds a named type by name in a package or the packages it
// imports.
func typeNamedIn(pkg *types.Package, name string) *types.Named {
	if pkg == nil {
		return nil
	}
	for _, p := range append([]*types.Package{pkg}, pkg.Imports()...) {
		if tn, ok := p.Scope().Lookup(name).(*types.TypeName); ok {
			if named, ok := types.Unalias(tn.Type()).(*types.Named); ok {
				return named
			}
		}
	}
	return nil
}

// takesScopeType reports a function with a parameter of a scope field's type.
func (s viewerScope) takesScopeType(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	for i := range sig.Params().Len() {
		for field := range s.fields {
			if types.Identical(sig.Params().At(i).Type(), field.Type()) {
				return true
			}
		}
	}
	return false
}

// scopedLocals returns the local variables assigned from the scope: a scope
// field, a checker's result, or another such variable.
func (s viewerScope) scopedLocals(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	scoped := map[types.Object]bool{}
	mark := func(expr ast.Expr) bool {
		ident, ok := expr.(*ast.Ident)
		if !ok {
			return false
		}
		obj := info.ObjectOf(ident)
		if obj == nil || scoped[obj] {
			return false
		}
		scoped[obj] = true
		return true
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			if loop, ok := n.(*ast.RangeStmt); ok && s.scopeIn(info, loop.X, scoped) {
				changed = mark(loop.Key) || changed
				changed = mark(loop.Value) || changed
				return true
			}
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			rhsScoped := false
			for _, rhs := range assign.Rhs {
				rhsScoped = rhsScoped || s.scopeIn(info, rhs, scoped)
			}
			if !rhsScoped {
				return true
			}
			for _, lhs := range assign.Lhs {
				changed = mark(lhs) || changed
			}
			return true
		})
	}
	return scoped
}

// scopeIn reports a node that reads the scope: a scope field, a scoped
// local, or a call of a checker.
func (s viewerScope) scopeIn(info *types.Info, node ast.Node, scoped map[types.Object]bool) bool {
	if s.mentionsField(info, node) || s.callsChecker(info, node) {
		return true
	}
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && scoped[info.ObjectOf(ident)] {
			found = true
		}
		return !found
	})
	return found
}

// readerRelated returns the local variables a reader call takes and the ones
// its results are assigned to, with the loop variables of ranges over them.
// The request, the writer, the context and the receiver are everywhere and
// relate to nothing.
func readerRelated(info *types.Info, fn *ast.FuncDecl, call *ast.CallExpr) map[types.Object]bool {
	body := fn.Body
	var receiver types.Object
	if fn.Recv != nil && len(fn.Recv.List) == 1 && len(fn.Recv.List[0].Names) == 1 {
		receiver = info.Defs[fn.Recv.List[0].Names[0]]
	}
	related := map[types.Object]bool{}
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok {
				if v, ok := info.Uses[ident].(*types.Var); ok && !v.IsField() && v != receiver && !ambientType(v.Type()) {
					related[v] = true
				}
			}
			return true
		})
	}
	// The results of this call, and of every other call keyed by the same
	// variables: the transaction read by the id whose history this call
	// reads is what a check of the id looks at.
	keys := map[types.Object]bool{}
	for obj := range related {
		keys[obj] = true
	}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		other, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		if other != call {
			keyed := false
			for _, arg := range other.Args {
				keyed = keyed || mentionsAnyObject(info, arg, keys)
			}
			if !keyed {
				return true
			}
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
				if obj := info.ObjectOf(ident); obj != nil {
					related[obj] = true
				}
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok || !mentionsAnyObject(info, loop.X, related) {
			return true
		}
		for _, v := range []ast.Expr{loop.Key, loop.Value} {
			if ident, ok := v.(*ast.Ident); ok && ident.Name != "_" {
				if obj := info.ObjectOf(ident); obj != nil {
					related[obj] = true
				}
			}
		}
		return true
	})
	return related
}

// ambientType reports the types a handler passes everywhere: the request,
// the writer, the context.
func ambientType(t types.Type) bool {
	switch types.TypeString(t, nil) {
	case "context.Context", "*net/http.Request", "net/http.ResponseWriter":
		return true
	}
	return false
}

// mentionsAnyObject reports an identifier of one of the objects inside node.
func mentionsAnyObject(info *types.Info, node ast.Node, objects map[types.Object]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && objects[info.ObjectOf(ident)] {
			found = true
		}
		return !found
	})
	return found
}

// checkedNearby reports an expression of the body that holds both the scope
// and one of the related variables: a check, a filter or a scope assignment.
func (s viewerScope) checkedNearby(info *types.Info, body *ast.BlockStmt, related, scoped map[types.Object]bool) bool {
	if len(related) == 0 {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.CallExpr, *ast.BinaryExpr, *ast.IndexExpr, *ast.AssignStmt:
			if mentionsAnyObject(info, n, related) && s.scopeIn(info, n, scoped) {
				found = true
			}
		}
		return !found
	})
	return found
}
