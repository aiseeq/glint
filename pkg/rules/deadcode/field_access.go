package deadcode

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// fieldAccess records how the loaded packages touch struct fields. It is the
// one traversal unused-field, never-assigned-field and unused-config-field
// share; each rule reads the sets it needs.
//
// Fields are keyed by the position of their declaration rather than by
// *types.Var: a field reached through an instantiated generic type is a
// different object than the one its declaration defines.
type fieldAccess struct {
	// read: the value is consumed — a selector that is not the target of an
	// assignment or of ++/--, including &x.f, which hands the value out.
	read map[token.Pos]bool
	// written: assigned, updated, named as a key in a composite literal, filled
	// by a positional literal, or handed out by address.
	written map[token.Pos]bool
	// valueWritten: written with something other than a provable nil — a
	// field only ever given nil or (*T)(nil) holds no value.
	valueWritten map[token.Pos]bool
	// dereferenced: a pointer field used through (x.f.y, x.f.M(), *x.f).
	dereferenced map[token.Pos]bool
	// storedInto: a map field indexed on the left of an assignment or of
	// ++/-- (x.f[k] = v) — the one use of a nil map that panics.
	storedInto map[token.Pos]bool
	// hashed: the field of a struct used as a whole — compared with == or !=,
	// or used as a map key — which the runtime reads field by field.
	hashed map[token.Pos]bool

	// decoded and encoded are the named structs that reach a decoder or an
	// encoder, following their fields.
	decoded map[*types.Named]bool
	encoded map[*types.Named]bool
	// boxed are the named structs whose values reach an empty interface - an
	// any parameter, fixed or variadic, or an element of a literal of any -
	// following pointers, slices, maps and fields: reflection behind it
	// (templates, fmt, encoders behind a wrapper) may read every exported field.
	boxed map[*types.Named]bool
	// decoderWrappers are the functions that hand an untyped parameter to a
	// decoder (get(path string, out any) { ... Decode(out) }), with the
	// indexes of those parameters.
	decoderWrappers map[*types.Func][]int
	// requestDecoded are the named structs decoded from the body of an
	// incoming request (json.NewDecoder(r.Body).Decode(&req)): what the
	// program's own clients send to it. requestWrappers are the decoder
	// wrappers that decode a request body; requestDecoders the variables
	// holding a decoder of one.
	requestDecoded  map[*types.Named]bool
	requestWrappers map[*types.Func]bool
	requestDecoders map[types.Object]bool
}

func newFieldAccess() *fieldAccess {
	return &fieldAccess{
		read:         make(map[token.Pos]bool),
		written:      make(map[token.Pos]bool),
		valueWritten: make(map[token.Pos]bool),
		dereferenced: make(map[token.Pos]bool),
		storedInto:   make(map[token.Pos]bool),
		hashed:       make(map[token.Pos]bool),
		decoded:      make(map[*types.Named]bool),
		encoded:      make(map[*types.Named]bool),
		boxed:        make(map[*types.Named]bool),

		decoderWrappers: make(map[*types.Func][]int),
		requestDecoded:  make(map[*types.Named]bool),
		requestWrappers: make(map[*types.Func]bool),
		requestDecoders: make(map[types.Object]bool),
	}
}

// collectProjectFieldAccess records the field accesses of every loaded
// package: a package whose files are not analyzed still reads and writes the
// fields of the ones that are.
type fieldAccessKey struct{}

// projectFieldAccess is collectProjectFieldAccess built once per project and
// shared by the field rules.
func projectFieldAccess(ctx *core.GoProjectContext) (*fieldAccess, error) {
	return core.SharedLoad(ctx, fieldAccessKey{}, func() (*fieldAccess, error) {
		return collectProjectFieldAccess(ctx)
	})
}

func collectProjectFieldAccess(ctx *core.GoProjectContext) (*fieldAccess, error) {
	access := newFieldAccess()
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("package has no typed syntax")
		}
		for _, file := range pkg.Package.Syntax {
			access.findDecoderWrappers(file, pkg.Package.TypesInfo)
		}
	}
	for _, pkg := range ctx.Packages {
		for _, file := range pkg.Package.Syntax {
			access.collect(file, pkg.Package.TypesInfo)
		}
	}
	return access, nil
}

// findDecoderWrappers records the functions of a file whose untyped
// parameter goes straight into a decoder call.
func (a *fieldAccess) findDecoderWrappers(file *ast.File, info *types.Info) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		obj, ok := info.Defs[fn.Name].(*types.Func)
		if !ok {
			continue
		}
		untyped := make(map[types.Object]int)
		index := 0
		for _, field := range fn.Type.Params.List {
			names := field.Names
			if len(names) == 0 {
				index++
				continue
			}
			for _, name := range names {
				if param := info.Defs[name]; param != nil && isEmptyInterface(param.Type()) {
					untyped[param] = index
				}
				index++
			}
		}
		if len(untyped) == 0 {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if assign, ok := n.(*ast.AssignStmt); ok {
				a.recordRequestDecoders(assign, info)
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := calledFunc(call, info)
			if callee == nil || !slices.Contains(decodeFuncs, callee.Name()) {
				return true
			}
			for _, arg := range call.Args {
				if id, ok := ast.Unparen(arg).(*ast.Ident); ok {
					if i, found := untyped[info.Uses[id]]; found && !slices.Contains(a.decoderWrappers[obj], i) {
						a.decoderWrappers[obj] = append(a.decoderWrappers[obj], i)
					}
					if _, found := untyped[info.Uses[id]]; found && a.decodesRequestBody(call, info) {
						a.requestWrappers[obj] = true
					}
				}
			}
			return true
		})
	}
}

// collect records the field accesses of one file in a single pass.
func (a *fieldAccess) collect(file *ast.File, info *types.Info) {
	// Inspect visits a statement before its operands, so the targets of an
	// assignment are known by the time its selectors are classified.
	targets := make(map[ast.Expr]bool)
	nilTargets := make(map[ast.Expr]bool)

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			a.recordRequestDecoders(node, info)
			for i, lhs := range node.Lhs {
				a.target(lhs, info, targets)
				if len(node.Lhs) == len(node.Rhs) && helpers.IsNilValue(node.Rhs[i], info) {
					nilTargets[ast.Unparen(lhs)] = true
				}
			}
		case *ast.IncDecStmt:
			a.target(node.X, info, targets)
		case *ast.SelectorExpr:
			a.selector(node, info, targets, nilTargets)
		case *ast.UnaryExpr:
			// &x.f hands the address out: assume the callee writes through it.
			if node.Op == token.AND {
				if pos, ok := selectedField(info, node.X); ok {
					a.markWritten(pos, true)
				}
			}
		case *ast.StarExpr:
			if pos, ok := selectedField(info, node.X); ok {
				a.dereferenced[pos] = true
			}
		case *ast.CompositeLit:
			a.literal(node, info)
			a.boxedElements(node, info)
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				a.markHashed(info.TypeOf(node.X))
				a.markHashed(info.TypeOf(node.Y))
			}
		case *ast.CallExpr:
			a.serialization(node, info)
			a.emptyInterfaceArguments(node, info)
		case *ast.IndexExpr:
			// m[k] of a map[any]: the key is hashed as the interface's
			// dynamic value.
			if mapType, ok := underlyingMap(info.TypeOf(node.X)); ok && isEmptyInterface(mapType.Key()) {
				a.markHashed(info.TypeOf(node.Index))
			}
		}
		if expr, ok := n.(ast.Expr); ok {
			if mapType, ok := underlyingMap(info.TypeOf(expr)); ok {
				a.markHashed(mapType.Key())
			}
		}
		return true
	})
}

// emptyInterfaceArguments marks the struct values a call hands over as an
// empty interface parameter: such a value is compared or hashed whole (a
// context key, a key of a map[any]). The variadic tail is left out: ...any
// formats or logs its arguments, and printing a field does not use it. An
// interface with methods is used through them, and the methods' own selectors
// count.
func (a *fieldAccess) emptyInterfaceArguments(call *ast.CallExpr, info *types.Info) {
	signature, ok := types.Unalias(info.TypeOf(call.Fun)).(*types.Signature)
	if !ok {
		return
	}
	fixed := signature.Params().Len()
	if signature.Variadic() {
		fixed--
	}
	for i, arg := range call.Args {
		if isUntypedParam(signature, i) && call.Ellipsis == token.NoPos {
			addReachableStructs(a.boxed, info.TypeOf(arg))
		}
		if i >= fixed {
			continue
		}
		if isEmptyInterface(signature.Params().At(i).Type()) {
			a.markHashed(info.TypeOf(arg))
		}
	}
}

// boxedElements records the values of a slice or map literal whose elements
// are an empty interface (map[string]any{"rows": rows}).
func (a *fieldAccess) boxedElements(lit *ast.CompositeLit, info *types.Info) {
	var elem types.Type
	switch typ := types.Unalias(info.TypeOf(lit)).Underlying().(type) {
	case *types.Slice:
		elem = typ.Elem()
	case *types.Array:
		elem = typ.Elem()
	case *types.Map:
		elem = typ.Elem()
	default:
		return
	}
	if !isEmptyInterface(elem) {
		return
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		addReachableStructs(a.boxed, info.TypeOf(elt))
	}
}

// isEmptyInterface reports whether t is an interface without methods: any,
// interface{}.
func isEmptyInterface(t types.Type) bool {
	iface, ok := t.Underlying().(*types.Interface)
	return ok && iface.NumMethods() == 0
}

// selector classifies one field selector.
func (a *fieldAccess) selector(sel *ast.SelectorExpr, info *types.Info, targets, nilTargets map[ast.Expr]bool) {
	if pos, ok := selectedField(info, sel); ok {
		if targets[sel] {
			a.markWritten(pos, !nilTargets[sel])
		} else {
			a.read[pos] = true
		}
	}
	// x.f.y / x.f.M() goes through x.f.
	if pos, ok := selectedField(info, sel.X); ok {
		a.dereferenced[pos] = true
	}
}

// literal records the fields a composite literal fills. A literal without
// keys is positional and fills every field of its struct.
func (a *fieldAccess) literal(lit *ast.CompositeLit, info *types.Info) {
	structType, ok := structUnder(info.TypeOf(lit))
	if !ok {
		return
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			for i := range structType.NumFields() {
				a.markWritten(structType.Field(i).Origin().Pos(), true)
			}
			return
		}
		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if v, ok := info.Uses[ident].(*types.Var); ok && v.IsField() {
			a.markWritten(v.Origin().Pos(), !helpers.IsNilValue(kv.Value, info))
		}
	}
}

// markWritten records a write of the field, and whether it gave the field a
// value rather than nil.
func (a *fieldAccess) markWritten(pos token.Pos, value bool) {
	a.written[pos] = true
	if value {
		a.valueWritten[pos] = true
	}
}

// markHashed marks every field the runtime reads to compare or hash a value
// of type t: the fields of a struct, and of the structs and arrays nested in
// it. Pointers and interfaces compare by identity or dynamic value, so the
// walk stops there.
func (a *fieldAccess) markHashed(t types.Type) {
	if t == nil {
		return
	}
	switch typ := t.Underlying().(type) {
	case *types.Struct:
		for i := range typ.NumFields() {
			field := typ.Field(i)
			pos := field.Origin().Pos()
			if a.hashed[pos] {
				continue
			}
			a.hashed[pos] = true
			a.markHashed(field.Type())
		}
	case *types.Array:
		a.markHashed(typ.Elem())
	}
}

// target records an expression a statement stores into: the left-hand side
// of an assignment or the operand of ++/--. Updating a counter keeps it
// current but consumes nothing; a read on the right-hand side is a separate
// node and still counts as a read. A store into x.f[k] with a map field f is
// the one use of a nil map that panics.
func (a *fieldAccess) target(expr ast.Expr, info *types.Info, targets map[ast.Expr]bool) {
	expr = ast.Unparen(expr)
	targets[expr] = true
	index, ok := expr.(*ast.IndexExpr)
	if !ok {
		return
	}
	pos, ok := selectedField(info, index.X)
	if !ok {
		return
	}
	if _, isMap := underlyingMap(info.TypeOf(index.X)); isMap {
		a.storedInto[pos] = true
	}
}

// selectedField returns the declaration position of the field an expression
// selects, or false when it is not a field selector.
func selectedField(info *types.Info, expr ast.Expr) (token.Pos, bool) {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return token.NoPos, false
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return token.NoPos, false
	}
	v, ok := selection.Obj().(*types.Var)
	if !ok {
		return token.NoPos, false
	}
	return v.Origin().Pos(), true
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

// decodeFuncs fill a Go value from outside the program: files, payloads, the
// environment. helpers.EncodeFuncs turn a value into bytes and read every
// exported field on the program's behalf.
var decodeFuncs = []string{
	"Unmarshal", "UnmarshalStrict", "UnmarshalExact", "UnmarshalKey",
	"Decode", "DecodeFile", "DecodeReader", "WeakDecode",
	"ReadConfig", "ReadEnv", "MapTo", "StrictMapTo",
	"Parse", "ParseWithOptions", "Process", "MustProcess",
}

// serialization records the types a decoder or an encoder call receives. A
// call counts when the callee has one of the known names and the argument
// goes into an untyped parameter (any / interface{}) — the signature every
// reflection-driven codec shares. A function merely named Decode that takes a
// concrete type does not fill it from outside.
func (a *fieldAccess) serialization(call *ast.CallExpr, info *types.Info) {
	fn := calledFunc(call, info)
	if fn == nil {
		return
	}
	if params, ok := a.decoderWrappers[fn.Origin()]; ok {
		for _, i := range params {
			if i < len(call.Args) {
				addReachableStructs(a.decoded, info.TypeOf(call.Args[i]))
				if a.requestWrappers[fn.Origin()] {
					addReachableStructs(a.requestDecoded, info.TypeOf(call.Args[i]))
				}
			}
		}
		return
	}
	if fn.Name() == "Decode" && a.decodesRequestBody(call, info) {
		for _, arg := range call.Args {
			addReachableStructs(a.requestDecoded, info.TypeOf(arg))
		}
	}
	var target map[*types.Named]bool
	switch {
	case slices.Contains(decodeFuncs, fn.Name()):
		target = a.decoded
	case slices.Contains(helpers.EncodeFuncs, fn.Name()):
		target = a.encoded
	default:
		return
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return
	}
	for i, arg := range call.Args {
		if isUntypedParam(sig, i) {
			addReachableStructs(target, info.TypeOf(arg))
		}
	}
}

// recordRequestDecoders records the variables an assignment gives a decoder
// of a request body: dec := json.NewDecoder(r.Body).
func (a *fieldAccess) recordRequestDecoders(assign *ast.AssignStmt, info *types.Info) {
	if len(assign.Lhs) != len(assign.Rhs) {
		return
	}
	for i, rhs := range assign.Rhs {
		if !isRequestBodyDecoder(rhs, info) {
			continue
		}
		if id, ok := assign.Lhs[i].(*ast.Ident); ok {
			if obj := info.ObjectOf(id); obj != nil {
				a.requestDecoders[obj] = true
			}
		}
	}
}

// decodesRequestBody reports a Decode call on a decoder of a request body:
// json.NewDecoder(r.Body).Decode(...) or dec.Decode(...) of such a decoder.
func (a *fieldAccess) decodesRequestBody(call *ast.CallExpr, info *types.Info) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Decode" {
		return false
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
		return a.requestDecoders[info.ObjectOf(id)]
	}
	return isRequestBodyDecoder(sel.X, info)
}

// isRequestBodyDecoder reports NewDecoder(r.Body) of an *http.Request r.
func isRequestBodyDecoder(expr ast.Expr, info *types.Info) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	if fn := calledFunc(call, info); fn == nil || fn.Name() != "NewDecoder" {
		return false
	}
	body, ok := ast.Unparen(call.Args[0]).(*ast.SelectorExpr)
	if !ok || body.Sel.Name != "Body" {
		return false
	}
	typ := info.TypeOf(body.X)
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := types.Unalias(typ).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "Request"
}

// calledFunc resolves the function or method a call invokes.
func calledFunc(call *ast.CallExpr, info *types.Info) *types.Func {
	var ident *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		ident = fun
	case *ast.SelectorExpr:
		ident = fun.Sel
	case *ast.IndexExpr:
		return calledFunc(&ast.CallExpr{Fun: fun.X}, info)
	case *ast.IndexListExpr:
		return calledFunc(&ast.CallExpr{Fun: fun.X}, info)
	default:
		return nil
	}
	fn, ok := info.Uses[ident].(*types.Func)
	if !ok {
		return nil
	}
	return fn
}

// isUntypedParam reports whether argument i of a call lands in a parameter of
// empty interface type.
func isUntypedParam(sig *types.Signature, i int) bool {
	params := sig.Params()
	if params.Len() == 0 {
		return false
	}
	var t types.Type
	switch {
	case i < params.Len()-1 || (i == params.Len()-1 && !sig.Variadic()):
		t = params.At(i).Type()
	case sig.Variadic():
		slice, ok := params.At(params.Len() - 1).Type().(*types.Slice)
		if !ok {
			return false
		}
		t = slice.Elem()
	default:
		return false
	}
	iface, ok := t.Underlying().(*types.Interface)
	return ok && iface.Empty()
}

// addReachableStructs walks a type and records every named struct it can reach
// through pointers, slices, maps and fields.
func addReachableStructs(set map[*types.Named]bool, t types.Type) {
	switch typ := types.Unalias(t).(type) {
	case *types.Pointer:
		addReachableStructs(set, typ.Elem())
	case *types.Slice:
		addReachableStructs(set, typ.Elem())
	case *types.Array:
		addReachableStructs(set, typ.Elem())
	case *types.Map:
		addReachableStructs(set, typ.Elem())
	case *types.Named:
		if set[typ] {
			return
		}
		structType, ok := typ.Underlying().(*types.Struct)
		if !ok {
			return
		}
		set[typ] = true
		for i := range structType.NumFields() {
			addReachableStructs(set, structType.Field(i).Type())
		}
	case *types.Struct:
		for i := range typ.NumFields() {
			addReachableStructs(set, typ.Field(i).Type())
		}
	}
}
