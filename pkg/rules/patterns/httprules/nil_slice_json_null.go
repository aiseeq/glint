package httprules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"golang.org/x/tools/go/types/typeutil"
)

func init() {
	rules.Register(NewNilSliceJSONNullRule())
}

// NilSliceJSONNullRule detects a list that starts as a nil slice, stays nil
// when nothing is found, and is encoded into a JSON response:
//
//	var entries []Entry
//	if err := db.SelectContext(ctx, &entries, query); err != nil { ... }
//	return entries, nil
//	...
//	writeJSON(w, response{Entries: entries}) // Entries []Entry `json:"entries"`
//
// encoding/json writes a nil slice as null, not []: a client that iterates
// or filters the list breaks for every user who has nothing in it yet. The
// slice is followed from the function that declares it - through functions
// returning it unchanged and through interface methods some implementation
// of which returns it - to a JSON field without omitempty, a key of a map
// written by an HTTP handler, json.Marshal, or a response helper that wraps
// its parameter into an envelope (a struct or map literal, inline or in a
// local) and encodes it.
type NilSliceJSONNullRule struct {
	*rules.BaseRule
}

// NewNilSliceJSONNullRule creates the rule
func NewNilSliceJSONNullRule() *NilSliceJSONNullRule {
	return &NilSliceJSONNullRule{BaseRule: rules.NewBaseRule(
		"nil-slice-json-null",
		"patterns",
		"Detects a list returned as a nil slice when empty that reaches a JSON response — the client gets null instead of []",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the slice and the response live in different functions.
func (r *NilSliceJSONNullRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NilSliceJSONNullRule) RequiresSSA() bool { return false }

// nilSliceSource is the declaration of a slice a function may return nil.
type nilSliceSource struct {
	file *core.FileContext
	name *ast.Ident
}

// AnalyzeGoProject reports the nil slice declarations whose value reaches JSON.
func (r *NilSliceJSONNullRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	decls, err := patternkit.FuncDeclsByObject(ctx)
	if err != nil {
		return nil, err
	}
	funcs := patternkit.ProjectFuncDecls(ctx)
	sources := nilSliceFuncs(funcs, patternkit.ProjectInterfaces(ctx))
	responders := jsonResponders(funcs, decls)

	reported := make(map[*ast.Ident]bool)
	var violations []*core.Violation
	for _, fn := range funcs {
		for _, sink := range nilSliceSinks(fn, sources, responders) {
			src := sink.source
			if reported[src.name] {
				continue
			}
			line := src.file.LineFor(src.name)
			if src.file.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[src.name] = true
			v := r.CreateViolation(src.file.RelPath, line, fmt.Sprintf(
				"Slice %s stays nil when nothing is found and reaches %s (%s:%d) — encoding/json writes null, and a client expecting a list breaks",
				src.name.Name, sink.what, fn.File.RelPath, fn.File.LineFor(sink.node)))
			v.WithCode(strings.TrimSpace(src.file.GetLine(line)))
			v.WithSuggestion(fmt.Sprintf("Start with an empty slice: %s := make(T, 0), or replace nil before encoding", src.name.Name))
			violations = append(violations, v)
		}
		for _, field := range appendOnlyFields(fn, responders) {
			line := fn.File.LineFor(field.owner)
			if reported[field.owner] || fn.File.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[field.owner] = true
			v := r.CreateViolation(fn.File.RelPath, line, fmt.Sprintf(
				"Field %s of %s is filled only by append in a loop and %s reaches a JSON response — with nothing to add it stays nil, encoding/json writes null, and a client expecting a list breaks",
				field.json, field.owner.Name, field.owner.Name))
			v.WithCode(strings.TrimSpace(fn.File.GetLine(line)))
			v.WithSuggestion("Set the field to an empty slice where the value is built")
			violations = append(violations, v)
		}
	}
	return violations, nil
}

// jsonResponders returns the functions that write some of their parameters
// to an http.ResponseWriter as JSON, with the indexes of those parameters:
// respondJSON(w, status, payload). A function that passes its parameter on
// to a responder - as it is or wrapped into the response envelope
// (Response[T]{Data: dataPtr(data)}) - is a responder too. Every parameter
// that may hold a list and reaches the JSON on some path counts: a helper
// encoding the message on its error path and the data on success, or two
// lists of one envelope, keeps each of them.
func jsonResponders(funcs []patternkit.TypedFunc, decls map[*types.Func]patternkit.TypedFuncDecl) map[*types.Func][]int {
	responders := make(map[*types.Func][]int)
	for changed := true; changed; {
		changed = false
		for _, fn := range funcs {
			obj, ok := fn.Info.Defs[fn.Decl.Name].(*types.Func)
			if !ok || !patternkit.HasResponseWriterParam(fn.Decl.Type.Params) {
				continue
			}
			if _, done := responders[obj]; done {
				continue
			}
			if indexes := respondedParams(fn, obj, decls, responders); len(indexes) > 0 {
				responders[obj] = indexes
				changed = true
			}
		}
	}
	return responders
}

// respondedParams returns the parameters a function encodes as JSON itself or
// hands, carried by the payload, to a responder.
func respondedParams(fn patternkit.TypedFunc, obj *types.Func, decls map[*types.Func]patternkit.TypedFuncDecl, responders map[*types.Func][]int) []int {
	params := obj.Signature().Params()
	responded := make([]bool, params.Len())
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		payloads := responderPayloads(call, fn.Info, responders)
		if jsonEncodeCall(call, fn.Info) && len(call.Args) > 0 {
			payloads = call.Args[:1]
		}
		for _, payload := range payloads {
			for i := range params.Len() {
				// A message string or a status code beside the list is
				// not where a nil slice reaches the client.
				if !responded[i] && !isBasicType(params.At(i).Type()) && carriesParam(payload, params.At(i), fn, decls) {
					responded[i] = true
				}
			}
		}
		return true
	})
	var indexes []int
	for i, ok := range responded {
		if ok {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

func isBasicType(t types.Type) bool {
	_, ok := t.Underlying().(*types.Basic)
	return ok
}

// mayHoldList reports a field type a list can be stored as: a slice, a type
// parameter, an interface, or a pointer (dataPtr(data) into Data *T).
func mayHoldList(t types.Type) bool {
	if _, ok := t.(*types.TypeParam); ok {
		return true
	}
	switch t.Underlying().(type) {
	case *types.Slice, *types.Interface, *types.Pointer:
		return true
	}
	return false
}

// paramCarrier follows a parameter of a function into an expression of its
// body, through the locals the body assigns.
type paramCarrier struct {
	fn    patternkit.TypedFunc
	decls map[*types.Func]patternkit.TypedFuncDecl
	param *types.Var
	seen  map[types.Object]bool
}

// carriesParam reports a payload that encodes the parameter's value as it
// is: the parameter, its address, a call of a loaded helper that returns
// its argument or the argument's address (dataPtr(data)), a local assigned
// one of these, a value of a map literal, or a field of a struct literal -
// keyed or positional - holding one of these. A helper that returns
// anything else may replace nil (nonNil(data) returns []T{} for nil) and is
// a value of its own. A field tagged json:"-" is not encoded, and a slice
// or type parameter field tagged omitempty is left out when nil, so neither
// carries a null; a pointer or an interface holding the slice is not empty,
// so an omitempty field of that type still does.
func carriesParam(expr ast.Expr, param *types.Var, fn patternkit.TypedFunc, decls map[*types.Func]patternkit.TypedFuncDecl) bool {
	c := paramCarrier{fn: fn, decls: decls, param: param, seen: make(map[types.Object]bool)}
	return c.carries(expr)
}

func (c paramCarrier) carries(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return c.carriesLocal(e)
	case *ast.UnaryExpr:
		return e.Op == token.AND && c.carries(e.X)
	case *ast.CallExpr:
		return c.carriesThroughCall(e)
	case *ast.CompositeLit:
		return c.carriesLiteral(e)
	}
	return false
}

// carriesLocal reports the parameter itself or a local of the function some
// assignment of which carries it: response := Response[T]{Data: &data}.
func (c paramCarrier) carriesLocal(id *ast.Ident) bool {
	obj := c.fn.Info.Uses[id]
	if obj == c.param {
		return true
	}
	v, ok := obj.(*types.Var)
	if !ok || v.IsField() || c.seen[obj] || v.Pos() < c.fn.Decl.Body.Pos() || v.Pos() >= c.fn.Decl.Body.End() {
		return false
	}
	c.seen[obj] = true
	carried := false
	ast.Inspect(c.fn.Decl.Body, func(n ast.Node) bool {
		if carried {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if name, ok := lhs.(*ast.Ident); ok && c.names(name, obj) && c.carries(node.Rhs[i]) {
					carried = true
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if i < len(node.Values) && c.fn.Info.Defs[name] == obj && c.carries(node.Values[i]) {
					carried = true
				}
			}
		}
		return true
	})
	return carried
}

func (c paramCarrier) names(id *ast.Ident, obj types.Object) bool {
	return c.fn.Info.Defs[id] == obj || c.fn.Info.Uses[id] == obj
}

// carriesThroughCall reports a call of a loaded helper whose every return
// is its parameter or that parameter's address, called with the carried
// value: dataPtr(data).
func (c paramCarrier) carriesThroughCall(call *ast.CallExpr) bool {
	fn, ok := typeutil.Callee(c.fn.Info, call).(*types.Func)
	if !ok {
		return false
	}
	callee, ok := c.decls[fn.Origin()]
	if !ok {
		return false
	}
	params := fn.Origin().Signature().Params()
	for i, arg := range call.Args {
		if i < params.Len() && c.carries(arg) {
			return returnsOnlyParam(callee, params.At(i))
		}
	}
	return false
}

// returnsOnlyParam reports a function every return of which is the
// parameter or its address: the value comes out nil when it goes in nil.
func returnsOnlyParam(fn patternkit.TypedFuncDecl, param *types.Var) bool {
	returns := 0
	only := true
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) != 1 {
				only = false
				return false
			}
			returns++
			result := ast.Unparen(node.Results[0])
			if unary, ok := result.(*ast.UnaryExpr); ok && unary.Op == token.AND {
				result = ast.Unparen(unary.X)
			}
			if id, ok := result.(*ast.Ident); !ok || fn.Info.Uses[id] != param {
				only = false
			}
		}
		return only
	})
	return only && returns > 0
}

// carriesLiteral reports a map literal with a value carrying the parameter,
// or a struct literal with a JSON list field carrying it.
func (c paramCarrier) carriesLiteral(lit *ast.CompositeLit) bool {
	typ := c.fn.Info.TypeOf(lit)
	if typ == nil {
		return false
	}
	if _, ok := typ.Underlying().(*types.Map); ok {
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok && c.carries(kv.Value) {
				return true
			}
		}
		return false
	}
	st, ok := pointedStruct(typ)
	if !ok {
		return false
	}
	for i, elt := range lit.Elts {
		field, value := "", elt
		if kv, keyed := elt.(*ast.KeyValueExpr); keyed {
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			field, value = key.Name, kv.Value
		} else if i < st.NumFields() {
			// Response[T]{true, dataPtr(data)} sets the fields in order.
			field = st.Field(i).Name()
		} else {
			continue
		}
		if _, listed := listJSONField(st, field); listed && c.carries(value) {
			return true
		}
	}
	return false
}

// responderPayloads returns the arguments a call passes as the JSON payload
// of a responder, nil for any other call.
func responderPayloads(call *ast.CallExpr, info *types.Info, responders map[*types.Func][]int) []ast.Expr {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok {
		return nil
	}
	var payloads []ast.Expr
	for _, i := range responders[fn.Origin()] {
		if i < len(call.Args) {
			payloads = append(payloads, call.Args[i])
		}
	}
	return payloads
}

// appendOnlyField is a JSON list field of a local response value that only
// appends inside a loop fill.
type appendOnlyField struct {
	owner *ast.Ident
	json  string
}

// responseLocal is a local built from a JSON struct literal, with the
// fields the function sets other than by append in a loop.
type responseLocal struct {
	owner    *ast.Ident
	st       *types.Struct
	set      map[string]bool
	appended map[string]bool
	reaches  bool
	escaped  bool
}

// appendOnlyFields returns the locals of a function built as a JSON struct
// without a list field, that field then only appended to inside a loop, and
// the local encoded or passed to a JSON responder.
func appendOnlyFields(fn patternkit.TypedFunc, responders map[*types.Func][]int) []appendOnlyField {
	locals := responseLocals(fn)
	if len(locals) == 0 {
		return nil
	}
	w := responseLocalWalker{fn: fn, responders: responders, locals: locals}
	w.visit(fn.Decl.Body, false)
	var fields []appendOnlyField
	for _, local := range locals {
		if !local.reaches || local.escaped {
			continue
		}
		for _, name := range patternkit.SortedKeys(local.appended) {
			if tag, ok := listJSONField(local.st, name); ok && !local.set[name] {
				fields = append(fields, appendOnlyField{owner: local.owner, json: tag})
				break
			}
		}
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].owner.Pos() < fields[j].owner.Pos() })
	return fields
}

// responseLocals returns the locals a function defines from a literal of a
// JSON struct, with the fields the literal sets.
func responseLocals(fn patternkit.TypedFunc) map[types.Object]*responseLocal {
	locals := make(map[types.Object]*responseLocal)
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		lit, isLit := ast.Unparen(assign.Rhs[0]).(*ast.CompositeLit)
		id, isIdent := assign.Lhs[0].(*ast.Ident)
		if !isLit || !isIdent || fn.Info.Defs[id] == nil {
			return true
		}
		st, ok := fn.Info.TypeOf(lit).Underlying().(*types.Struct)
		if !ok || !isJSONStruct(st) {
			return true
		}
		local := &responseLocal{owner: id, st: st, set: make(map[string]bool), appended: make(map[string]bool)}
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok {
					local.set[key.Name] = true
				}
			}
		}
		locals[fn.Info.Defs[id]] = local
		return true
	})
	return locals
}

// responseLocalWalker records what a function does with its response
// locals: fields appended in loops or set otherwise, the address taken, the
// value encoded.
type responseLocalWalker struct {
	fn         patternkit.TypedFunc
	responders map[*types.Func][]int
	locals     map[types.Object]*responseLocal
}

func (w responseLocalWalker) local(expr ast.Expr) (*responseLocal, types.Object) {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil, nil
	}
	obj := w.fn.Info.Uses[id]
	return w.locals[obj], obj
}

func (w responseLocalWalker) visit(root ast.Node, inLoop bool) {
	ast.Inspect(root, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ForStmt:
			if x == root {
				return true
			}
			w.visit(x.Body, true)
			return false
		case *ast.RangeStmt:
			if x == root {
				return true
			}
			w.visit(x.Body, true)
			return false
		case *ast.AssignStmt:
			w.assign(x, inLoop)
		case *ast.UnaryExpr:
			if local, _ := w.local(x.X); local != nil && x.Op == token.AND {
				local.escaped = true
			}
		case *ast.CallExpr:
			for _, payload := range w.payloads(x) {
				if local, _ := w.local(payload); local != nil {
					local.reaches = true
				}
			}
		}
		return true
	})
}

// assign records a write to a field of a response local.
func (w responseLocalWalker) assign(stmt *ast.AssignStmt, inLoop bool) {
	for i, lhs := range stmt.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		local, obj := w.local(sel.X)
		if local == nil {
			continue
		}
		if inLoop && len(stmt.Lhs) == len(stmt.Rhs) && appendsToField(stmt.Rhs[i], obj, sel.Sel.Name, w.fn.Info) {
			local.appended[sel.Sel.Name] = true
		} else {
			local.set[sel.Sel.Name] = true
		}
	}
}

// payloads returns what a call writes to the client as JSON: the payloads
// of a responder, or the value a handler encodes; nil for any other call.
func (w responseLocalWalker) payloads(call *ast.CallExpr) []ast.Expr {
	if jsonEncodeCall(call, w.fn.Info) && len(call.Args) > 0 && patternkit.HasResponseWriterParam(w.fn.Decl.Type.Params) {
		return call.Args[:1]
	}
	return responderPayloads(call, w.fn.Info, w.responders)
}

// appendsToField reports v.F = append(v.F, ...).
func appendsToField(expr ast.Expr, owner types.Object, field string, info *types.Info) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) < 2 {
		return false
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "append" {
		return false
	}
	sel, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != field {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && info.Uses[id] == owner
}

// isJSONStruct reports a struct some field of which a json tag names: a
// type written as JSON, where an untagged exported field is encoded too. A
// type whose tags only hide fields (json:"-") is a configuration kept out
// of logs, not a payload.
func isJSONStruct(st *types.Struct) bool {
	for i := range st.NumFields() {
		if tag, ok := reflect.StructTag(st.Tag(i)).Lookup("json"); ok && tag != "-" {
			return true
		}
	}
	return false
}

// nilSliceFuncs returns the functions and interface methods whose slice
// result may be a nil slice on success, with the declaration it comes from.
func nilSliceFuncs(funcs []patternkit.TypedFunc, interfaces []*types.TypeName) map[*types.Func]nilSliceSource {
	sources := make(map[*types.Func]nilSliceSource)
	for changed := true; changed; {
		changed = false
		for _, fn := range funcs {
			obj, ok := fn.Info.Defs[fn.Decl.Name].(*types.Func)
			if !ok {
				continue
			}
			if _, done := sources[obj]; done {
				continue
			}
			if src, ok := returnedNilSlice(fn, sources); ok {
				sources[obj] = src
				for _, method := range patternkit.ImplementedMethods(obj, interfaces) {
					if _, done := sources[method]; !done {
						sources[method] = src
					}
				}
				changed = true
			}
		}
	}
	return sources
}

// sliceResult reports whether a signature returns a slice, alone or with an
// error.
func sliceResult(sig *types.Signature) bool {
	results := sig.Results()
	switch results.Len() {
	case 1:
	case 2:
		if !patternkit.IsErrorType(results.At(1).Type()) {
			return false
		}
	default:
		return false
	}
	_, ok := results.At(0).Type().Underlying().(*types.Slice)
	return ok
}

// returnedNilSlice finds a successful return of the function whose slice is
// a nil slice declaration the function never replaces, or the result of a
// call that may return one.
func returnedNilSlice(fn patternkit.TypedFunc, sources map[*types.Func]nilSliceSource) (nilSliceSource, bool) {
	obj, ok := fn.Info.Defs[fn.Decl.Name].(*types.Func)
	if !ok {
		return nilSliceSource{}, false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || !sliceResult(sig) {
		return nilSliceSource{}, false
	}
	locals := nilSliceLocals(fn, sources)
	var found nilSliceSource
	ok = false
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		if ok {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if src, hit := successfulNilReturn(node, sig, fn, locals, sources); hit {
				found, ok = src, true
			}
		}
		return true
	})
	return found, ok
}

// successfulNilReturn reports a return whose error is nil and whose slice
// may be nil.
func successfulNilReturn(ret *ast.ReturnStmt, sig *types.Signature, fn patternkit.TypedFunc, locals map[types.Object]nilSliceSource, sources map[*types.Func]nilSliceSource) (nilSliceSource, bool) {
	switch len(ret.Results) {
	case 1:
		// return f(...) passes on the results of a call with the same shape.
		if call, ok := ast.Unparen(ret.Results[0]).(*ast.CallExpr); ok && sig.Results().Len() == 2 {
			return sourceOfCall(call, fn.Info, sources)
		}
	case 2:
		// return out, rows.Err() succeeds when the error is nil; an error
		// built on the spot is a failure path.
		if constructsError(ret.Results[1], fn.Info) {
			return nilSliceSource{}, false
		}
	default:
		return nilSliceSource{}, false
	}
	return sourceOfExpr(ret.Results[0], fn.Info, locals, sources)
}

// sourceOfExpr returns the nil slice an expression may carry: a tracked
// local or a call that may return one.
func sourceOfExpr(expr ast.Expr, info *types.Info, locals map[types.Object]nilSliceSource, sources map[*types.Func]nilSliceSource) (nilSliceSource, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		src, ok := locals[info.Uses[e]]
		return src, ok
	case *ast.CallExpr:
		return sourceOfCall(e, info, sources)
	}
	return nilSliceSource{}, false
}

func sourceOfCall(call *ast.CallExpr, info *types.Info, sources map[*types.Func]nilSliceSource) (nilSliceSource, bool) {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok {
		return nilSliceSource{}, false
	}
	src, ok := sources[fn.Origin()]
	return src, ok
}

// nilSliceLocals returns the locals of a function that may hold a nil slice
// when it returns: declared without a value (var out []T) or assigned once
// from a call that may return one, then only appended to or filled by a
// Select call, and never tested - a test is where code replaces nil.
func nilSliceLocals(fn patternkit.TypedFunc, sources map[*types.Func]nilSliceSource) map[types.Object]nilSliceSource {
	candidates := make(map[types.Object]nilSliceSource)
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ValueSpec:
			if len(node.Values) != 0 {
				return true
			}
			for _, name := range node.Names {
				if obj := fn.Info.Defs[name]; obj != nil && isSliceType(obj.Type()) {
					candidates[obj] = nilSliceSource{file: fn.File, name: name}
				}
			}
		case *ast.AssignStmt:
			if node.Tok != token.DEFINE || len(node.Rhs) != 1 {
				return true
			}
			call, ok := ast.Unparen(node.Rhs[0]).(*ast.CallExpr)
			if !ok || len(node.Lhs) == 0 {
				return true
			}
			src, ok := sourceOfCall(call, fn.Info, sources)
			if !ok {
				return true
			}
			if id, ok := node.Lhs[0].(*ast.Ident); ok {
				if obj := fn.Info.Defs[id]; obj != nil {
					candidates[obj] = src
				}
			}
		}
		return true
	})
	if len(candidates) == 0 {
		return candidates
	}
	for obj := range replacedLocals(fn, candidates) {
		delete(candidates, obj)
	}
	// An element appended by a statement of the function's own body is
	// always there: the slice is not nil past it.
	for _, stmt := range fn.Decl.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 2 {
			continue
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && appendsTo(call, fn.Info.Uses[id], fn.Info) {
			delete(candidates, fn.Info.Uses[id])
		}
	}
	return candidates
}

func isSliceType(t types.Type) bool {
	_, ok := t.Underlying().(*types.Slice)
	return ok
}

// replacedLocals returns the candidates the function may replace with a
// non-nil value: assigned other than by append to itself, taken by address
// for anything but a Select call, or named in a condition.
func replacedLocals(fn patternkit.TypedFunc, candidates map[types.Object]nilSliceSource) map[types.Object]bool {
	replaced := make(map[types.Object]bool)
	use := func(expr ast.Expr) types.Object {
		id, ok := ast.Unparen(expr).(*ast.Ident)
		if !ok {
			return nil
		}
		obj := fn.Info.Uses[id]
		if _, tracked := candidates[obj]; !tracked {
			return nil
		}
		return obj
	}
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				obj := use(lhs)
				if obj == nil {
					continue
				}
				if len(node.Lhs) != len(node.Rhs) || !appendsTo(node.Rhs[i], obj, fn.Info) {
					replaced[obj] = true
				}
			}
		case *ast.RangeStmt:
			if obj := use(node.Key); obj != nil {
				replaced[obj] = true
			}
			if node.Value != nil {
				if obj := use(node.Value); obj != nil {
					replaced[obj] = true
				}
			}
		case *ast.CallExpr:
			for _, arg := range node.Args {
				unary, ok := ast.Unparen(arg).(*ast.UnaryExpr)
				if !ok || unary.Op != token.AND {
					continue
				}
				if obj := use(unary.X); obj != nil && !selectCall(node) {
					replaced[obj] = true
				}
			}
		case *ast.IfStmt:
			markMentioned(node.Cond, fn.Info, candidates, replaced)
		case *ast.SwitchStmt:
			if node.Tag != nil {
				markMentioned(node.Tag, fn.Info, candidates, replaced)
			}
		case *ast.CaseClause:
			for _, expr := range node.List {
				markMentioned(expr, fn.Info, candidates, replaced)
			}
		}
		return true
	})
	return replaced
}

func markMentioned(expr ast.Expr, info *types.Info, candidates map[types.Object]nilSliceSource, marked map[types.Object]bool) {
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if obj := info.Uses[id]; obj != nil {
				if _, tracked := candidates[obj]; tracked {
					marked[obj] = true
				}
			}
		}
		return true
	})
}

// appendsTo reports x = append(x, ...).
func appendsTo(expr ast.Expr, obj types.Object, info *types.Info) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	if builtin, ok := typeutil.Callee(info, call).(*types.Builtin); !ok || builtin.Name() != "append" {
		return false
	}
	id, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
	return ok && info.Uses[id] == obj
}

// selectCall reports a call filling a slice from rows (sqlx Select,
// SelectContext): with no rows it leaves the slice nil.
func selectCall(call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && strings.HasPrefix(sel.Sel.Name, "Select")
}

// nilSliceSink is a place a possibly nil slice is encoded to JSON.
type nilSliceSink struct {
	source nilSliceSource
	node   ast.Node
	what   string
}

// nilSliceSinks returns the places a function puts a possibly nil slice into
// JSON: a tagged field without omitempty, a key of a map an HTTP handler
// builds, or the argument of json.Marshal or Encode.
func nilSliceSinks(fn patternkit.TypedFunc, sources map[*types.Func]nilSliceSource, responders map[*types.Func][]int) []nilSliceSink {
	locals := nilSliceLocals(fn, sources)
	handler := patternkit.HasResponseWriterParam(fn.Decl.Type.Params)
	var sinks []nilSliceSink
	add := func(expr ast.Expr, node ast.Node, what string) {
		if src, ok := sourceOfExpr(expr, fn.Info, locals, sources); ok {
			sinks = append(sinks, nilSliceSink{source: src, node: node, what: what})
		}
	}
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CompositeLit:
			switch typ := fn.Info.TypeOf(node).Underlying().(type) {
			case *types.Struct:
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok {
						if name, ok := listJSONField(typ, key.Name); ok {
							add(kv.Value, kv, `JSON field "`+name+`"`)
						}
					}
				}
			case *types.Map:
				if !handler || !types.IsInterface(typ.Elem()) {
					return true
				}
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.BasicLit); ok && key.Kind == token.STRING {
						add(kv.Value, kv, "response key "+key.Value)
					}
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				st, ok := pointedStruct(fn.Info.TypeOf(sel.X))
				if !ok {
					continue
				}
				if name, ok := listJSONField(st, sel.Sel.Name); ok {
					add(node.Rhs[i], node, `JSON field "`+name+`"`)
				}
			}
		case *ast.CallExpr:
			// Marshalled elsewhere the bytes may only be measured or
			// stored; a handler writes them to its client.
			if handler && jsonEncodeCall(node, fn.Info) && len(node.Args) > 0 {
				add(node.Args[0], node, "json encoding")
			}
			for _, payload := range responderPayloads(node, fn.Info, responders) {
				add(payload, node, "the JSON response")
			}
		}
		return true
	})
	return sinks
}

func pointedStruct(t types.Type) (*types.Struct, bool) {
	if t == nil {
		return nil, false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}

// listJSONField returns the JSON name of a field a list can be stored in
// that is written when the list is nil: tagged without omitempty, or a
// pointer or interface holding the list, which omitempty does not drop.
func listJSONField(st *types.Struct, field string) (string, bool) {
	for i := range st.NumFields() {
		f := st.Field(i)
		if f.Name() != field || !mayHoldList(f.Type()) {
			continue
		}
		tag, ok := reflect.StructTag(st.Tag(i)).Lookup("json")
		if !ok {
			// An untagged exported field of a JSON type is encoded under
			// its Go name.
			if f.Exported() && !f.Anonymous() && isJSONStruct(st) {
				return f.Name(), true
			}
			return "", false
		}
		parts := strings.Split(tag, ",")
		if parts[0] == "-" {
			return "", false
		}
		for _, opt := range parts[1:] {
			if (opt == "omitempty" || opt == "omitzero") && !holdsListBeyondOmitEmpty(f.Type()) {
				return "", false
			}
		}
		name := parts[0]
		if name == "" {
			name = f.Name()
		}
		return name, true
	}
	return "", false
}

// holdsListBeyondOmitEmpty reports a field type omitempty and omitzero keep
// when it holds a nil list: a non-nil pointer or interface around it is not
// empty. A type parameter field is the list itself and is dropped.
func holdsListBeyondOmitEmpty(t types.Type) bool {
	if _, ok := t.(*types.TypeParam); ok {
		return false
	}
	switch t.Underlying().(type) {
	case *types.Interface, *types.Pointer:
		return true
	}
	return false
}

// jsonEncodeCall reports json.Marshal, json.MarshalIndent or
// (*json.Encoder).Encode.
func jsonEncodeCall(call *ast.CallExpr, info *types.Info) bool {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "encoding/json" && slices.Contains(helpers.EncodeFuncs, fn.Name())
}

// constructsError reports an error made at the return: fmt.Errorf,
// errors.New, a composite error value or a package-level sentinel.
func constructsError(expr ast.Expr, info *types.Info) bool {
	var id *ast.Ident
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		fn, ok := typeutil.Callee(info, e).(*types.Func)
		return ok && fn.Pkg() != nil && (fn.Pkg().Path() == "fmt" || fn.Pkg().Path() == "errors")
	case *ast.UnaryExpr, *ast.CompositeLit:
		return true
	case *ast.Ident:
		id = e
	case *ast.SelectorExpr:
		id = e.Sel
	default:
		return false
	}
	v, ok := info.Uses[id].(*types.Var)
	return ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope()
}
