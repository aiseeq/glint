package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
// written by an HTTP handler, or json.Marshal.
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

// typedFunc is a function declaration with the types of its package.
type typedFunc struct {
	file *core.FileContext
	info *types.Info
	decl *ast.FuncDecl
}

// AnalyzeGoProject reports the nil slice declarations whose value reaches JSON.
func (r *NilSliceJSONNullRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	funcs := projectFuncDecls(ctx)
	sources := nilSliceFuncs(funcs, projectInterfaces(ctx))
	responders := jsonResponders(funcs)

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
				src.name.Name, sink.what, fn.file.RelPath, fn.file.LineFor(sink.node)))
			v.WithCode(strings.TrimSpace(src.file.GetLine(line)))
			v.WithSuggestion(fmt.Sprintf("Start with an empty slice: %s := make(T, 0), or replace nil before encoding", src.name.Name))
			violations = append(violations, v)
		}
		for _, field := range appendOnlyFields(fn, responders) {
			line := fn.file.LineFor(field.owner)
			if reported[field.owner] || fn.file.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[field.owner] = true
			v := r.CreateViolation(fn.file.RelPath, line, fmt.Sprintf(
				"Field %s of %s is filled only by append in a loop and %s reaches a JSON response — with nothing to add it stays nil, encoding/json writes null, and a client expecting a list breaks",
				field.json, field.owner.Name, field.owner.Name))
			v.WithCode(strings.TrimSpace(fn.file.GetLine(line)))
			v.WithSuggestion("Set the field to an empty slice where the value is built")
			violations = append(violations, v)
		}
	}
	return violations, nil
}

// jsonResponders returns the functions that write one of their parameters
// to an http.ResponseWriter as JSON, with the index of that parameter:
// respondJSON(w, status, payload).
func jsonResponders(funcs []typedFunc) map[*types.Func]int {
	responders := make(map[*types.Func]int)
	for _, fn := range funcs {
		obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
		if !ok || !hasResponseWriterParam(fn.decl.Type.Params) {
			continue
		}
		params := obj.Signature().Params()
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !jsonEncodeCall(call, fn.info) || len(call.Args) == 0 {
				return true
			}
			id, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
			if !ok {
				return true
			}
			for i := range params.Len() {
				if params.At(i) == fn.info.Uses[id] {
					responders[obj] = i
				}
			}
			return true
		})
	}
	return responders
}

// responderPayload returns the argument a call passes as the JSON payload
// of a responder, nil for any other call.
func responderPayload(call *ast.CallExpr, info *types.Info, responders map[*types.Func]int) ast.Expr {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok {
		return nil
	}
	if i, ok := responders[fn]; ok && i < len(call.Args) {
		return call.Args[i]
	}
	return nil
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
func appendOnlyFields(fn typedFunc, responders map[*types.Func]int) []appendOnlyField {
	locals := responseLocals(fn)
	if len(locals) == 0 {
		return nil
	}
	w := responseLocalWalker{fn: fn, responders: responders, locals: locals}
	w.visit(fn.decl.Body, false)
	var fields []appendOnlyField
	for _, local := range locals {
		if !local.reaches || local.escaped {
			continue
		}
		for _, name := range sortedKeys(local.appended) {
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
func responseLocals(fn typedFunc) map[types.Object]*responseLocal {
	locals := make(map[types.Object]*responseLocal)
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		lit, isLit := ast.Unparen(assign.Rhs[0]).(*ast.CompositeLit)
		id, isIdent := assign.Lhs[0].(*ast.Ident)
		if !isLit || !isIdent || fn.info.Defs[id] == nil {
			return true
		}
		st, ok := fn.info.TypeOf(lit).Underlying().(*types.Struct)
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
		locals[fn.info.Defs[id]] = local
		return true
	})
	return locals
}

// responseLocalWalker records what a function does with its response
// locals: fields appended in loops or set otherwise, the address taken, the
// value encoded.
type responseLocalWalker struct {
	fn         typedFunc
	responders map[*types.Func]int
	locals     map[types.Object]*responseLocal
}

func (w responseLocalWalker) local(expr ast.Expr) (*responseLocal, types.Object) {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil, nil
	}
	obj := w.fn.info.Uses[id]
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
			if local, _ := w.local(w.payload(x)); local != nil {
				local.reaches = true
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
		if inLoop && len(stmt.Lhs) == len(stmt.Rhs) && appendsToField(stmt.Rhs[i], obj, sel.Sel.Name, w.fn.info) {
			local.appended[sel.Sel.Name] = true
		} else {
			local.set[sel.Sel.Name] = true
		}
	}
}

// payload returns what a call writes to the client as JSON: the payload of
// a responder, or the value a handler encodes; nil for any other call.
func (w responseLocalWalker) payload(call *ast.CallExpr) ast.Expr {
	if payload := responderPayload(call, w.fn.info, w.responders); payload != nil {
		return payload
	}
	if jsonEncodeCall(call, w.fn.info) && len(call.Args) > 0 && hasResponseWriterParam(w.fn.decl.Type.Params) {
		return call.Args[0]
	}
	return nil
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

// projectFuncDecls returns the function declarations of the analyzed
// production files.
func projectFuncDecls(ctx *core.GoProjectContext) []typedFunc {
	var funcs []typedFunc
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			for _, decl := range file.GoAST.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
					funcs = append(funcs, typedFunc{file: file, info: pkg.Package.TypesInfo, decl: fn})
				}
			}
		}
	}
	return funcs
}

// nilSliceFuncs returns the functions and interface methods whose slice
// result may be a nil slice on success, with the declaration it comes from.
func nilSliceFuncs(funcs []typedFunc, interfaces []*types.TypeName) map[*types.Func]nilSliceSource {
	sources := make(map[*types.Func]nilSliceSource)
	for changed := true; changed; {
		changed = false
		for _, fn := range funcs {
			obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
			if !ok {
				continue
			}
			if _, done := sources[obj]; done {
				continue
			}
			if src, ok := returnedNilSlice(fn, sources); ok {
				sources[obj] = src
				for _, method := range implementedMethods(obj, interfaces) {
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

// implementedMethods returns the methods of project interfaces a method
// implements.
func implementedMethods(method *types.Func, interfaces []*types.TypeName) []*types.Func {
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	recv := sig.Recv().Type()
	var found []*types.Func
	for _, typeName := range interfaces {
		iface, ok := typeName.Type().Underlying().(*types.Interface)
		if !ok || !types.Implements(recv, iface) {
			continue
		}
		for i := range iface.NumMethods() {
			if m := iface.Method(i); m.Name() == method.Name() {
				found = append(found, m)
			}
		}
	}
	return found
}

// sliceResult reports whether a signature returns a slice, alone or with an
// error.
func sliceResult(sig *types.Signature) bool {
	results := sig.Results()
	switch results.Len() {
	case 1:
	case 2:
		if !isErrorType(results.At(1).Type()) {
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
func returnedNilSlice(fn typedFunc, sources map[*types.Func]nilSliceSource) (nilSliceSource, bool) {
	obj, ok := fn.info.Defs[fn.decl.Name].(*types.Func)
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
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
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
func successfulNilReturn(ret *ast.ReturnStmt, sig *types.Signature, fn typedFunc, locals map[types.Object]nilSliceSource, sources map[*types.Func]nilSliceSource) (nilSliceSource, bool) {
	switch len(ret.Results) {
	case 1:
		// return f(...) passes on the results of a call with the same shape.
		if call, ok := ast.Unparen(ret.Results[0]).(*ast.CallExpr); ok && sig.Results().Len() == 2 {
			return sourceOfCall(call, fn.info, sources)
		}
	case 2:
		// return out, rows.Err() succeeds when the error is nil; an error
		// built on the spot is a failure path.
		if constructsError(ret.Results[1], fn.info) {
			return nilSliceSource{}, false
		}
	default:
		return nilSliceSource{}, false
	}
	return sourceOfExpr(ret.Results[0], fn.info, locals, sources)
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
func nilSliceLocals(fn typedFunc, sources map[*types.Func]nilSliceSource) map[types.Object]nilSliceSource {
	candidates := make(map[types.Object]nilSliceSource)
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ValueSpec:
			if len(node.Values) != 0 {
				return true
			}
			for _, name := range node.Names {
				if obj := fn.info.Defs[name]; obj != nil && isSliceType(obj.Type()) {
					candidates[obj] = nilSliceSource{file: fn.file, name: name}
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
			src, ok := sourceOfCall(call, fn.info, sources)
			if !ok {
				return true
			}
			if id, ok := node.Lhs[0].(*ast.Ident); ok {
				if obj := fn.info.Defs[id]; obj != nil {
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
	for _, stmt := range fn.decl.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 2 {
			continue
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && appendsTo(call, fn.info.Uses[id], fn.info) {
			delete(candidates, fn.info.Uses[id])
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
func replacedLocals(fn typedFunc, candidates map[types.Object]nilSliceSource) map[types.Object]bool {
	replaced := make(map[types.Object]bool)
	use := func(expr ast.Expr) types.Object {
		id, ok := ast.Unparen(expr).(*ast.Ident)
		if !ok {
			return nil
		}
		obj := fn.info.Uses[id]
		if _, tracked := candidates[obj]; !tracked {
			return nil
		}
		return obj
	}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				obj := use(lhs)
				if obj == nil {
					continue
				}
				if len(node.Lhs) != len(node.Rhs) || !appendsTo(node.Rhs[i], obj, fn.info) {
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
			markMentioned(node.Cond, fn.info, candidates, replaced)
		case *ast.SwitchStmt:
			if node.Tag != nil {
				markMentioned(node.Tag, fn.info, candidates, replaced)
			}
		case *ast.CaseClause:
			for _, expr := range node.List {
				markMentioned(expr, fn.info, candidates, replaced)
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
func nilSliceSinks(fn typedFunc, sources map[*types.Func]nilSliceSource, responders map[*types.Func]int) []nilSliceSink {
	locals := nilSliceLocals(fn, sources)
	handler := hasResponseWriterParam(fn.decl.Type.Params)
	var sinks []nilSliceSink
	add := func(expr ast.Expr, node ast.Node, what string) {
		if src, ok := sourceOfExpr(expr, fn.info, locals, sources); ok {
			sinks = append(sinks, nilSliceSink{source: src, node: node, what: what})
		}
	}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CompositeLit:
			switch typ := fn.info.TypeOf(node).Underlying().(type) {
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
				st, ok := pointedStruct(fn.info.TypeOf(sel.X))
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
			if handler && jsonEncodeCall(node, fn.info) && len(node.Args) > 0 {
				add(node.Args[0], node, "json encoding")
			}
			if payload := responderPayload(node, fn.info, responders); payload != nil {
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

// listJSONField returns the JSON name of a slice field tagged without
// omitempty.
func listJSONField(st *types.Struct, field string) (string, bool) {
	for i := range st.NumFields() {
		f := st.Field(i)
		if f.Name() != field || !isSliceType(f.Type()) {
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
			if opt == "omitempty" || opt == "omitzero" {
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
