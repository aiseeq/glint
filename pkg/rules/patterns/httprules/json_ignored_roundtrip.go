package httprules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewJSONIgnoredFieldLostInRoundTripRule())
}

// JSONIgnoredFieldLostInRoundTripRule detects a field left out of JSON on a
// type the code stores as JSON and reads back:
//
//	type Holding struct {
//		Key       string `json:"key"`
//		LegacyKey string `json:"-"`            // set by the builder
//	}
//	raw, _ := json.Marshal(holdings)              // saved in a snapshot
//	json.Unmarshal(row.Holdings, &holdings)       // read back by another job
//	if h.LegacyKey != "" { migrate(h) }           // never true on that path
//
// The value the builder sets lives only in memory: code reading the type
// back from storage always sees the zero value, and what depends on it never
// happens there.
//
// A decode into a local variable of which the function reads only fields JSON
// carries proves no such reading: no one sees the ignored field of it.
type JSONIgnoredFieldLostInRoundTripRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
	// projectAnalysis is a per-instance seam for observing the post-precheck path.
	projectAnalysis func(*core.GoProjectContext) ([]*core.Violation, error)
}

// NewJSONIgnoredFieldLostInRoundTripRule creates the rule
func NewJSONIgnoredFieldLostInRoundTripRule() *JSONIgnoredFieldLostInRoundTripRule {
	return &JSONIgnoredFieldLostInRoundTripRule{BaseRule: rules.NewBaseRule(
		"json-ignored-field-lost-in-roundtrip",
		"patterns",
		"Detects a json:\"-\" field set and read on a type the code both marshals and unmarshals — the value never survives storage, and readers of the stored copy see zero",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the check needs every package's types.
func (r *JSONIgnoredFieldLostInRoundTripRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *JSONIgnoredFieldLostInRoundTripRule) RequiresSSA() bool { return false }

// jsonRoundTrip is what the project does with JSON and the ignored fields.
type jsonRoundTrip struct {
	marshalled, unmarshalled map[*types.TypeName]bool
	// written and read are the ignored fields assigned and read; refilled
	// are those a function decoding their type assigns itself.
	written, read, refilled map[*types.Var]bool
	// owners maps, per package, each field of a package-level struct type to
	// the type declaring it, built on the first field of the package asked.
	owners map[*types.Package]map[*types.Var]*types.TypeName
	// whole and partialRead are what readBack went through: from the decodes
	// read whole, and the types of those read by their JSON fields alone.
	whole       jsonReading
	partialRead map[*types.Named]bool
	selfDecoded map[*types.Named]bool
	ignoring    jsonIgnoring
}

// owner returns the named struct type that declares the field.
func (t *jsonRoundTrip) owner(v *types.Var) *types.TypeName {
	if v.Pkg() == nil {
		return nil
	}
	owners, ok := t.owners[v.Pkg()]
	if !ok {
		owners = fieldOwners(v.Pkg())
		t.owners[v.Pkg()] = owners
	}
	return owners[v]
}

// AnalyzeGoProject reports the ignored fields lost by the round trip.
func (r *JSONIgnoredFieldLostInRoundTripRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	if !projectHasIgnoredJSONField(ctx) {
		return nil, nil
	}
	if r.projectAnalysis != nil {
		return r.projectAnalysis(ctx)
	}
	trip := jsonRoundTrip{
		marshalled: map[*types.TypeName]bool{}, unmarshalled: map[*types.TypeName]bool{},
		written: map[*types.Var]bool{}, read: map[*types.Var]bool{}, refilled: map[*types.Var]bool{},
		owners: map[*types.Package]map[*types.Var]*types.TypeName{},
		whole:  jsonReading{depths: map[*types.Named]int{}}, partialRead: map[*types.Named]bool{}, selfDecoded: map[*types.Named]bool{},
		ignoring: jsonIgnoring{known: map[types.Type]bool{}, at: map[types.Type]int{}},
	}
	eachProductionGoFile(ctx, trip.collect)
	return trip.analyzeStructs(ctx, r.Name(), func(file *core.FileContext, info *types.Info, name *types.TypeName, st *ast.StructType) []*core.Violation {
		var violations []*core.Violation
		for _, field := range st.Fields.List {
			if field.Tag == nil || len(field.Names) == 0 || !jsonIgnored(strings.Trim(field.Tag.Value, "`")) {
				continue
			}
			for _, ident := range field.Names {
				v, ok := info.Defs[ident].(*types.Var)
				if !ok || !trip.written[v] || !trip.read[v] || trip.refilled[v] {
					continue
				}
				line := file.LineFor(ident)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				violation := r.CreateViolation(file.RelPath, line, ident.Name+" is set and read, but json:\"-\" leaves it out of the JSON "+name.Name()+
					" is stored as and read back from — code reading the stored copy always sees the zero value")
				violation.WithCode(strings.TrimSpace(file.GetLine(line)))
				violation.WithSuggestion("Give the field a JSON name (omitempty if it may be empty), or recompute it where the stored copy is read")
				violations = append(violations, violation)
			}
		}
		return violations
	})
}

func projectHasIgnoredJSONField(ctx *core.GoProjectContext) bool {
	if ctx == nil {
		return false
	}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil {
			continue
		}
		if pkgCtx.Package.Fset == nil {
			return true
		}
		for _, file := range pkgCtx.Package.Syntax {
			if strings.HasSuffix(pkgCtx.Package.Fset.Position(file.Pos()).Filename, "_test.go") {
				continue
			}
			found := false
			ast.Inspect(file, func(node ast.Node) bool {
				st, ok := node.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					if field.Tag != nil && len(field.Names) > 0 && jsonIgnored(strings.Trim(field.Tag.Value, "`")) {
						found = true
						return false
					}
				}
				return !found
			})
			if found {
				return true
			}
		}
	}
	return false
}

// eachProductionGoFile calls visit with every typed file of the project that
// is not a test.
func eachProductionGoFile(ctx *core.GoProjectContext, visit func(info *types.Info, file *ast.File)) {
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkgCtx.Package.Syntax {
			if !strings.HasSuffix(pkgCtx.Package.Fset.Position(file.Pos()).Filename, "_test.go") {
				visit(pkgCtx.Package.TypesInfo, file)
			}
		}
	}
}

// analyzeStructs calls check with each struct type declared outside tests
// that the code both marshals and unmarshals as JSON.
func (t *jsonRoundTrip) analyzeStructs(ctx *core.GoProjectContext, rule string,
	check func(file *core.FileContext, info *types.Info, name *types.TypeName, st *ast.StructType) []*core.Violation,
) ([]*core.Violation, error) {
	return rules.AnalyzeTypedRunFiles(ctx, rule, func(file *core.FileContext, info *types.Info) []*core.Violation {
		if !file.HasGoAST() || file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			name, ok := info.Defs[spec.Name].(*types.TypeName)
			if st, isStruct := spec.Type.(*ast.StructType); ok && isStruct && t.marshalled[name] && t.unmarshalled[name] {
				violations = append(violations, check(file, info, name, st)...)
			}
			return true
		})
		return violations
	})
}

// jsonIgnored reports a struct tag that leaves the field out of JSON:
// json:"-" (json:"-," names the key "-").
func jsonIgnored(tag string) bool {
	return reflect.StructTag(tag).Get("json") == "-"
}

// collect records the types a file marshals and unmarshals, and the ignored
// fields it writes and reads.
func (t *jsonRoundTrip) collect(info *types.Info, file *ast.File) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		decoded := map[*types.TypeName]bool{}
		var assigned []*types.Var
		var decodes []ast.Expr
		targets := map[ast.Expr]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				encoded, target := jsonCall(info, node)
				jsonTypes(info.TypeOf(encoded), t.marshalled, 0)
				if target != nil {
					jsonTypes(info.TypeOf(target), decoded, 0)
					decodes = append(decodes, target)
				}
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					targets[ast.Unparen(lhs)] = true
					if v := ignoredField(info, lhs); v != nil {
						t.written[v] = true
						assigned = append(assigned, v)
					}
				}
			case *ast.CompositeLit:
				for _, elt := range node.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if key, ok := kv.Key.(*ast.Ident); ok {
							if v, ok := info.ObjectOf(key).(*types.Var); ok && v.IsField() {
								t.written[v] = true
								assigned = append(assigned, v)
							}
						}
					}
				}
			case *ast.SelectorExpr:
				if v := ignoredField(info, node); v != nil && !targets[node] {
					t.read[v] = true
				}
			}
			return true
		})
		t.readBack(info, fn.Body, decodes)
		for _, v := range assigned {
			if owner := t.owner(v); owner != nil && decoded[owner] {
				t.refilled[v] = true
			}
		}
	}
}

// jsonCall returns what a call of json.Marshal or an encoder encodes, and what
// json.Unmarshal or a decoder decodes into, nil for another call.
func jsonCall(info *types.Info, call *ast.CallExpr) (encoded, decoded ast.Expr) {
	fn := patternkit.StaticFunc(info, call)
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "encoding/json" || len(call.Args) == 0 {
		return nil, nil
	}
	switch fn.Name() {
	case "Marshal", "MarshalIndent", "Encode":
		return call.Args[0], nil
	case "Unmarshal":
		if len(call.Args) == 2 {
			return nil, call.Args[1]
		}
	case "Decode":
		return nil, call.Args[0]
	}
	return nil, nil
}

// maxJSONDepth bounds the steps into a value's JSON its types are followed.
const maxJSONDepth = 4

// jsonNamed returns the named type behind the pointers and the elements of a
// type, and the depth it is at.
func jsonNamed(typ types.Type, depth int) (*types.Named, int) {
	for depth <= maxJSONDepth {
		switch t := typ.(type) {
		case *types.Pointer:
			typ = t.Elem()
		case *types.Slice:
			typ, depth = t.Elem(), depth+1
		case *types.Array:
			typ, depth = t.Elem(), depth+1
		case *types.Map:
			typ, depth = t.Elem(), depth+1
		case *types.Named:
			return t, depth
		default:
			return nil, depth
		}
	}
	return nil, depth
}

// eachJSONField calls visit with the type of each field JSON carries.
func eachJSONField(st *types.Struct, visit func(types.Type)) {
	for i := range st.NumFields() {
		if field := st.Field(i); field.Exported() && !jsonIgnored(st.Tag(i)) {
			visit(field.Type())
		}
	}
}

// jsonTypes records the named struct types a value of type typ carries in
// JSON: itself, its elements, its exported fields, a few levels deep.
func jsonTypes(typ types.Type, seen map[*types.TypeName]bool, depth int) {
	named, depth := jsonNamed(typ, depth)
	if named == nil || seen[named.Obj()] {
		return
	}
	if st, ok := named.Underlying().(*types.Struct); ok {
		seen[named.Obj()] = true
		eachJSONField(st, func(field types.Type) { jsonTypes(field, seen, depth+1) })
	}
}

// jsonReading holds the types gone through from the values decoded, each with
// its least depth, all but except.
type jsonReading struct {
	depths map[*types.Named]int
	except *types.Named
}

// readBack records the types the decodes of a function read: the ones jsonTypes
// names, whatever was recorded before, so that the order of the decodes does
// not matter. A partial decode reads the types of its fields, but not its own.
func (t *jsonRoundTrip) readBack(info *types.Info, body *ast.BlockStmt, decodes []ast.Expr) {
	partial := t.partialDecodes(info, body, decodes)
	for _, target := range decodes {
		named := partial[decodedIdent(target)]
		if named == nil {
			t.markRead(t.whole, info.TypeOf(target), 0)
			continue
		}
		if st, ok := named.Underlying().(*types.Struct); ok && !t.partialRead[named] {
			t.partialRead[named] = true
			fields := jsonReading{depths: map[*types.Named]int{}, except: named}
			eachJSONField(st, func(field types.Type) { t.markRead(fields, field, 1) })
		}
	}
}

// markRead marks the struct types of a decoded value, each from its least depth.
func (t *jsonRoundTrip) markRead(reading jsonReading, typ types.Type, depth int) {
	named, depth := jsonNamed(typ, depth)
	if named == nil || reading.except != nil && types.Identical(named, reading.except) {
		return
	}
	if least, seen := reading.depths[named]; seen && least <= depth {
		return
	}
	reading.depths[named] = depth
	if st, ok := named.Underlying().(*types.Struct); ok {
		t.unmarshalled[named.Obj()] = true
		eachJSONField(st, func(field types.Type) { t.markRead(reading, field, depth+1) })
	}
}

// decodedIdent returns the variable whose address is decoded into.
func decodedIdent(target ast.Expr) *ast.Ident {
	addr, ok := ast.Unparen(target).(*ast.UnaryExpr)
	if !ok {
		return nil
	}
	ident, _ := ast.Unparen(addr.X).(*ast.Ident)
	return ident
}

// partialDecodes returns the variables among the targets of decodes, with
// their types, that are declared in the function without a value and of which
// it only reads fields JSON carries: any other use may read the rest of the
// value. A type that decodes itself reads the whole of it.
func (t *jsonRoundTrip) partialDecodes(info *types.Info, body *ast.BlockStmt, decodes []ast.Expr) map[*ast.Ident]*types.Named {
	partial := map[*ast.Ident]*types.Named{}
	vars := map[types.Object]bool{}
	for _, target := range decodes {
		if ident := decodedIdent(target); ident != nil {
			if named, ok := info.TypeOf(ident).(*types.Named); ok && !t.decodesItself(named) {
				partial[ident] = named
				vars[info.Uses[ident]] = true
			}
		}
	}
	if len(vars) == 0 {
		return nil
	}
	// declared is the number of closures around the declaration, plus one.
	declared, whole := map[types.Object]int{}, map[types.Object]bool{}
	closures := 1
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			if _, ok := stack[len(stack)-1].(*ast.FuncLit); ok {
				closures--
			}
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, n)
		switch node := n.(type) {
		case *ast.FuncLit:
			closures++
		case *ast.Ident:
			if v := info.Defs[node]; vars[v] {
				if spec, ok := stack[len(stack)-2].(*ast.ValueSpec); ok && len(spec.Values) == 0 {
					declared[v] = closures
				}
			}
			if v := info.Uses[node]; vars[v] && (declared[v] != closures || partial[node] == nil && !t.readsJSONField(info, stack)) {
				whole[v] = true
			}
		}
		return true
	})
	for ident := range partial {
		if whole[info.Uses[ident]] {
			delete(partial, ident)
		}
	}
	return partial
}

// decodesItself reports a type with a decoding method of its own.
func (t *jsonRoundTrip) decodesItself(named *types.Named) bool {
	own, known := t.selfDecoded[named]
	if !known {
		for _, name := range []string{"UnmarshalJSON", "UnmarshalText"} {
			method, _, _ := types.LookupFieldOrMethod(named, true, nil, name)
			own = own || method != nil
		}
		t.selfDecoded[named] = own
	}
	return own
}

// readsJSONField reports a use of a variable, last in the stack of its
// parents, that reads a field JSON carries or a part of one: the field is not
// set and its address is not taken.
func (t *jsonRoundTrip) readsJSONField(info *types.Info, stack []ast.Node) bool {
	pos, i := stack[len(stack)-1].Pos(), len(stack)-1
	outer := func() ast.Node {
		for i--; ; i-- {
			if _, ok := stack[i].(*ast.ParenExpr); !ok {
				return stack[i]
			}
		}
	}
	sel, ok := outer().(*ast.SelectorExpr)
	if !ok || !t.isPlainJSONField(info.Selections[sel]) {
		return false
	}
	for {
		switch node := outer().(type) {
		case *ast.SelectorExpr:
			if method, ok := info.Uses[node.Sel].(*types.Func); ok {
				_, onPointer := types.Unalias(method.Signature().Recv().Type()).(*types.Pointer)
				return !onPointer
			}
		case *ast.IndexExpr:
			if pos > node.Lbrack {
				return true
			}
		case *ast.SliceExpr:
			_, isArray := info.TypeOf(node.X).Underlying().(*types.Array)
			return pos > node.Lbrack || !isArray
		case *ast.UnaryExpr:
			return node.Op != token.AND
		case *ast.AssignStmt:
			return pos > node.TokPos
		case *ast.RangeStmt:
			return pos > node.Range
		case *ast.IncDecStmt:
			return false
		default:
			return true
		}
	}
}

// isPlainJSONField reports a selected field of the struct itself that JSON
// carries and whose type holds no ignored field: that one would be read whole.
func (t *jsonRoundTrip) isPlainJSONField(selection *types.Selection) bool {
	if selection == nil || selection.Kind() != types.FieldVal || len(selection.Index()) != 1 {
		return false
	}
	st, ok := selection.Recv().Underlying().(*types.Struct)
	if !ok {
		return false
	}
	field, tag := st.Field(selection.Index()[0]), st.Tag(selection.Index()[0])
	if !field.Exported() || jsonIgnored(tag) {
		return false
	}
	held, _ := t.ignoring.holds(field.Type())
	return !held
}

// jsonIgnoring answers whether a type holds or refers to a struct with a field
// left out of JSON. The types of a cycle (Tarjan's component) get one answer,
// when the search leaves the cycle.
type jsonIgnoring struct {
	known map[types.Type]bool
	// at is the place in stack of a type whose answer is not known yet.
	at    map[types.Type]int
	stack []types.Type
}

// holds returns the answer and, while it is not final, the least place in the
// stack that the type leads back to. A type parameter may hold anything.
func (h *jsonIgnoring) holds(typ types.Type) (held bool, least int) {
	if at, pending := h.at[typ]; pending {
		return false, at
	}
	place := len(h.stack)
	if answer, ok := h.known[typ]; ok {
		return answer, place
	}
	h.at[typ], h.stack, least = place, append(h.stack, typ), place
	part := func(typ types.Type) {
		if !held {
			partHeld, partLeast := h.holds(typ)
			held, least = partHeld, min(least, partLeast)
		}
	}
	switch t := typ.Underlying().(type) {
	case interface{ Elem() types.Type }:
		part(t.Elem())
	case *types.Interface:
		_, held = types.Unalias(typ).(*types.TypeParam)
	case *types.Struct:
		for i := range t.NumFields() {
			held = held || jsonIgnored(t.Tag(i))
			part(t.Field(i).Type())
		}
	}
	if least == place {
		for _, done := range h.stack[place:] {
			h.known[done] = held
			delete(h.at, done)
		}
		h.stack = h.stack[:place]
	}
	return held, least
}

// ignoredField returns the field a selector reads when its tag leaves it out
// of JSON.
func ignoredField(info *types.Info, expr ast.Expr) *types.Var {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection := info.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal {
		return nil
	}
	v, ok := selection.Obj().(*types.Var)
	if !ok {
		return nil
	}
	return v
}

// fieldOwners maps each field of the package-level struct types of pkg to the
// first type, in name order, whose struct holds it: a defined type over
// another (type B A) shares its fields. One pass over the scope serves every
// field of the package, where a search per field sorted the names each time.
func fieldOwners(pkg *types.Package) map[*types.Var]*types.TypeName {
	owners := map[*types.Var]*types.TypeName{}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for field := range st.Fields() {
			if _, found := owners[field]; !found {
				owners[field] = tn
			}
		}
	}
	return owners
}
