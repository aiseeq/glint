package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"reflect"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
type JSONIgnoredFieldLostInRoundTripRule struct {
	*rules.BaseRule
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
	// owners caches the struct type declaring a field.
	owners map[*types.Var]*types.TypeName
}

// owner returns the named struct type that declares the field.
func (t *jsonRoundTrip) owner(v *types.Var) *types.TypeName {
	if owner, ok := t.owners[v]; ok {
		return owner
	}
	owner := fieldOwner(v)
	t.owners[v] = owner
	return owner
}

// AnalyzeGoProject reports the ignored fields lost by the round trip.
func (r *JSONIgnoredFieldLostInRoundTripRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	trip := jsonRoundTrip{
		marshalled: map[*types.TypeName]bool{}, unmarshalled: map[*types.TypeName]bool{},
		written: map[*types.Var]bool{}, read: map[*types.Var]bool{}, refilled: map[*types.Var]bool{},
		owners: map[*types.Var]*types.TypeName{},
	}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkgCtx.Package.Syntax {
			if !strings.HasSuffix(pkgCtx.Package.Fset.Position(file.Pos()).Filename, "_test.go") {
				trip.collect(pkgCtx.Package.TypesInfo, file)
			}
		}
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
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
			st, isStruct := spec.Type.(*ast.StructType)
			if !ok || !isStruct || !trip.marshalled[name] || !trip.unmarshalled[name] {
				return true
			}
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
		targets := map[ast.Expr]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				t.jsonCall(info, node, decoded)
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
		for _, v := range assigned {
			if owner := t.owner(v); owner != nil && decoded[owner] {
				t.refilled[v] = true
			}
		}
	}
}

// jsonCall records the types json.Marshal, json.Unmarshal and the encoder
// and decoder take.
func (t *jsonRoundTrip) jsonCall(info *types.Info, call *ast.CallExpr, decoded map[*types.TypeName]bool) {
	fn := staticFunc(info, call)
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "encoding/json" || len(call.Args) == 0 {
		return
	}
	switch fn.Name() {
	case "Marshal", "MarshalIndent", "Encode":
		jsonTypes(info.TypeOf(call.Args[0]), t.marshalled, 0)
	case "Unmarshal":
		if len(call.Args) == 2 {
			jsonTypes(info.TypeOf(call.Args[1]), t.unmarshalled, 0)
			jsonTypes(info.TypeOf(call.Args[1]), decoded, 0)
		}
	case "Decode":
		jsonTypes(info.TypeOf(call.Args[0]), t.unmarshalled, 0)
		jsonTypes(info.TypeOf(call.Args[0]), decoded, 0)
	}
}

// jsonTypes records the named struct types a value of type typ carries in
// JSON: itself, its elements, its exported fields, a few levels deep.
func jsonTypes(typ types.Type, seen map[*types.TypeName]bool, depth int) {
	if typ == nil || depth > 4 {
		return
	}
	switch t := typ.(type) {
	case *types.Pointer:
		jsonTypes(t.Elem(), seen, depth)
	case *types.Slice:
		jsonTypes(t.Elem(), seen, depth+1)
	case *types.Array:
		jsonTypes(t.Elem(), seen, depth+1)
	case *types.Map:
		jsonTypes(t.Elem(), seen, depth+1)
	case *types.Named:
		if seen[t.Obj()] {
			return
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok {
			return
		}
		seen[t.Obj()] = true
		for i := range st.NumFields() {
			field := st.Field(i)
			if field.Exported() && !jsonIgnored(st.Tag(i)) {
				jsonTypes(field.Type(), seen, depth+1)
			}
		}
	}
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

// fieldOwner returns the named struct type that declares the field.
func fieldOwner(v *types.Var) *types.TypeName {
	if v.Pkg() == nil {
		return nil
	}
	scope := v.Pkg().Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := range st.NumFields() {
			if st.Field(i) == v {
				return tn
			}
		}
	}
	return nil
}
