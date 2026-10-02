package valueset

import (
	"go/ast"
	"go/token"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// Tables are the places a file spells values through named constants rather
// than literals - a list or a case clause of constants, the arguments filling
// an SQL IN list, a table translating slugs to constants - and the values it
// gives a JSON field. The constants are resolved against the project's
// declarations by the rule, so a file records names here.
type Tables struct {
	Consts   []ConstDecl
	Sets     []RefSet
	Mappings []Mapping
	Switches []DerivedDefaultSwitch
	Fields   []JSONField
	Assigns  []FieldAssign
	Unions   []PropUnion
}

// ConstDecl is a string constant. Group is the set it belongs to: its type
// within its package, or its name prefix within its declaration.
type ConstDecl struct {
	Name  string
	Value string
	Group string
	Path  string
	Line  int
}

// Ref is a name in the code that may be a constant: an identifier or the
// selector of one (pkg.Name).
type Ref struct {
	Name string
	Line int
}

// RefSet is a run of names written as one set: the elements of a list
// literal, a case clause's labels, consecutive arguments of a call.
type RefSet struct {
	Path string
	Line int
	Refs []Ref
	// Args is a run of call arguments: only its constants of one set are a
	// set, the other arguments (an alias, an id list) are not members.
	Args bool
}

// Pair is a literal translated to a constant, or a constant to a literal.
type Pair struct {
	Literal string
	Ref     string
}

// Mapping is a translation table: a map literal or a switch whose clauses
// each return one value.
type Mapping struct {
	Path  string
	Line  int
	Pairs []Pair
}

// DerivedDefaultSwitch is a switch over constants whose default returns a
// value made from the switch's own input.
type DerivedDefaultSwitch struct {
	Path   string
	Line   int
	Labels []string
}

// JSONField is a field of a struct type and the JSON name it is sent under,
// empty when it has none.
type JSONField struct {
	Struct string
	Field  string
	JSON   string
}

// FieldAssign is a literal or a name given to a struct field.
type FieldAssign struct {
	Field   string
	Literal string // set when the value is a string literal
	Ref     string // set when the value is a name
	Path    string
	Line    int
}

// PropUnion is a TS property typed as a union of string literals, with the
// interface or type it is declared in.
type PropUnion struct {
	Path    string
	Line    int
	Owner   string
	Prop    string
	Members []string
}

type tablesKey struct{}

// FileTables is the tables of a file, extracted once per file.
func FileTables(ctx *core.FileContext) Tables {
	return core.FileShared(ctx, tablesKey{}, func() Tables {
		switch {
		case ctx.IsGoFile() && ctx.GoAST != nil:
			return goTables(ctx)
		case ctx.IsTypeScriptFile():
			return Tables{Unions: propUnions(ctx)}
		}
		return Tables{}
	})
}

func goTables(ctx *core.FileContext) Tables {
	var t Tables
	dir := path.Dir(ctxSlash(ctx))
	for _, decl := range ctx.GoAST.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		families := nameFamilies(gen)
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, value := range vs.Values {
				s, ok := goString(value)
				if !ok {
					continue
				}
				t.Consts = append(t.Consts, ConstDecl{
					Name: vs.Names[i].Name, Value: s, Group: dir + "\x00" + constFamily(gen, vs, i, families),
					Path: ctx.RelPath, Line: ctx.LineFor(vs.Names[i]),
				})
			}
		}
	}
	line := ctx.LineFor
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			t.compositeLit(ctx, node)
		case *ast.CallExpr:
			var run []Ref
			flush := func() {
				if len(run) > 1 {
					t.Sets = append(t.Sets, RefSet{Path: ctx.RelPath, Line: run[0].Line, Refs: run, Args: true})
				}
				run = nil
			}
			for _, arg := range node.Args {
				if name, ok := refName(arg); ok {
					run = append(run, Ref{Name: name, Line: line(arg)})
					continue
				}
				flush()
			}
			flush()
		case *ast.SwitchStmt:
			t.switchStmt(ctx, node)
		case *ast.TypeSpec:
			st, ok := node.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				name := ""
				if field.Tag != nil {
					if tag, err := strconv.Unquote(field.Tag.Value); err == nil {
						name, _, _ = strings.Cut(reflect.StructTag(tag).Get("json"), ",")
					}
				}
				if name == "-" {
					name = ""
				}
				for _, id := range field.Names {
					t.Fields = append(t.Fields, JSONField{Struct: node.Name.Name, Field: id.Name, JSON: name})
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					t.assign(ctx, sel.Sel.Name, node.Rhs[i])
				}
			}
		}
		return true
	})
	return t
}

func ctxSlash(ctx *core.FileContext) string {
	return strings.ReplaceAll(ctx.RelPath, "\\", "/")
}

// constFamily is the set a constant belongs to: its type, or its name prefix
// within its declaration. A constant declared alone goes with the others of
// its package sharing the prefix: RuleSourceAlpha with RuleSourceBeta.
func constFamily(gen *ast.GenDecl, vs *ast.ValueSpec, i int, families map[string]int) string {
	if vs.Type != nil {
		if name := goTypeName(vs.Type); name != "" {
			return "type " + name
		}
	}
	name := vs.Names[i].Name
	prefix := namePrefix(name)
	for p := prefix; p != ""; p = namePrefix(p) {
		if families[p] > 1 {
			return p
		}
	}
	return prefix
}

func (t *Tables) assign(ctx *core.FileContext, field string, value ast.Expr) {
	a := FieldAssign{Field: field, Path: ctx.RelPath, Line: ctx.LineFor(value)}
	if s, ok := goString(value); ok {
		a.Literal = s
	} else if name, ok := refName(value); ok {
		a.Ref = name
	} else {
		return
	}
	t.Assigns = append(t.Assigns, a)
}

func (t *Tables) compositeLit(ctx *core.FileContext, lit *ast.CompositeLit) {
	switch typ := lit.Type.(type) {
	case *ast.ArrayType:
		var refs []Ref
		for _, elt := range lit.Elts {
			name, ok := refName(elt)
			if !ok {
				return
			}
			refs = append(refs, Ref{Name: name, Line: ctx.LineFor(elt)})
		}
		if len(refs) > 1 {
			t.Sets = append(t.Sets, RefSet{Path: ctx.RelPath, Line: ctx.LineFor(lit), Refs: refs})
		}
	case *ast.MapType:
		var pairs []Pair
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				return
			}
			pair, ok := literalPair(kv.Key, kv.Value)
			if !ok {
				return
			}
			pairs = append(pairs, pair)
		}
		if len(pairs) > 0 {
			t.Mappings = append(t.Mappings, Mapping{Path: ctx.RelPath, Line: ctx.LineFor(lit), Pairs: pairs})
		}
	case *ast.Ident, *ast.SelectorExpr:
		_ = typ
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok {
					t.assign(ctx, key.Name, kv.Value)
				}
			}
		}
	}
}

// literalPair is a translation of a literal to a name or of a name to a
// literal.
func literalPair(from, to ast.Expr) (Pair, bool) {
	if s, ok := goString(from); ok {
		if name, ok := refName(to); ok {
			return Pair{Literal: s, Ref: name}, true
		}
	}
	if s, ok := goString(to); ok {
		if name, ok := refName(from); ok {
			return Pair{Literal: s, Ref: name}, true
		}
	}
	return Pair{}, false
}

func (t *Tables) switchStmt(ctx *core.FileContext, sw *ast.SwitchStmt) {
	var pairs []Pair
	var labels []string
	allRefs := true
	var dflt *ast.CaseClause
	for _, stmt := range sw.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if clause.List == nil {
			dflt = clause
			continue
		}
		var refs []Ref
		for _, expr := range clause.List {
			name, ok := refName(expr)
			if !ok {
				allRefs = false
				continue
			}
			refs = append(refs, Ref{Name: name, Line: ctx.LineFor(expr)})
			labels = append(labels, name)
		}
		if len(refs) > 1 && len(refs) == len(clause.List) {
			t.Sets = append(t.Sets, RefSet{Path: ctx.RelPath, Line: ctx.LineFor(clause), Refs: refs})
		}
		if result := singleReturn(clause.Body); result != nil {
			for _, expr := range clause.List {
				if pair, ok := literalPair(expr, result); ok {
					pairs = append(pairs, pair)
				}
			}
		}
	}
	if len(pairs) > 0 {
		t.Mappings = append(t.Mappings, Mapping{Path: ctx.RelPath, Line: ctx.LineFor(sw), Pairs: pairs})
	}
	if sw.Tag != nil && allRefs && len(labels) > 1 && dflt != nil && derivedFrom(singleReturn(dflt.Body), sw.Tag) {
		t.Switches = append(t.Switches, DerivedDefaultSwitch{Path: ctx.RelPath, Line: ctx.LineFor(sw), Labels: labels})
	}
}

// singleReturn is the one value a clause body returns: return x, alone.
func singleReturn(body []ast.Stmt) ast.Expr {
	if len(body) != 1 {
		return nil
	}
	ret, ok := body[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil
	}
	return ret.Results[0]
}

// derivedFrom reports a value made from the variables of the switch's tag:
// strings.ToUpper(chain) for switch chain, the input itself.
func derivedFrom(value, tag ast.Expr) bool {
	if value == nil {
		return false
	}
	vars := make(map[string]bool)
	ast.Inspect(tag, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			ast.Inspect(sel.X, func(inner ast.Node) bool {
				if id, ok := inner.(*ast.Ident); ok && id != sel.X {
					vars[id.Name] = true
				}
				return true
			})
			return false
		}
		if id, ok := n.(*ast.Ident); ok {
			vars[id.Name] = true
		}
		return true
	})
	found := false
	ast.Inspect(value, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && vars[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

// refName is the name an identifier or a package selector refers to.
func refName(expr ast.Expr) (string, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if e.Name == "nil" || e.Name == "true" || e.Name == "false" || e.Name == "_" {
			return "", false
		}
		return e.Name, true
	case *ast.SelectorExpr:
		if _, ok := e.X.(*ast.Ident); ok {
			return e.Sel.Name, true
		}
	}
	return "", false
}

// jsPropUnion is a property typed as a union of string literals:
// status?: 'a' | 'b' | 'c'.
var (
	jsPropUnion = regexp.MustCompile(`(?m)^\s*(?:readonly\s+)?([A-Za-z_$][\w$]*)\??\s*:\s*\|?\s*(` + jsString + `(?:\s*\|\s*` + jsString + `)+)\s*[,;]?\s*(?://.*)?$`)
	jsTypeOwner = regexp.MustCompile(`\b(?:interface|type)\s+([A-Za-z_$][\w$]*)`)
)

func propUnions(ctx *core.FileContext) []PropUnion {
	text := strings.Join(helpers.FileJSText(ctx), "\n")
	lineAt := lineIndex(text)
	var unions []PropUnion
	owners := jsTypeOwner.FindAllStringSubmatchIndex(text, -1)
	for _, m := range jsPropUnion.FindAllStringSubmatchIndex(text, -1) {
		// The owner is the last interface or type declared before the
		// property.
		i, _ := slices.BinarySearchFunc(owners, m[2], func(o []int, offset int) int { return o[0] - offset })
		if i == 0 {
			continue
		}
		o := owners[i-1]
		unions = append(unions, PropUnion{
			Path:    ctx.RelPath,
			Line:    lineAt(m[2]),
			Owner:   text[o[2]:o[3]],
			Prop:    text[m[2]:m[3]],
			Members: unquoteAll(jsStrings.FindAllString(text[m[4]:m[5]], -1)),
		})
	}
	return unions
}
