package patterns

import (
	"go/ast"
	"go/types"
	"reflect"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewOrdinalInPersistentKeyRule())
}

// ordinalDepth bounds how many calls up an index parameter is followed.
const ordinalDepth = 3

// NewOrdinalInPersistentKeyRule creates ordinal-in-persistent-key: the index
// of an item in a list decoded from an external response is its position in
// today's answer, not its identity; an identifier built from it moves stored
// history onto another item as soon as the provider reorders the list:
//
//	for i := range proto.Items {
//	    tokens = append(tokens, itemTokens(proto.ID, i, &proto.Items[i])...)
//	}
//	func sourceID(protocolID string, itemIndex int, t Token) string {
//	    return fmt.Sprintf("p:%s:%d:%s", protocolID, itemIndex, t.ID)
//	}
//
// Reported: fmt.Sprintf building an identifier (returned by a *ID / *Key
// function or assigned to a *ID / *Key variable) from the index of a range
// over a slice of JSON-tagged structs, followed through the parameters it is
// passed in.
func NewOrdinalInPersistentKeyRule() *OrdinalInPersistentKeyRule {
	return &OrdinalInPersistentKeyRule{BaseRule: rules.NewBaseRule(
		"ordinal-in-persistent-key",
		"patterns",
		"Detects an identifier built from an item's index in a decoded external list — when the provider reorders the list, stored history moves onto another item",
		core.SeverityMedium,
	)}
}

// OrdinalInPersistentKeyRule is the rule; it needs the call sites of every
// function to follow an index parameter up.
type OrdinalInPersistentKeyRule struct {
	*rules.BaseRule
}

// AnalyzeFile is a no-op: the check needs types and call sites.
func (r *OrdinalInPersistentKeyRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough.
func (r *OrdinalInPersistentKeyRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports identifiers built from list positions.
func (r *OrdinalInPersistentKeyRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	decls, err := funcDeclsByObject(ctx)
	if err != nil {
		return nil, err
	}
	sites, err := funcCallSites(ctx, decls)
	if err != nil {
		return nil, err
	}
	inner := &typedFuncRule{
		BaseRule:   r.BaseRule,
		suggestion: "Build the identifier from an id the provider gives the item (its id or position index field), not from where it stands in the list",
	}
	inner.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		self, _ := scope.info.Defs[fn.Name].(*types.Func)
		for _, call := range identifierFormats(scope.info, fn) {
			for _, arg := range call.Args[1:] {
				ident, ok := ast.Unparen(arg).(*ast.Ident)
				if !ok {
					continue
				}
				v, ok := scope.info.ObjectOf(ident).(*types.Var)
				if ok && isListOrdinal(typedFuncDecl{decl: fn, info: scope.info}, self, v, sites, ordinalDepth) {
					findings = append(findings, funcFinding{node: call, message: "The identifier is built from " + v.Name() + ", an item's position in a decoded external list — when the list is reordered, the stored record moves onto another item"})
					break
				}
			}
		}
		return findings
	}
	return inner.AnalyzeGoProject(ctx)
}

// identifierFormats returns the fmt.Sprintf calls of a function that build
// an identifier: returned by a function named *ID / *Key, or assigned to a
// variable named so.
func identifierFormats(info *types.Info, fn *ast.FuncDecl) []*ast.CallExpr {
	var calls []*ast.CallExpr
	isFormat := func(expr ast.Expr) (*ast.CallExpr, bool) {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return nil, false
		}
		f := staticFunc(info, call)
		return call, f != nil && f.Pkg() != nil && f.Pkg().Path() == "fmt" && f.Name() == "Sprintf"
	}
	returnsID := namesIdentifier(fn.Name.Name)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if returnsID && len(node.Results) > 0 {
				if call, ok := isFormat(node.Results[0]); ok {
					calls = append(calls, call)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || i >= len(node.Rhs) || !namesIdentifier(ident.Name) {
					continue
				}
				if call, ok := isFormat(node.Rhs[i]); ok {
					calls = append(calls, call)
				}
			}
		}
		return true
	})
	return calls
}

// namesIdentifier reports a name whose last word is id or key.
func namesIdentifier(name string) bool {
	words := helpers.IdentifierWords(name)
	if len(words) == 0 {
		return false
	}
	last := words[len(words)-1]
	return last == "id" || last == "key"
}

// isListOrdinal reports a variable holding an item's index in a decoded
// external list: the key of a range over a slice of JSON-tagged structs in
// the function, or a parameter that some caller passes such an index.
func isListOrdinal(fn typedFuncDecl, self *types.Func, v *types.Var, sites map[*types.Func][]funcCallSite, depth int) bool {
	if rangesDecodedList(fn, v) {
		return true
	}
	if depth == 0 || self == nil {
		return false
	}
	index := -1
	for i, p := range paramObjects(fn) {
		if p == v {
			index = i
		}
	}
	if index < 0 {
		return false
	}
	for _, site := range sites[self.Origin()] {
		if index >= len(site.call.Args) {
			continue
		}
		ident, ok := ast.Unparen(site.call.Args[index]).(*ast.Ident)
		if !ok {
			continue
		}
		arg, ok := site.caller.info.ObjectOf(ident).(*types.Var)
		caller, _ := site.caller.info.Defs[site.caller.decl.Name].(*types.Func)
		if ok && isListOrdinal(site.caller, caller, arg, sites, depth-1) {
			return true
		}
	}
	return false
}

// rangesDecodedList reports a variable that is the key of a range, in the
// function, over a slice of structs with JSON tags.
func rangesDecodedList(fn typedFuncDecl, v *types.Var) bool {
	found := false
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok || found {
			return !found
		}
		key, ok := loop.Key.(*ast.Ident)
		if !ok || fn.info.ObjectOf(key) != v {
			return true
		}
		slice, ok := fn.info.TypeOf(loop.X).Underlying().(*types.Slice)
		found = ok && hasJSONTags(slice.Elem())
		return !found
	})
	return found
}

// hasJSONTags reports a struct (or pointer to one) with a json-tagged field.
func hasJSONTags(t types.Type) bool {
	st := structUnder(t)
	if st == nil {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		if _, ok := reflect.StructTag(st.Tag(i)).Lookup("json"); ok {
			return true
		}
	}
	return false
}
