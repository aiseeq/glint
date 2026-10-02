package patterns

import (
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// statsFuncName names a function computing totals over a filtered set.
var statsFuncName = regexp.MustCompile(`(?i)stat|summary|count|total|aggregate`)

// filterItem is one thing a filter mapping reads from its source: a field of
// a filter struct, or a key of a query string.
type filterItem struct {
	node ast.Node
	name string
}

// filterSource is what a filter is read from: a filter struct type, or the
// query string (nil).
type filterSource struct {
	named *types.Named
}

// filterMapping is a function reading a filter: the items it reads by hand
// and the helpers it hands the source to.
type filterMapping struct {
	fn      *ast.FuncDecl
	file    *core.FileContext
	source  filterSource
	items   []filterItem
	helpers map[*types.Func]bool
}

// handMappedFilters returns, per file, the first item read by each totals
// function of a package that maps a list filter by hand while a helper of
// the package maps the same filter for the list:
//
//	func (r *Repo) List(ctx context.Context, f *Filter) (...) { applyFilter(b, f) ... }
//	func (r *Repo) StatsByFilter(ctx context.Context, f *Filter) (...) {
//	    if f.Wallet != nil { ... }   // the mapping again, by hand
//
// The totals and the list then filter differently as soon as one mapping
// changes: the cards above a table count other rows than the table shows.
func handMappedFilters(pkg *core.GoPackageContext) map[*core.FileContext][]handMapped {
	info := pkg.Package.TypesInfo
	var mappings []filterMapping
	for _, file := range pkg.Files {
		if file.GoAST == nil || file.IsTestFile() {
			continue
		}
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			mappings = append(mappings, filterMappings(fn, file, info)...)
		}
	}
	// A helper maps a source when it reads three of its items and another
	// function hands it that source.
	helpers := make(map[*types.Func]filterMapping)
	bySource := make(map[filterSource][]filterMapping)
	for _, m := range mappings {
		bySource[m.source] = append(bySource[m.source], m)
	}
	for _, m := range mappings {
		obj, ok := info.Defs[m.fn.Name].(*types.Func)
		if !ok || len(distinctItems(m.items)) < 3 {
			continue
		}
		for _, other := range bySource[m.source] {
			if other.fn != m.fn && other.source == m.source && other.helpers[obj] {
				helpers[obj] = m
				break
			}
		}
	}
	found := make(map[*core.FileContext][]handMapped)
	for _, m := range mappings {
		if !statsFuncName.MatchString(m.fn.Name.Name) || len(m.items) == 0 {
			continue
		}
		mine := distinctItems(m.items)
		for _, helper := range sortedHelpers(helpers) {
			if helper.source != m.source || helper.fn == m.fn || m.helpers[helperObj(helper, info)] {
				continue
			}
			shared := 0
			theirs := distinctItems(helper.items)
			for name := range mine {
				if theirs[name] {
					shared++
				}
			}
			if shared >= 2 {
				found[m.file] = append(found[m.file], handMapped{node: m.items[0].node, fn: m.fn.Name.Name, helper: helper.fn.Name.Name})
				break
			}
		}
	}
	return found
}

// handMapped is one totals function mapping a filter by hand.
type handMapped struct {
	node   ast.Node
	fn     string
	helper string
}

func helperObj(m filterMapping, info *types.Info) *types.Func {
	obj, _ := info.Defs[m.fn.Name].(*types.Func)
	return obj
}

// sortedHelpers returns the helpers in source order, so findings name the
// same helper on every run.
func sortedHelpers(helpers map[*types.Func]filterMapping) []filterMapping {
	list := make([]filterMapping, 0, len(helpers))
	for _, m := range helpers {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].file.RelPath != list[j].file.RelPath {
			return list[i].file.RelPath < list[j].file.RelPath
		}
		return list[i].fn.Pos() < list[j].fn.Pos()
	})
	return list
}

func distinctItems(items []filterItem) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item.name] = true
	}
	return set
}

// filterMappings returns what a function reads of each filter source it
// has: the fields of a filter-struct parameter, the keys of a query string.
func filterMappings(fn *ast.FuncDecl, file *core.FileContext, info *types.Info) []filterMapping {
	var mappings []filterMapping
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			param, ok := info.Defs[name].(*types.Var)
			if !ok {
				continue
			}
			if named := filterStruct(param.Type()); named != nil {
				mappings = append(mappings, structFilterMapping(fn, file, info, param, named))
			}
		}
	}
	if m, ok := queryFilterMapping(fn, file, info); ok {
		mappings = append(mappings, m)
	}
	return mappings
}

// filterStruct returns the named struct type a filter parameter points to:
// a type named as a filter, query or criteria.
func filterStruct(t types.Type) *types.Named {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return nil
	}
	if !filterTypeName.MatchString(named.Obj().Name()) {
		return nil
	}
	return named
}

var filterTypeName = regexp.MustCompile(`(?i)filter|query|criteria|params$`)

func structFilterMapping(fn *ast.FuncDecl, file *core.FileContext, info *types.Info, param *types.Var, named *types.Named) filterMapping {
	m := filterMapping{fn: fn, file: file, source: filterSource{named: named}, helpers: make(map[*types.Func]bool)}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := ast.Unparen(node.X).(*ast.Ident); ok && info.Uses[id] == param {
				if selection, ok := info.Selections[node]; ok && selection.Kind() == types.FieldVal {
					m.items = append(m.items, filterItem{node: node, name: node.Sel.Name})
				}
			}
		case *ast.CallExpr:
			for _, arg := range node.Args {
				if id, ok := ast.Unparen(arg).(*ast.Ident); ok && info.Uses[id] == param {
					if callee := staticFunc(info, node); callee != nil {
						m.helpers[callee] = true
					}
				}
			}
		}
		return true
	})
	return m
}

// queryFilterMapping returns the keys a function reads from a query string
// (url.Values): the string constants handed to its Get, directly or through
// a local helper closure, and the functions it hands the query string to.
func queryFilterMapping(fn *ast.FuncDecl, file *core.FileContext, info *types.Info) (filterMapping, bool) {
	m := filterMapping{fn: fn, file: file, helpers: make(map[*types.Func]bool)}
	reads := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if isURLValues(info.TypeOf(arg)) {
				if callee := staticFunc(info, call); callee != nil {
					m.helpers[callee] = true
					reads = true
				}
			}
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Get" && isURLValues(info.TypeOf(sel.X)) {
			reads = true
		}
		// A key constant handed to Get or to a closure that reads the query.
		for _, arg := range call.Args {
			tv, ok := info.Types[arg]
			if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
				continue
			}
			key := constant.StringVal(tv.Value)
			if queryKeyShape.MatchString(key) && readsQuery(call, info) {
				m.items = append(m.items, filterItem{node: call, name: key})
			}
		}
		return true
	})
	return m, reads
}

var queryKeyShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// readsQuery reports a call reading a query-string key: Get on url.Values,
// or a call of a local closure.
func readsQuery(call *ast.CallExpr, info *types.Info) bool {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name == "Get" && isURLValues(info.TypeOf(fun.X))
	case *ast.Ident:
		v, ok := info.Uses[fun].(*types.Var)
		return ok && !v.IsField() && v.Parent() != nil && v.Parent() != v.Pkg().Scope()
	}
	return false
}

func isURLValues(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/url" && named.Obj().Name() == "Values"
}

// handMappedMessage renders the finding.
func handMappedMessage(m handMapped) string {
	return strings.Join([]string{m.fn, " maps the list filter by hand while ", m.helper,
		" maps it for the list — the totals count other rows than the list shows as soon as one mapping changes"}, "")
}
