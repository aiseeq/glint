package patterns

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewCacheKeyMissingDiscriminatorRule())
	rules.Register(NewCompositeKeySeparatorMismatchRule())
	rules.Register(NewCacheKeyCoarserThanFetchKeyRule())
	rules.Register(NewFuzzyMatchReturnsFirstCandidateRule())
	rules.Register(NewLookupValidatesBeforeMatchFilterRule())
	rules.Register(NewDuplicateKeyInDefinitionListRule())
}

// cacheReadPrefixes and cacheWritePrefixes start the names of the methods
// that read and fill a cache.
var (
	cacheReadPrefixes  = []string{"Get", "Load", "Lookup", "Fetch", "Read", "Find"}
	cacheWritePrefixes = []string{"Set", "Put", "Upsert", "Store", "Save", "Write", "Add"}
)

// cacheCall returns the receiver spelling of a method call on a value named
// for a cache and whether the method reads (Get) or fills (Set) it.
func cacheCall(call *ast.CallExpr) (receiver string, read, write bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return "", false, false
	}
	receiver = types.ExprString(sel.X)
	if !strings.Contains(strings.ToLower(receiver), "cache") {
		return "", false, false
	}
	hasPrefix := func(prefix string) bool { return strings.HasPrefix(sel.Sel.Name, prefix) }
	return receiver, slices.ContainsFunc(cacheReadPrefixes, hasPrefix), slices.ContainsFunc(cacheWritePrefixes, hasPrefix)
}

// NewCacheKeyMissingDiscriminatorRule creates
// cache-key-missing-discriminator: a value cached under a key that leaves
// out what chose how it was computed. Between the cache read and the cache
// write the function branches on a variable neither call takes, so a value
// computed one way is served to callers that need the other:
//
//	cached, err := o.fxCache.Get(ctx, pair, country)
//	...
//	switch source {
//	case sourceA: rate = a.Rate(pair)
//	default:      rate = b.Rate(pair)
//	}
//	o.fxCache.Upsert(ctx, pair, country, rate)
func NewCacheKeyMissingDiscriminatorRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"cache-key-missing-discriminator",
			"patterns",
			"Detects a cached value computed by a branch on a variable the cache key leaves out — a value computed one way is served to callers that need the other",
			core.SeverityHigh,
		),
		suggestion: "Add the variable the computation branches on to the cache key of both the read and the write",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		reads := make(map[string]*ast.CallExpr)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			receiver, read, write := cacheCall(call)
			if read {
				if _, seen := reads[receiver]; !seen {
					reads[receiver] = call
				}
			}
			if get, ok := reads[receiver]; ok && write && !read {
				if branch, name := keylessBranch(scope.info, fn.Body, get, call); branch != nil {
					findings = append(findings, funcFinding{node: branch, message: "The cached value is computed by a branch on " + name + ", which the cache key leaves out — a value computed for one " + name + " is served for another"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// keylessBranch returns a switch or an if between the cache read and write
// that branches on a variable neither call takes and computes a value the
// write stores.
func keylessBranch(info *types.Info, body *ast.BlockStmt, get, set *ast.CallExpr) (ast.Node, string) {
	keyed := func(obj types.Object) bool {
		return slices.ContainsFunc(append(slices.Clone(get.Args), set.Args...), func(arg ast.Expr) bool { return mentionsObject(info, arg, obj) })
	}
	var found ast.Node
	name := ""
	ast.Inspect(body, func(n ast.Node) bool {
		if found != nil || n == nil {
			return false
		}
		if n.Pos() < get.End() || n.End() > set.Pos() {
			return n.Pos() < set.Pos()
		}
		var subject ast.Expr
		switch stmt := n.(type) {
		case *ast.SwitchStmt:
			subject = stmt.Tag
		case *ast.IfStmt:
			if cmp, ok := ast.Unparen(stmt.Cond).(*ast.BinaryExpr); ok && (cmp.Op == token.EQL || cmp.Op == token.NEQ) && !isNilIdent(cmp.X) && !isNilIdent(cmp.Y) {
				subject = cmp.X
			}
		default:
			return true
		}
		ident, ok := ast.Unparen(subject).(*ast.Ident)
		if !ok {
			return true
		}
		v, ok := info.ObjectOf(ident).(*types.Var)
		if !ok || v.IsField() || isErrorOrBool(v.Type()) || keyed(v) || !assignsCachedValue(info, n, set) {
			return true
		}
		found, name = n, ident.Name
		return false
	})
	return found, name
}

// assignsCachedValue reports a branch assigning a variable the cache write
// takes: the branch computes what is cached, it does not merely refuse.
func assignsCachedValue(info *types.Info, branch ast.Node, set *ast.CallExpr) bool {
	found := false
	ast.Inspect(branch, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return !found
		}
		for _, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if ok && slices.ContainsFunc(set.Args, func(arg ast.Expr) bool { return mentionsObject(info, arg, info.ObjectOf(ident)) }) {
				found = true
			}
		}
		return !found
	})
	return found
}

// isErrorOrBool reports the error interface or a boolean.
func isErrorOrBool(t types.Type) bool {
	if types.Identical(t, types.Universe.Lookup("error").Type()) {
		return true
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsBoolean != 0
}

// keyConcat is one key built as a.F + "sep" + b.G.
type keyConcat struct {
	node *ast.BinaryExpr
	sep  string
	log  bool
}

// concatFields identifies a pair of fields joined into a key within one
// package.
type concatFields struct {
	pkg         *types.Package
	left, right *types.Var
}

// NewCompositeKeySeparatorMismatchRule creates
// composite-key-separator-mismatch: the same two fields joined into a key
// with different separators in one package. A key written as "USD:EUR" is
// never found by a reader that builds "USD/EUR":
//
//	pair := tx.From + ":" + tx.To // elsewhere: tx.From + "/" + tx.To
func NewCompositeKeySeparatorMismatchRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"composite-key-separator-mismatch",
			"patterns",
			"Detects the same two fields joined into a key with another separator than elsewhere in the package — a key written one way is never found by readers building the other",
			core.SeverityMedium,
		),
		suggestion: "Build the key in one function and call it everywhere",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		byFields := make(map[concatFields][]keyConcat)
		for obj, decl := range decls {
			if decl.decl.Body == nil {
				continue
			}
			for fields, concat := range keyConcats(decl.info, obj.Pkg(), decl.decl.Body) {
				byFields[fields] = append(byFields[fields], concat...)
			}
		}
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			obj, ok := scope.info.Defs[fn.Name].(*types.Func)
			if !ok || fn.Body == nil {
				return nil
			}
			var findings []funcFinding
			for fields, concats := range keyConcats(scope.info, obj.Pkg(), fn.Body) {
				counts := make(map[string]int)
				for _, c := range byFields[fields] {
					counts[c.sep]++
				}
				for _, c := range concats {
					if c.log {
						continue
					}
					if other, ok := moreCommonSeparator(counts, c.sep); ok {
						findings = append(findings, funcFinding{node: c.node, message: "The key joins " + fields.left.Name() + " and " + fields.right.Name() + " with \"" + c.sep + "\" while the package also joins them with \"" + other + "\" — a key written one way is never found by readers building the other"})
					}
				}
			}
			slices.SortFunc(findings, func(a, b funcFinding) int { return cmp.Compare(a.node.Pos(), b.node.Pos()) })
			return findings
		}
	}
	return r
}

// moreCommonSeparator returns a separator used at least as often as sep.
func moreCommonSeparator(counts map[string]int, sep string) (string, bool) {
	best := ""
	for other, count := range counts {
		if other != sep && count >= counts[sep] && (best == "" || other < best) {
			best = other
		}
	}
	return best, best != ""
}

// keyConcats returns the a.F + "sep" + b.G concatenations of a body by the
// pair of fields.
func keyConcats(info *types.Info, pkg *types.Package, body *ast.BlockStmt) map[concatFields][]keyConcat {
	found := make(map[concatFields][]keyConcat)
	var logged []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && (helpers.IsLoggerCall(call) || isPkgFunc(info, call, "fmt", "Errorf")) {
			logged = append(logged, call)
		}
		outer, ok := n.(*ast.BinaryExpr)
		if !ok || outer.Op != token.ADD {
			return true
		}
		inner, ok := ast.Unparen(outer.X).(*ast.BinaryExpr)
		if !ok || inner.Op != token.ADD {
			return true
		}
		sep, ok := stringLiteral(inner.Y)
		left, right := selectedField(inner.X, info), selectedField(outer.Y, info)
		if !ok || !isSeparator(sep) || left == nil || right == nil {
			return true
		}
		inLog := slices.ContainsFunc(logged, func(call *ast.CallExpr) bool { return call.Pos() <= outer.Pos() && outer.End() <= call.End() })
		key := concatFields{pkg: pkg, left: left, right: right}
		found[key] = append(found[key], keyConcat{node: outer, sep: sep, log: inLog})
		return true
	})
	return found
}

// isSeparator reports a short run of punctuation: ":", "/", "|", "::".
func isSeparator(text string) bool {
	if text == "" || len(text) > 3 {
		return false
	}
	return !strings.ContainsFunc(text, func(r rune) bool { return !strings.ContainsRune(":/|-_.,;#@", r) })
}

// NewCacheKeyCoarserThanFetchKeyRule creates
// cache-key-coarser-than-fetch-key: a loop over distinct keys that fetches
// with every part of the key but stores and skips by only one of them. The
// first fetch for a country is kept for every method of that country:
//
//	for k := range seen { // k: struct{country, method, kind}
//		if _, ok := result[k.country]; ok {
//			continue
//		}
//		banks, err := client.Banks(k.country, k.method, k.kind)
//		result[k.country] = banks
func NewCacheKeyCoarserThanFetchKeyRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"cache-key-coarser-than-fetch-key",
			"patterns",
			"Detects a loop over distinct keys that fetches with several parts of the key but stores the result under fewer — the first fetch is kept for keys that needed their own",
			core.SeverityHigh,
		),
		suggestion: "Store the result under the whole key the fetch was made with",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			key, ok := loop.Key.(*ast.Ident)
			if !ok || !isStructKeyedMap(scope.info.TypeOf(loop.X)) {
				return true
			}
			obj := scope.info.ObjectOf(key)
			if finding, ok := coarserStore(scope.info, loop.Body, obj); ok {
				findings = append(findings, finding)
			}
			return true
		})
		return findings
	}
	return r
}

// isStructKeyedMap reports a map whose key is a struct.
func isStructKeyedMap(t types.Type) bool {
	if t == nil {
		return false
	}
	m, ok := t.Underlying().(*types.Map)
	if !ok {
		return false
	}
	_, isStruct := m.Key().Underlying().(*types.Struct)
	return isStruct
}

// coarserStore finds a map stored under a field of the key while a fetch in
// the loop takes other fields of it.
func coarserStore(info *types.Info, body *ast.BlockStmt, key types.Object) (funcFinding, bool) {
	keyField := func(expr ast.Expr) string {
		sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
		if !ok || !isIdentOf(info, sel.X, key) {
			return ""
		}
		return sel.Sel.Name
	}
	type store struct {
		first ast.Node
		field string
	}
	stores := make(map[string]*store)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			index, ok := lhs.(*ast.IndexExpr)
			if field := keyField(indexOf(index, ok)); ok && field != "" {
				stores[types.ExprString(index.X)] = &store{field: field}
			}
		}
		return true
	})
	if len(stores) == 0 {
		return funcFinding{}, false
	}
	var fetched []string
	ast.Inspect(body, func(n ast.Node) bool {
		if index, ok := n.(*ast.IndexExpr); ok {
			if s := stores[types.ExprString(index.X)]; s != nil && s.first == nil && keyField(index.Index) == s.field {
				s.first = index
			}
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || !returnsError(call, info) {
			return true
		}
		ast.Inspect(call, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok {
				if field := keyField(sel); field != "" && !slices.Contains(fetched, field) {
					fetched = append(fetched, field)
				}
			}
			return true
		})
		return true
	})
	for _, name := range slices.Sorted(maps.Keys(stores)) {
		s := stores[name]
		if s.first == nil || !slices.Contains(fetched, s.field) {
			continue
		}
		for _, field := range fetched {
			if field != s.field {
				return funcFinding{node: s.first, message: "The result is fetched with " + strings.Join(fetched, ", ") + " of the key but kept in " + name + " under " + s.field + " alone — the first fetch for a " + s.field + " is kept for keys that needed their own"}, true
			}
		}
	}
	return funcFinding{}, false
}

// indexOf returns the index of an index expression the caller matched.
func indexOf(index *ast.IndexExpr, ok bool) ast.Expr {
	if !ok {
		return nil
	}
	return index.Index
}

// fuzzyCompareFuncs compare text by containment rather than equality.
var fuzzyCompareFuncs = []string{"Contains", "HasPrefix", "HasSuffix", "ContainsAny"}

// nameWords name a value people type by hand.
var nameWords = map[string]bool{"name": true, "title": true, "label": true}

// NewFuzzyMatchReturnsFirstCandidateRule creates
// fuzzy-match-returns-first-candidate: a loop over options that returns the
// first one whose name contains (or is contained in) the wanted one. When
// two options fit - "Union" fits "Union Bank" and "First Union Bank" - the
// order of the list picks the answer:
//
//	for _, o := range opts {
//		if strings.Contains(NormalizeName(o.Name), target) {
//			return o.ID, true
//		}
//	}
func NewFuzzyMatchReturnsFirstCandidateRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"fuzzy-match-returns-first-candidate",
			"patterns",
			"Detects a loop returning the first option whose name contains the wanted one — when two options fit, the order of the list picks the answer",
			core.SeverityHigh,
		),
		suggestion: "Collect every option that fits and refuse an answer when more than one does",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			value, ok := loop.Value.(*ast.Ident)
			if !ok || value.Name == "_" {
				return true
			}
			option := scope.info.ObjectOf(value)
			names := optionNames(scope.info, loop.Body, option)
			for _, stmt := range loop.Body.List {
				check, ok := stmt.(*ast.IfStmt)
				if !ok || !fuzzyOnName(scope.info, check.Cond, names) || !returnsOption(scope.info, check.Body, option) {
					continue
				}
				findings = append(findings, funcFinding{node: check, message: "The first option whose name contains the wanted one is returned — when two options fit, the order of the list picks the answer"})
			}
			return true
		})
		return findings
	}
	return r
}

// optionNames returns the loop variables computed from the option's name
// (n := normalize(o.Name)) as true, and the option itself as false: its
// name fields are read through it.
func optionNames(info *types.Info, body *ast.BlockStmt, option types.Object) map[types.Object]bool {
	names := make(map[types.Object]bool)
	readsName := func(expr ast.Expr) bool {
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && isIdentOf(info, sel.X, option) && hasWordFrom(sel.Sel.Name, nameWords) {
				found = true
			}
			return !found
		})
		return found
	}
	names[option] = false
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			continue
		}
		for i, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && readsName(assign.Rhs[i]) {
				names[info.ObjectOf(ident)] = true
			}
		}
	}
	return names
}

// fuzzyOnName reports a condition comparing the option's name by
// containment.
func fuzzyOnName(info *types.Info, cond ast.Expr, names map[types.Object]bool) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !slices.ContainsFunc(fuzzyCompareFuncs, func(name string) bool { return isPkgFunc(info, call, "strings", name) }) {
			return true
		}
		for _, arg := range call.Args {
			if readsOptionName(info, arg, names) {
				found = true
			}
		}
		return !found
	})
	return found
}

// readsOptionName reports an argument that is a name variable of the loop.
func readsOptionName(info *types.Info, arg ast.Expr, names map[types.Object]bool) bool {
	found := false
	ast.Inspect(arg, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if names[info.ObjectOf(node)] {
				found = true
			}
		case *ast.SelectorExpr:
			if id, ok := ast.Unparen(node.X).(*ast.Ident); ok {
				if _, isOption := names[info.ObjectOf(id)]; isOption && hasWordFrom(node.Sel.Name, nameWords) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// returnsOption reports a block ending in a return of the option or a
// field of it.
func returnsOption(info *types.Info, body *ast.BlockStmt, option types.Object) bool {
	if len(body.List) == 0 {
		return false
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	return ok && slices.ContainsFunc(ret.Results, func(e ast.Expr) bool { return mentionsObject(info, e, option) })
}

// NewLookupValidatesBeforeMatchFilterRule creates
// lookup-validates-before-match-filter: a function that tells whether an
// element is the one sought, called for every element of a list, fails on
// a bad element before it checks whether it is the sought one. One broken
// entry the caller does not need fails every lookup of the list:
//
//	func pairRate(pair, value, from, to string) (decimal.Decimal, bool, error) {
//		rate, err := decimal.NewFromString(value)
//		if err != nil {
//			return decimal.Zero, false, err
//		}
//		if pairOf(pair) == from+"/"+to {
//			return rate, true, nil
//		}
//		return decimal.Zero, false, nil
func NewLookupValidatesBeforeMatchFilterRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"lookup-validates-before-match-filter",
			"patterns",
			"Detects a per-element match function that fails on a bad element before checking whether it is the one sought — one broken entry nobody asked for fails every lookup",
			core.SeverityMedium,
		),
		suggestion: "Check whether the element is the one sought first and validate only the element that matches",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil || !foundAndErrorResults(scope.info, fn) || !calledInsideRange(scope, fn) {
			return nil
		}
		params := paramObjects(typedFuncDecl{decl: fn, info: scope.info})
		var failure ast.Node
		for _, stmt := range fn.Body.List {
			check, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}
			foundSlot, errSlot := ifReturnSlots(check.Body)
			if failure == nil && foundSlot != nil && isFalseIdent(ast.Unparen(foundSlot)) && errSlot != nil && !isNilIdent(errSlot) {
				failure = check
				continue
			}
			if failure == nil || !isTrueIdent(foundSlot) || errSlot == nil || !isNilIdent(errSlot) {
				continue
			}
			if matchesSoughtParam(scope.info, check.Cond, params) {
				return []funcFinding{{node: check, message: "Whether the element is the one sought is decided only after a check above fails the lookup — one broken element nobody asked for fails every lookup"}}
			}
		}
		return nil
	}
	return r
}

// foundAndErrorResults reports results ending in (bool, error).
func foundAndErrorResults(info *types.Info, fn *ast.FuncDecl) bool {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok {
		return false
	}
	results := sig.Results()
	if results.Len() < 2 {
		return false
	}
	last, found := results.At(results.Len()-1).Type(), results.At(results.Len()-2).Type()
	basic, ok := found.Underlying().(*types.Basic)
	return types.Identical(last, types.Universe.Lookup("error").Type()) && ok && basic.Kind() == types.Bool
}

// calledInsideRange reports a function called from the body of a range
// loop.
func calledInsideRange(scope funcScope, fn *ast.FuncDecl) bool {
	obj, ok := scope.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	for _, site := range scope.callers[obj.Origin()] {
		inside := false
		ast.Inspect(site.caller.decl.Body, func(n ast.Node) bool {
			if loop, ok := n.(*ast.RangeStmt); ok && loop.Body.Pos() <= site.call.Pos() && site.call.End() <= loop.Body.End() {
				inside = true
			}
			return !inside
		})
		if inside {
			return true
		}
	}
	return false
}

// ifReturnSlots returns the found and error results of a block ending in a
// return.
func ifReturnSlots(body *ast.BlockStmt) (found, err ast.Expr) {
	if len(body.List) == 0 {
		return nil, nil
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) < 2 {
		return nil, nil
	}
	return ret.Results[len(ret.Results)-2], ret.Results[len(ret.Results)-1]
}

// isTrueIdent reports the identifier true.
func isTrueIdent(expr ast.Expr) bool {
	return expr != nil && isIdentNamed(ast.Unparen(expr), "true")
}

// matchesSoughtParam reports a condition comparing a parameter: x == p,
// strings.EqualFold(x, p).
func matchesSoughtParam(info *types.Info, cond ast.Expr, params []*types.Var) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		var operands []ast.Expr
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op == token.EQL {
				operands = []ast.Expr{node.X, node.Y}
			}
		case *ast.CallExpr:
			if isPkgFunc(info, node, "strings", "EqualFold") {
				operands = node.Args
			}
		}
		for _, operand := range operands {
			if slices.ContainsFunc(params, func(p *types.Var) bool { return p != nil && isIdentOf(info, operand, p) }) {
				found = true
			}
		}
		return !found
	})
	return found
}

// keyFieldNames are the fields that identify an entry of a definition list.
var keyFieldNames = map[string]bool{"Name": true, "Key": true, "ID": true, "Id": true, "Code": true, "Label": true, "Slug": true}

// DuplicateKeyInDefinitionListRule reports a definition list holding two
// entries with the same name, key or label.
type DuplicateKeyInDefinitionListRule struct {
	*rules.BaseRule
}

// NewDuplicateKeyInDefinitionListRule creates
// duplicate-key-in-definition-list: a slice of struct literals with two
// entries carrying the same name, key or label. A form shows two fields
// under one label, a lookup by the key finds only the first:
//
//	{Label: "Bank Branch Code", Name: "corporateBranchCode"},
//	{Label: "Bank Branch Code", Name: "branchCode"},
func NewDuplicateKeyInDefinitionListRule() *DuplicateKeyInDefinitionListRule {
	return &DuplicateKeyInDefinitionListRule{BaseRule: rules.NewBaseRule(
		"duplicate-key-in-definition-list",
		"patterns",
		"Detects two entries of a definition list with the same name, key or label — a form shows two fields under one label, a lookup finds only the first",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the repeated keys of the file's definition lists.
func (r *DuplicateKeyInDefinitionListRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil || ctx.IsTestFile() {
		return nil
	}
	var out []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || len(lit.Elts) < 2 {
			return true
		}
		seen := make(map[string]bool)
		for _, elt := range lit.Elts {
			entry, ok := ast.Unparen(elt).(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, field := range entry.Elts {
				kv, ok := field.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || !keyFieldNames[key.Name] {
					continue
				}
				value, ok := stringLiteral(kv.Value)
				if !ok || value == "" {
					continue
				}
				id := key.Name + "\x00" + value
				if !seen[id] {
					seen[id] = true
					continue
				}
				line := ctx.LineFor(kv)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line, "Another entry of this list already has "+key.Name+" \""+value+"\" — a form shows two fields under one label, a lookup by it finds only the first")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Remove the repeated entry or give it its own " + key.Name)
				out = append(out, v)
			}
		}
		return true
	})
	return out
}
