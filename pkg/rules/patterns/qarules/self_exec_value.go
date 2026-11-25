package qarules

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// The value a start gives a helper child decides which branch the child
// takes. Beyond constants the analysis knows a value that is never empty -
// a temporary directory, a path joined from a part that is not empty, a
// number - the parameter every call of a function passes the same constant,
// and the field of a table of constants a range walks.

// selfExecElemKey is an element of a slice variable at an index the body
// names, commands[i]: the key of the variable and the index.
type selfExecElemKey [2]any

// selfExecTarget returns the key of what an assignment writes: a variable,
// or an element of one at a named index.
func selfExecTarget(b *selfExecBody, expr ast.Expr) any {
	if key := b.key(expr); key != nil {
		return key
	}
	elem, ok := ast.Unparen(expr).(*ast.IndexExpr)
	if !ok {
		return nil
	}
	base := b.key(elem.X)
	if base == nil {
		return nil
	}
	switch index := ast.Unparen(elem.Index).(type) {
	case *ast.Ident:
		return selfExecElemKey{base, index.Name}
	case *ast.BasicLit:
		return selfExecElemKey{base, index.Value}
	}
	return nil
}

// nonEmptyCall reports a call whose string result is never empty.
func (a *selfExecAnalysis) nonEmptyCall(b *selfExecBody, call *ast.CallExpr, depth int) bool {
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "TempDir" && len(call.Args) == 0 && selfExecTestingValue(b, sel.X) {
		return true
	}
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "os"); ok && name == "TempDir" {
		return true
	}
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "strconv"); ok {
		switch name {
		case "Itoa", "FormatInt", "FormatUint", "Quote":
			return true
		}
	}
	for _, pkg := range []string{"path/filepath", "path"} {
		if name, ok := patternkit.PackageFuncName(b.file, b.info, call, pkg); ok && name == "Join" {
			// Join drops only empty elements: one that is not empty stays.
			return slices.ContainsFunc(call.Args, func(arg ast.Expr) bool {
				part := a.str(b, arg, depth+1)
				return part.s != "" || part.more
			})
		}
	}
	return false
}

// selfExecTestingValue reports the value of a test, benchmark or fuzz
// target: its TempDir is never empty.
func selfExecTestingValue(b *selfExecBody, x ast.Expr) bool {
	if b.info != nil {
		t := b.info.TypeOf(x)
		if t == nil {
			return false
		}
		if ptr, ok := t.(*types.Pointer); ok {
			t = ptr.Elem()
		}
		named, ok := t.(*types.Named)
		return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing"
	}
	id, ok := ast.Unparen(x).(*ast.Ident)
	if !ok || b.decl == nil {
		return false
	}
	local := b.localAt(id.Name, id.Pos())
	if local == nil {
		return false
	}
	field, ok := local.decl.(*ast.Field)
	if !ok {
		return false
	}
	typ := field.Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	sel, ok := typ.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && selfExecImports(b.file, pkg.Name, "testing") && patternkit.TestingHandleType(sel.Sel.Name)
}

// selfExecImports reports that a file names an import path by a qualifier.
func selfExecImports(file *ast.File, qualifier, importPath string) bool {
	if file == nil {
		return false
	}
	for _, imp := range patternkit.FileImports(file) {
		if imp.Name == qualifier && imp.Path == importPath {
			return true
		}
	}
	return false
}

// selfExecCallSite is a call of a function in a body.
type selfExecCallSite struct {
	body *selfExecBody
	call *ast.CallExpr
}

// selfExecParam is a parameter of a function.
type selfExecParam struct {
	body *selfExecBody
	key  any
}

// selfExecParamValue is the constant every call passes a parameter.
type selfExecParamValue struct {
	s  string
	ok bool
}

// paramConstant returns the string constant every call of a function
// passes a parameter: the function is called somewhere and used nowhere
// but in calls, and every call passes the same constant.
func (a *selfExecAnalysis) paramConstant(b *selfExecBody, key any) (string, bool) {
	param := selfExecParam{body: b, key: key}
	if value, ok := a.paramConst[param]; ok {
		return value.s, value.ok
	}
	a.paramConst[param] = selfExecParamValue{}
	i := slices.Index(b.params, key)
	if i < 0 || b.decl == nil || b.decl.Recv != nil || (b.variadic && i == len(b.params)-1) {
		return "", false
	}
	sites := a.callSitesOf(b)
	if len(sites) == 0 || a.escaped[b] {
		return "", false
	}
	value := ""
	for n, site := range sites {
		if site.call.Ellipsis.IsValid() || i >= len(site.call.Args) {
			return "", false
		}
		s, ok := selfExecString(site.body, site.call.Args[i])
		if !ok || (n > 0 && s != value) {
			return "", false
		}
		value = s
	}
	a.paramConst[param] = selfExecParamValue{s: value, ok: true}
	return value, true
}

// callSitesOf returns the calls of a function, and finds once the
// functions used other than by a call: a name of a function that appears
// anywhere but as the callee of a call - even one that names something
// else - counts.
func (a *selfExecAnalysis) callSitesOf(b *selfExecBody) []selfExecCallSite {
	if a.callSites != nil {
		return a.callSites[b]
	}
	a.callSites, a.escaped = map[*selfExecBody][]selfExecCallSite{}, map[*selfExecBody]bool{}
	used := map[string]bool{}
	for _, body := range slices.Concat(a.bodies, a.pkgLevel) {
		var roots []ast.Node
		if body.decl != nil {
			roots = append(roots, body.decl.Body)
		}
		for _, assign := range a.facts(body).assigns {
			for _, rhs := range assign.rhs {
				roots = append(roots, rhs)
			}
		}
		for _, root := range roots {
			callees := map[*ast.Ident]bool{}
			ast.Inspect(root, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					switch fun := ast.Unparen(node.Fun).(type) {
					case *ast.Ident:
						callees[fun] = true
					case *ast.SelectorExpr:
						callees[fun.Sel] = true
					}
					for _, callee := range a.resolve(body, node) {
						a.callSites[callee] = append(a.callSites[callee], selfExecCallSite{body: body, call: node})
					}
				case *ast.Ident:
					if !callees[node] {
						used[node.Name] = true
					}
				}
				return true
			})
		}
	}
	for _, body := range a.bodies {
		if body.decl != nil && used[body.decl.Name.Name] {
			a.escaped[body] = true
		}
	}
	return a.callSites[b]
}

// tableField returns what a field of a range value may hold where the
// range walks a literal table: the common prefix of its constants, and
// whether every one is longer.
func (a *selfExecAnalysis) tableField(b *selfExecBody, sel *ast.SelectorExpr) selfExecStr {
	x, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok || b.decl == nil {
		return selfExecStr{}
	}
	key := b.key(x)
	if key == nil {
		return selfExecStr{}
	}
	if _, _, count := a.assignedAt(b, key); count != 0 {
		return selfExecStr{}
	}
	lit := selfExecRangeOver(b, key)
	if lit == nil || lit.Incomplete {
		return selfExecStr{}
	}
	var values []string
	for _, elt := range lit.Elts {
		row, ok := ast.Unparen(elt).(*ast.CompositeLit)
		if !ok {
			return selfExecStr{}
		}
		value, ok := selfExecRowField(b, lit, row, sel.Sel.Name)
		if !ok {
			return selfExecStr{}
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return selfExecStr{}
	}
	prefix := values[0]
	for _, value := range values[1:] {
		for !strings.HasPrefix(value, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	complete, more := true, true
	for _, value := range values {
		complete = complete && value == prefix
		more = more && len(value) > len(prefix)
	}
	return selfExecStr{s: prefix, complete: complete, more: more}
}

// selfExecRowField returns the constant a row of a table gives a field, by
// its key or by its place in the struct type the table spells out.
func selfExecRowField(b *selfExecBody, table, row *ast.CompositeLit, field string) (string, bool) {
	for _, elt := range row.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
				return selfExecString(b, kv.Value)
			}
		}
	}
	array, ok := table.Type.(*ast.ArrayType)
	if !ok {
		return "", false
	}
	st, ok := array.Elt.(*ast.StructType)
	if !ok {
		return "", false
	}
	i := 0
	for _, f := range st.Fields.List {
		for _, name := range f.Names {
			if name.Name == field && i < len(row.Elts) {
				if _, keyed := row.Elts[i].(*ast.KeyValueExpr); !keyed {
					return selfExecString(b, row.Elts[i])
				}
			}
			i++
		}
	}
	return "", false
}

// isParam reports a name of a function body that names one of its
// parameters: in a test file the declaration in scope tells.
func (a *selfExecAnalysis) isParam(b *selfExecBody, id *ast.Ident, key any) bool {
	if b.info != nil || b.decl == nil {
		return slices.Contains(b.params, key)
	}
	local := b.localAt(id.Name, id.Pos())
	if local == nil {
		return false
	}
	field, ok := local.decl.(*ast.Field)
	return ok && b.decl.Type.Params != nil && slices.Contains(b.decl.Type.Params.List, field)
}

// localAssign returns the last assignment of the variable a name of a body
// names, the index of the variable in it and the number of the
// assignments, as localAssigns finds them.
func (a *selfExecAnalysis) localAssign(b *selfExecBody, id *ast.Ident, key any) (selfExecAssign, int, int) {
	found := a.localAssigns(b, id, key)
	if len(found) == 0 {
		return selfExecAssign{}, 0, 0
	}
	last := found[len(found)-1]
	return last.assign, last.index, len(found)
}

// localOf returns the variable an assigned name of a test file body is: the
// one the statement declares, or the one in scope.
func (b *selfExecBody) localOf(assign selfExecAssign, name *ast.Ident) *selfExecLocal {
	declares := assign.decl != nil
	if stmt, ok := assign.decl.(*ast.AssignStmt); ok {
		declares = stmt.Tok == token.DEFINE
	}
	if declares {
		for i := range b.scopes() {
			if local := &b.locals[i]; local.decl == assign.decl && local.name == name.Name {
				return local
			}
		}
	}
	return b.localAt(name.Name, name.Pos())
}

// identStr says what a name may hold: a parameter the constants its
// callers pass, a variable what each of its assignments may hold, the
// value of a range over a literal one of its elements.
func (a *selfExecAnalysis) identStr(b *selfExecBody, id *ast.Ident, depth int) selfExecStr {
	key := b.key(id)
	if key == nil {
		return selfExecStr{}
	}
	if a.isParam(b, id, key) {
		values, ok := a.paramValues(b, key)
		if !ok {
			return a.paramStr(b, key, depth)
		}
		return selfExecMergeValues(values)
	}
	assigns := a.localAssigns(b, id, key)
	if len(assigns) == 0 {
		return a.rangeStr(b, id, key)
	}
	var merged selfExecStr
	for n, at := range assigns {
		value := selfExecAssigned(at.assign, at.index)
		if value == nil {
			return selfExecStr{}
		}
		s := a.str(b, value, depth+1)
		if a.checkedSuccess(b, at) {
			s = selfExecStr{more: true}
		}
		if n == 0 {
			merged = s
		} else {
			merged = selfExecMerge(merged, s)
		}
	}
	return merged
}

// paramValues returns the constants a parameter may hold: those the path
// to the node gives it, or the one every call passes.
func (a *selfExecAnalysis) paramValues(b *selfExecBody, key any) ([]string, bool) {
	if i := slices.Index(b.params, key); i >= 0 {
		if values, ok := a.bound[b][strconv.Itoa(i)]; ok {
			return values, true
		}
	}
	value, ok := a.paramConstant(b, key)
	return []string{value}, ok
}

// rangeStr says what the value of a range over a literal of constants may
// hold.
func (a *selfExecAnalysis) rangeStr(b *selfExecBody, id *ast.Ident, key any) selfExecStr {
	var lit *ast.CompositeLit
	if b.info == nil && b.decl != nil {
		local := b.localAt(id.Name, id.Pos())
		if local == nil {
			return selfExecStr{}
		}
		rng, ok := local.decl.(*ast.RangeStmt)
		if !ok || rng.Value == nil {
			return selfExecStr{}
		}
		if value, ok := rng.Value.(*ast.Ident); !ok || value.Name != id.Name {
			return selfExecStr{}
		}
		lit, _ = ast.Unparen(rng.X).(*ast.CompositeLit)
	} else {
		lit = selfExecRangeOver(b, key)
	}
	if lit == nil || lit.Incomplete {
		return selfExecStr{}
	}
	var values []string
	for _, elt := range lit.Elts {
		value, ok := selfExecString(b, elt)
		if !ok {
			return selfExecStr{}
		}
		values = append(values, value)
	}
	return selfExecMergeValues(values)
}

// selfExecMergeValues says what one of the constants is.
func selfExecMergeValues(values []string) selfExecStr {
	if len(values) == 0 {
		return selfExecStr{}
	}
	merged := selfExecStr{s: values[0], complete: true}
	for _, value := range values[1:] {
		merged = selfExecMerge(merged, selfExecStr{s: value, complete: true})
	}
	return merged
}

// selfExecMerge says what one of two strings is: their common prefix,
// whole where both are the same whole string, and followed by more where
// each is longer than the prefix or followed by more.
func selfExecMerge(x, y selfExecStr) selfExecStr {
	prefix := x.s
	for !strings.HasPrefix(y.s, prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	if x.complete && y.complete && x.s == y.s {
		return x
	}
	longer := func(s selfExecStr) bool { return len(s.s) > len(prefix) || s.more }
	return selfExecStr{s: prefix, more: longer(x) && longer(y)}
}

// selfExecAssignAt is an assignment of a variable and its index there.
type selfExecAssignAt struct {
	assign selfExecAssign
	index  int
}

// localAssigns returns the assignments of the variable a name of a body
// names. In a test file the variable is the declaration in scope at the
// name, so another variable of the same name does not count; a name that
// names no local variable there has none.
func (a *selfExecAnalysis) localAssigns(b *selfExecBody, id *ast.Ident, key any) []selfExecAssignAt {
	var found []selfExecAssignAt
	if b.info != nil || b.decl == nil {
		for _, assign := range a.facts(b).assigns {
			for i, target := range assign.lhs {
				if target == key && !selfExecAppendsTo(b, assign, i, key) {
					found = append(found, selfExecAssignAt{assign, i})
				}
			}
		}
		return found
	}
	local := b.localAt(id.Name, id.Pos())
	if local == nil {
		return nil
	}
	if _, param := local.decl.(*ast.Field); param {
		return nil
	}
	for _, assign := range a.facts(b).assigns {
		for i, target := range assign.targets {
			name, ok := ast.Unparen(target).(*ast.Ident)
			if ok && name.Name == id.Name && !selfExecAppendsTo(b, assign, i, key) && b.localOf(assign, name) == local {
				found = append(found, selfExecAssignAt{assign, i})
			}
		}
	}
	return found
}

// selfExecStringParams returns the keys of the string parameters of a
// body.
func selfExecStringParams(b *selfExecBody) []string {
	var keys []string
	i := 0
	for _, field := range b.decl.Type.Params.List {
		n := max(len(field.Names), 1)
		if id, ok := field.Type.(*ast.Ident); ok && id.Name == "string" {
			for j := range n {
				keys = append(keys, strconv.Itoa(i+j))
			}
		}
		i += n
	}
	return keys
}

// bind gives the parameters of a body the constants they hold until the
// returned function puts back what they held before.
func (a *selfExecAnalysis) bind(b *selfExecBody, known map[string][]string) func() {
	if a.bound == nil {
		a.bound = map[*selfExecBody]map[string][]string{}
	}
	old, had := a.bound[b]
	a.bound[b] = known
	return func() {
		if had {
			a.bound[b] = old
		} else {
			delete(a.bound, b)
		}
	}
}

// bindCall gives the string parameters of a callee the constants the
// arguments of a call hold.
func (a *selfExecAnalysis) bindCall(b *selfExecBody, call *ast.CallExpr, callee *selfExecBody) func() {
	if a.boundBy == nil {
		a.boundBy = map[*selfExecBody]selfExecCallSite{}
	}
	site, had := a.boundBy[callee]
	a.boundBy[callee] = selfExecCallSite{body: b, call: call}
	known := map[string][]string{}
	for i, arg := range call.Args {
		if call.Ellipsis.IsValid() && i == len(call.Args)-1 {
			break
		}
		if value := a.str(b, arg, 0); value.complete {
			known[strconv.Itoa(i)] = []string{value.s}
		}
	}
	unbind := a.bind(callee, known)
	return func() {
		unbind()
		if had {
			a.boundBy[callee] = site
		} else {
			delete(a.boundBy, callee)
		}
	}
}

// boundSlice returns the elements the call being followed into a body gives
// a slice parameter: the argument, or the arguments a variadic one
// gathers.
func (a *selfExecAnalysis) boundSlice(b *selfExecBody, key any, depth int, unordered bool) (selfExecArgs, bool) {
	site, ok := a.boundBy[b]
	i := slices.Index(b.params, key)
	if !ok || i < 0 {
		return selfExecArgs{}, false
	}
	args := site.call.Args
	if b.variadic && i == len(b.params)-1 {
		if i > len(args) {
			return selfExecArgs{}, false
		}
		return a.argListOf(site.body, args[i:], site.call.Ellipsis.IsValid(), depth+1, unordered), true
	}
	if i >= len(args) || site.call.Ellipsis.IsValid() {
		return selfExecArgs{}, false
	}
	return a.sliceElems(site.body, args[i], depth+1, unordered), true
}

// selfExecGuard is a span of a body that runs only where a variable of the
// environment holds a value.
type selfExecGuard struct {
	from, to    token.Pos
	name, value string
}

// guards returns the spans of a body each branch on a variable of the
// environment takes: the body of an if whose condition requires
// os.Getenv(name) == value, a case of a switch that does. A body that sets
// the variable itself, or one it cannot name, has none on it.
func (a *selfExecAnalysis) guards(b *selfExecBody) []selfExecGuard {
	if guards, ok := a.guardsOf[b]; ok {
		return guards
	}
	var guards []selfExecGuard
	if b.decl != nil {
		add := func(cond ast.Expr, from, to token.Pos) {
			for _, term := range selfExecConjuncts(cond) {
				if name, value, ok := selfExecEnvEquals(b, term); ok {
					guards = append(guards, selfExecGuard{from: from, to: to, name: name, value: value})
				}
			}
		}
		ast.Inspect(b.decl.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.IfStmt:
				add(node.Cond, node.Body.Pos(), node.Body.End())
			case *ast.SwitchStmt:
				name, tagged := selfExecEnvRead(b, node.Tag)
				for _, item := range node.Body.List {
					clause, ok := item.(*ast.CaseClause)
					if !ok || len(clause.List) != 1 || selfExecFallsInto(node, clause) {
						continue
					}
					if node.Tag == nil {
						add(clause.List[0], clause.Colon, clause.End())
					} else if value, ok := selfExecString(b, clause.List[0]); ok && tagged {
						guards = append(guards, selfExecGuard{from: clause.Colon, to: clause.End(), name: name, value: value})
					}
				}
			}
			return true
		})
		guards = slices.DeleteFunc(guards, func(g selfExecGuard) bool { return a.setsEnvIn(b, g.name) })
	}
	if a.guardsOf == nil {
		a.guardsOf = map[*selfExecBody][]selfExecGuard{}
	}
	a.guardsOf[b] = guards
	return guards
}

// selfExecFallsInto reports a clause the clause before it falls through to.
func selfExecFallsInto(stmt *ast.SwitchStmt, clause *ast.CaseClause) bool {
	i := slices.Index(stmt.Body.List, ast.Stmt(clause))
	if i <= 0 {
		return false
	}
	before, ok := stmt.Body.List[i-1].(*ast.CaseClause)
	return ok && selfExecFallsThrough(before)
}

// setsEnvIn reports a body that sets or unsets a variable of the
// environment by that name or by one it cannot tell.
func (a *selfExecAnalysis) setsEnvIn(b *selfExecBody, name string) bool {
	for _, call := range a.facts(b).calls {
		fn, ok := patternkit.PackageFuncName(b.file, b.info, call, "os")
		if !ok || (fn != "Setenv" && fn != "Unsetenv" && fn != "Clearenv") {
			continue
		}
		if len(call.Args) == 0 {
			return true
		}
		if set, ok := selfExecString(b, call.Args[0]); ok {
			if set == name {
				return true
			}
			continue
		}
		if keys, ok := selfExecRangeKeys(b, call.Args[0]); !ok || slices.Contains(keys, name) {
			return true
		}
	}
	return false
}

// selfExecRangeKeys returns the constant keys a variable takes as the key
// of the range over a map literal around it.
func selfExecRangeKeys(b *selfExecBody, expr ast.Expr) ([]string, bool) {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok || b.decl == nil {
		return nil, false
	}
	var rng *ast.RangeStmt
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		node, ok := n.(*ast.RangeStmt)
		if ok && node.Body.Pos() <= id.Pos() && id.End() <= node.Body.End() {
			if key, ok := node.Key.(*ast.Ident); ok && key.Name == id.Name && node.Tok == token.DEFINE {
				rng = node
			}
		}
		return true
	})
	if rng == nil {
		return nil, false
	}
	lit, ok := ast.Unparen(rng.X).(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	if _, isMap := lit.Type.(*ast.MapType); !isMap {
		return nil, false
	}
	var keys []string
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, false
		}
		key, ok := selfExecString(b, kv.Key)
		if !ok {
			return nil, false
		}
		keys = append(keys, key)
	}
	return keys, true
}

// selfExecConjuncts returns the terms a condition requires all of.
func selfExecConjuncts(cond ast.Expr) []ast.Expr {
	if bin, ok := ast.Unparen(cond).(*ast.BinaryExpr); ok && bin.Op == token.LAND {
		return append(selfExecConjuncts(bin.X), selfExecConjuncts(bin.Y)...)
	}
	return []ast.Expr{cond}
}

// selfExecEnvEquals returns the variable and the value a comparison
// os.Getenv(name) == value requires.
func selfExecEnvEquals(b *selfExecBody, term ast.Expr) (string, string, bool) {
	bin, ok := ast.Unparen(term).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return "", "", false
	}
	for _, pair := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
		call, ok := ast.Unparen(pair[0]).(*ast.CallExpr)
		if !ok {
			continue
		}
		if fn, ok := patternkit.PackageFuncName(b.file, b.info, call, "os"); !ok || fn != "Getenv" {
			continue
		}
		name, ok := selfExecEnvRead(b, call)
		value, known := selfExecString(b, pair[1])
		if ok && known {
			return name, value, true
		}
	}
	return "", "", false
}

// guardedRun returns the mode of a call a body makes in a run: the run
// with the variables the branches around the call require, where the run
// does not tell them.
func (a *selfExecAnalysis) guardedRun(b *selfExecBody, mode string, pos token.Pos) string {
	run := a.run(mode)
	var refined *selfExecRun
	for _, g := range a.guards(b) {
		if pos < g.from || pos >= g.to {
			continue
		}
		if value, set := run.env[g.name]; (set && value.complete) || (!set && run.envClosed) {
			continue
		}
		if refined == nil {
			refined = &selfExecRun{env: maps.Clone(run.env), envClosed: run.envClosed, args: run.args, argsKnown: run.argsKnown}
		}
		refined.env[g.name] = selfExecStr{s: g.value, complete: true}
	}
	if refined == nil {
		return mode
	}
	key := refined.key()
	if _, ok := a.runs[key]; !ok {
		a.runs[key] = refined
	}
	return key
}

// paramStr says what a parameter may hold from what every call of its
// function passes it, where the function is used only in calls.
func (a *selfExecAnalysis) paramStr(b *selfExecBody, key any, depth int) selfExecStr {
	param := selfExecParam{body: b, key: key}
	i := slices.Index(b.params, key)
	if i < 0 || b.decl == nil || b.decl.Recv != nil || (b.variadic && i == len(b.params)-1) || a.following[param] || depth > 6 {
		return selfExecStr{}
	}
	sites := a.callSitesOf(b)
	if len(sites) == 0 || a.escaped[b] {
		return selfExecStr{}
	}
	if a.following == nil {
		a.following = map[selfExecParam]bool{}
	}
	a.following[param] = true
	defer delete(a.following, param)
	var merged selfExecStr
	for n, site := range sites {
		if site.call.Ellipsis.IsValid() || i >= len(site.call.Args) {
			return selfExecStr{}
		}
		s := a.str(site.body, site.call.Args[i], depth+1)
		if n == 0 {
			merged = s
		} else {
			merged = selfExecMerge(merged, s)
		}
	}
	return merged
}

// checkedSuccess reports the first variable of an assignment from a call
// of a function whose string result is never empty where its error is nil,
// when the statement after it leaves on the error the second one holds.
func (a *selfExecAnalysis) checkedSuccess(b *selfExecBody, at selfExecAssignAt) bool {
	stmt, ok := at.assign.decl.(*ast.AssignStmt)
	if !ok || at.index != 0 || len(stmt.Lhs) != 2 || len(stmt.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(stmt.Rhs[0]).(*ast.CallExpr)
	errName, named := stmt.Lhs[1].(*ast.Ident)
	if !ok || !named || errName.Name == "_" {
		return false
	}
	next, ok := selfExecNextStmt(b, stmt).(*ast.IfStmt)
	if !ok || next.Init != nil || !selfExecNotNil(next.Cond, errName.Name) || !selfExecTerminates(b, next.Body) {
		return false
	}
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "os"); ok && name == "MkdirTemp" {
		return true
	}
	callees := a.resolve(b, call)
	return len(callees) == 1 && a.succeedsNonEmpty(callees[0])
}

// selfExecNextStmt returns the statement after one in its block.
func selfExecNextStmt(b *selfExecBody, stmt ast.Stmt) ast.Stmt {
	if b.decl == nil {
		return nil
	}
	var next ast.Stmt
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		var list []ast.Stmt
		switch node := n.(type) {
		case *ast.BlockStmt:
			list = node.List
		case *ast.CaseClause:
			list = node.Body
		case *ast.CommClause:
			list = node.Body
		}
		if i := slices.Index(list, stmt); i >= 0 && i+1 < len(list) {
			next = list[i+1]
		}
		return next == nil
	})
	return next
}

// selfExecNotNil reports a condition name != nil.
func selfExecNotNil(cond ast.Expr, name string) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	x, okX := ast.Unparen(bin.X).(*ast.Ident)
	y, okY := ast.Unparen(bin.Y).(*ast.Ident)
	return okX && okY && x.Name == name && y.Name == "nil"
}

// succeedsNonEmpty reports a function of a string and an error whose every
// return has an error that is never nil or a string that is never empty.
func (a *selfExecAnalysis) succeedsNonEmpty(b *selfExecBody) bool {
	if ok, done := a.succeeds[b]; done {
		return ok
	}
	if a.succeeds == nil {
		a.succeeds = map[*selfExecBody]bool{}
	}
	a.succeeds[b] = false
	results := b.decl.Type.Results
	if results == nil || results.NumFields() != 2 || len(results.List[len(results.List)-1].Names) > 1 {
		return false
	}
	if id, ok := results.List[len(results.List)-1].Type.(*ast.Ident); !ok || id.Name != "error" {
		return false
	}
	ok := true
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) != 2 {
				ok = false
			} else if !a.neverNil(b, node.Results[1], node.Pos()) {
				value := a.str(b, node.Results[0], 0)
				ok = ok && (value.s != "" || value.more || a.tempName(b, node.Results[0]))
			}
		}
		return ok
	})
	a.succeeds[b] = ok
	return ok
}

// neverNil reports an error expression that is never nil: a new error,
// a join of one, or a variable a branch on it being non-nil returns.
func (a *selfExecAnalysis) neverNil(b *selfExecBody, expr ast.Expr, at token.Pos) bool {
	switch node := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		for _, pkg := range []string{"fmt", "errors"} {
			name, ok := patternkit.PackageFuncName(b.file, b.info, node, pkg)
			if !ok {
				continue
			}
			switch pkg + "." + name {
			case "fmt.Errorf", "errors.New":
				return true
			case "errors.Join":
				return slices.ContainsFunc(node.Args, func(arg ast.Expr) bool { return a.neverNil(b, arg, at) })
			}
		}
	case *ast.Ident:
		found := false
		ast.Inspect(b.decl.Body, func(n ast.Node) bool {
			if stmt, ok := n.(*ast.IfStmt); ok && stmt.Body.Pos() <= at && at < stmt.Body.End() && selfExecNotNil(stmt.Cond, node.Name) && stmt.Init == nil {
				found = found || !patternkit.AssignsNameIn(stmt.Body, node.Name)
			}
			return !found
		})
		return found
	}
	return false
}

// tempName reports f.Name() of a file os.CreateTemp gives: never empty.
func (a *selfExecAnalysis) tempName(b *selfExecBody, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Name" {
		return false
	}
	file, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	key := b.key(file)
	if key == nil {
		return false
	}
	value, count := a.assignedOnce(b, key)
	created, ok := value.(*ast.CallExpr)
	if count != 1 || !ok {
		return false
	}
	name, ok := patternkit.PackageFuncName(b.file, b.info, created, "os")
	return ok && name == "CreateTemp"
}
