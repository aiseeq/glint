package qarules

import (
	"go/ast"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// A multi-call binary picks its function by name: a switch on a parameter or
// on its first element. A test that passes the name as a constant reaches
// only the case of that name, so the reach of the tests follows each body
// together with the names its callers give it.

// selfExecArgsKey is the key of the name in os.Args[1]: a helper child sets
// os.Args and calls main, which passes os.Args[1:] to the dispatcher.
const selfExecArgsKey = "os.Args[1]"

// selfExecMaxContexts bounds the sets of names a body is followed with in
// one run; past it the body is followed with none, as every case may run.
const selfExecMaxContexts = 16

// selfExecNode is a body reached with the constant names its parameters
// hold: "key=value" pairs joined by NUL, sorted, where the key is the index
// of a parameter ("1") or of its first element ("1[0]"); in a run of the
// test binary (mode, "" for the one go test starts), with the labels the
// path has set (covered, joined by NUL).
type selfExecNode struct {
	body    *selfExecBody
	names   string
	mode    string
	covered string
}

// selfExecSwitch is a switch of a body on a name: a constant or a key of the
// body's parameters.
type selfExecSwitch struct {
	stmt   *ast.SwitchStmt
	values []string
	key    string
}

// selfExecDispatch holds, per body, its switches on a name and the keys of
// its parameters a switch depends on, in the body or in a callee.
type selfExecDispatch struct {
	switches map[*selfExecBody][]selfExecSwitch
	needs    map[*selfExecBody]map[string]bool
}

// dispatch finds the switches on a name and, to a fixed point, the keys of
// the parameters they depend on through the calls.
func (a *selfExecAnalysis) dispatch() *selfExecDispatch {
	if a.dispatchInfo != nil {
		return a.dispatchInfo
	}
	d := &selfExecDispatch{switches: map[*selfExecBody][]selfExecSwitch{}, needs: map[*selfExecBody]map[string]bool{}}
	a.dispatchInfo = d
	for _, b := range a.bodies {
		ast.Inspect(b.decl.Body, func(n ast.Node) bool {
			if stmt, ok := n.(*ast.SwitchStmt); ok && stmt.Tag != nil {
				if values, key, ok := a.symbol(b, stmt.Tag, false, 0); ok {
					d.switches[b] = append(d.switches[b], selfExecSwitch{stmt: stmt, values: values, key: key})
					if key != "" {
						d.need(b, key)
					}
				}
			}
			return true
		})
	}
	for changed := true; changed; {
		changed = false
		for _, b := range a.bodies {
			for _, call := range a.facts(b).calls {
				for _, callee := range a.resolve(b, call) {
					changed = a.needFor(d, b, call, callee) || changed
				}
			}
		}
	}
	// A start gives its child what the parameters of its body hold: the
	// constants of the calls of the body, not followed further up, where
	// each test would make a context of its own.
	for _, b := range a.bodies {
		if len(a.points(b)) > 0 {
			for _, key := range selfExecStringParams(b) {
				d.need(b, key)
			}
		}
	}
	return d
}

// needFor adds the keys of a body's parameters that a switch of the callee
// depends on through the call; it reports a change.
func (a *selfExecAnalysis) needFor(d *selfExecDispatch, b *selfExecBody, call *ast.CallExpr, callee *selfExecBody) bool {
	changed := false
	for key := range d.needs[callee] {
		own := key
		if key != selfExecArgsKey {
			arg, first, ok := selfExecArgFor(call, callee, key)
			if !ok {
				continue
			}
			_, own, _ = a.symbol(b, arg, first, 0)
		} else if _, sets := selfExecSetArgs(b); sets {
			continue
		}
		if own != "" && !d.needs[b][own] {
			d.need(b, own)
			changed = true
		}
	}
	return changed
}

func (d *selfExecDispatch) need(b *selfExecBody, key string) {
	if d.needs[b] == nil {
		d.needs[b] = map[string]bool{}
	}
	d.needs[b][key] = true
}

// selfExecArgFor returns the argument of a call a key of the callee's
// parameters reads and whether the key is of its first element.
func selfExecArgFor(call *ast.CallExpr, callee *selfExecBody, key string) (ast.Expr, bool, bool) {
	index, first := strings.CutSuffix(key, "[0]")
	// A key that is not an index, os.Args[1], names no argument.
	if i, err := strconv.Atoi(index); err == nil && i < len(call.Args) && (!callee.variadic || i < len(callee.params)-1) {
		return call.Args[i], first, true
	}
	return nil, false, false
}

// calleeNames returns the names a call gives the callee: the constants its
// arguments hold where a switch of the callee depends on them.
func (a *selfExecAnalysis) calleeNames(node selfExecNode, call *ast.CallExpr, callee *selfExecBody) string {
	needs := a.dispatch().needs[callee]
	if len(needs) == 0 {
		return ""
	}
	known := selfExecNames(node.names)
	var pairs []string
	for _, key := range slices.Sorted(maps.Keys(needs)) {
		var values []string
		ok := false
		if key == selfExecArgsKey {
			values, ok = a.argsName(node, known)
		} else if arg, first, found := selfExecArgFor(call, callee, key); found {
			values, ok = a.constant(node.body, known, arg, first)
		}
		if ok {
			pairs = append(pairs, key+"="+strings.Join(values, "\x01"))
		}
	}
	return strings.Join(pairs, "\x00")
}

// argsName returns the names os.Args[1] holds for the calls of a body: the
// literal the body sets os.Args to, or what its callers set.
func (a *selfExecAnalysis) argsName(node selfExecNode, known map[string][]string) ([]string, bool) {
	elt, sets := selfExecSetArgs(node.body)
	if !sets {
		values, ok := known[selfExecArgsKey]
		return values, ok
	}
	if elt == nil {
		return nil, false
	}
	return a.constant(node.body, known, elt, false)
}

// selfExecSetArgs reports whether a body assigns os.Args and returns the
// second element when the only assignment is a literal that has one.
func selfExecSetArgs(b *selfExecBody) (ast.Expr, bool) {
	var elt ast.Expr
	count := 0
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Args" || !selfExecPackageMember(b, sel, "os") {
				continue
			}
			count++
			elt = nil
			if len(assign.Rhs) != len(assign.Lhs) {
				continue
			}
			if lit, ok := ast.Unparen(assign.Rhs[i]).(*ast.CompositeLit); ok && len(lit.Elts) > 1 {
				elt = lit.Elts[1]
			}
		}
		return true
	})
	if count != 1 {
		elt = nil
	}
	return elt, count > 0
}

// skipped returns a test of the calls a body with its names does not make:
// those in a case of a switch on a known name that is not the case of it,
// and in a test file the branches the run rules out.
func (a *selfExecAnalysis) skipped(node selfExecNode) func(ast.Node) bool {
	switches := a.dispatch().switches[node.body]
	spans := slices.Clone(a.modeSpans(node.body, node.mode, node.names))
	if len(spans) == 0 && node.names == "" && !slices.ContainsFunc(switches, func(s selfExecSwitch) bool { return s.key == "" }) {
		return func(ast.Node) bool { return false }
	}
	known := selfExecNames(node.names)
	for _, s := range switches {
		values, ok := s.values, s.key == ""
		if !ok {
			values, ok = known[s.key]
		}
		if ok {
			spans = append(spans, a.otherCases(node.body, known, s.stmt, values)...)
		}
	}
	return func(n ast.Node) bool {
		return slices.ContainsFunc(spans, func(span [2]token.Pos) bool { return n.Pos() >= span[0] && n.End() <= span[1] })
	}
}

// otherCases returns the spans of the clauses of a switch that run for none
// of the values - a clause a run clause falls through to runs too; none
// when a case is not a constant.
func (a *selfExecAnalysis) otherCases(b *selfExecBody, known map[string][]string, stmt *ast.SwitchStmt, values []string) [][2]token.Pos {
	matched := map[*ast.CaseClause]bool{}
	unmatched := slices.Clone(values)
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok {
			return nil
		}
		for _, expr := range clause.List {
			constants, ok := a.constant(b, known, expr, false)
			if !ok || len(constants) != 1 {
				return nil
			}
			if slices.Contains(unmatched, constants[0]) {
				matched[clause] = true
				unmatched = slices.DeleteFunc(unmatched, func(v string) bool { return v == constants[0] })
			}
		}
	}
	var spans [][2]token.Pos
	runs := false
	for _, item := range stmt.Body.List {
		clause, _ := item.(*ast.CaseClause)
		runs = runs || matched[clause] || (clause.List == nil && len(unmatched) > 0)
		if !runs {
			spans = append(spans, [2]token.Pos{clause.Pos(), clause.End()})
		}
		runs = runs && selfExecFallsThrough(clause)
	}
	return spans
}

// selfExecFallsThrough reports a clause that ends in fallthrough.
func selfExecFallsThrough(clause *ast.CaseClause) bool {
	_, falls := selfExecNoFallthrough(clause)
	return !falls
}

// constant returns the strings an expression - or its first element - may
// hold with the names of the body known.
func (a *selfExecAnalysis) constant(b *selfExecBody, known map[string][]string, expr ast.Expr, first bool) ([]string, bool) {
	values, key, ok := a.symbol(b, expr, first, 0)
	if !ok || key == "" {
		return values, ok
	}
	// A body that sets os.Args names what it set, not what its callers did;
	// set from os.Args itself, it names nothing the analysis knows.
	if elt, sets := selfExecSetArgs(b); key == selfExecArgsKey && sets {
		if elt == nil {
			return nil, false
		}
		values, key, ok = a.symbol(b, elt, false, 0)
		if !ok || key == "" {
			return values, ok
		}
		if key == selfExecArgsKey {
			return nil, false
		}
	}
	values, ok = known[key]
	return values, ok
}

// symbol says what an expression - or its first element when first is set
// - holds: the string constants it may be, or the key of a parameter of the
// body the body does not assign. A variable assigned once, a range variable
// over a literal and the result of a function literal are followed.
func (a *selfExecAnalysis) symbol(b *selfExecBody, expr ast.Expr, first bool, depth int) ([]string, string, bool) {
	if depth > 4 {
		return nil, "", false
	}
	expr = ast.Unparen(expr)
	if !first {
		if value, ok := selfExecString(b, expr); ok {
			return []string{value}, "", true
		}
	}
	switch node := expr.(type) {
	case *ast.Ident:
		return a.identSymbol(b, node, first, depth)
	case *ast.IndexExpr:
		lit, ok := node.Index.(*ast.BasicLit)
		if !first && ok && lit.Kind == token.INT && lit.Value == "1" && selfExecOSArgs(b, node.X) {
			return nil, selfExecArgsKey, true
		}
		if !first && ok && lit.Kind == token.INT && lit.Value == "0" {
			return a.symbol(b, node.X, true, depth+1)
		}
	case *ast.SliceExpr:
		lit, ok := node.Low.(*ast.BasicLit)
		if first && ok && lit.Kind == token.INT && lit.Value == "1" && selfExecOSArgs(b, node.X) {
			return nil, selfExecArgsKey, true
		}
	case *ast.CompositeLit:
		if first && len(node.Elts) > 0 {
			return a.symbol(b, node.Elts[0], false, depth+1)
		}
	case *ast.CallExpr:
		if from, ok := selfExecHeadFrom(b, node); first && ok {
			return a.symbol(b, from, true, depth+1)
		}
		if lit := a.funcLitOf(b, node.Fun); lit != nil {
			return a.resultSymbol(b, lit, first, depth)
		}
	}
	return nil, "", false
}

func (a *selfExecAnalysis) identSymbol(b *selfExecBody, id *ast.Ident, first bool, depth int) ([]string, string, bool) {
	key := b.key(id)
	if key == nil || (first && selfExecHeadWritten(b, key)) {
		return nil, "", false
	}
	value, assigned := a.assignedOnce(b, key)
	if i := slices.Index(b.params, key); i >= 0 {
		if assigned != 0 {
			return nil, "", false
		}
		if first {
			return nil, strconv.Itoa(i) + "[0]", true
		}
		return nil, strconv.Itoa(i), true
	}
	if assigned == 1 && value != nil {
		return a.symbol(b, value, first, depth+1)
	}
	if lit := selfExecRangeOver(b, key); assigned == 0 && lit != nil && !lit.Incomplete && !first {
		var values []string
		for _, elt := range lit.Elts {
			value, ok := selfExecString(b, elt)
			if !ok {
				return nil, "", false
			}
			values = append(values, value)
		}
		return values, "", len(values) > 0
	}
	return nil, "", false
}

// selfExecOSArgs reports whether an expression is os.Args.
func selfExecOSArgs(b *selfExecBody, expr ast.Expr) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Args" && selfExecPackageMember(b, sel, "os")
}

// funcLitOf returns the function literal a variable called as a function
// is assigned once.
func (a *selfExecAnalysis) funcLitOf(b *selfExecBody, fun ast.Expr) *ast.FuncLit {
	key := b.key(fun)
	if key == nil || slices.Contains(b.params, key) {
		return nil
	}
	value, assigned := a.assignedOnce(b, key)
	lit, _ := ast.Unparen(value).(*ast.FuncLit)
	if assigned != 1 {
		return nil
	}
	return lit
}

// resultSymbol says what every return of a function literal gives as its
// first result: the union of the constants, when each gives constants.
func (a *selfExecAnalysis) resultSymbol(b *selfExecBody, lit *ast.FuncLit, first bool, depth int) ([]string, string, bool) {
	var values []string
	ok := true
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) == 0 {
				ok = false
				return false
			}
			more, key, found := a.symbol(b, node.Results[0], first, depth+1)
			if !found || key != "" {
				ok = false
			}
			values = selfExecUnion(values, more)
		}
		return ok
	})
	return values, "", ok && len(values) > 0
}

// selfExecRangeOver returns the literal a range statement of the body walks
// with the variable as its value.
func selfExecRangeOver(b *selfExecBody, key any) *ast.CompositeLit {
	var found *ast.CompositeLit
	if b.decl == nil {
		return nil
	}
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		if rng, ok := n.(*ast.RangeStmt); ok && rng.Value != nil && b.key(rng.Value) == key {
			found, _ = ast.Unparen(rng.X).(*ast.CompositeLit)
		}
		return found == nil
	})
	return found
}

// selfExecHeadFrom returns the slice whose first element a call's result
// starts with: the first argument of append, or the appended slice when the
// first is empty; the slice slices.Clone copies.
func selfExecHeadFrom(b *selfExecBody, call *ast.CallExpr) (ast.Expr, bool) {
	if name, ok := patternkit.PackageFuncName(b.file, b.info, call, "slices"); ok && name == "Clone" && len(call.Args) == 1 {
		return call.Args[0], true
	}
	if fun, ok := call.Fun.(*ast.Ident); !ok || fun.Name != "append" || len(call.Args) == 0 {
		return nil, false
	}
	if call.Ellipsis.IsValid() && len(call.Args) == 2 && selfExecEmptySlice(call.Args[0]) {
		return call.Args[1], true
	}
	return call.Args[0], true
}

// selfExecEmptySlice reports a slice written with no elements: nil, an
// empty literal or a conversion of nil.
func selfExecEmptySlice(expr ast.Expr) bool {
	switch node := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return node.Name == "nil"
	case *ast.CompositeLit:
		return len(node.Elts) == 0
	case *ast.CallExpr:
		return len(node.Args) == 1 && selfExecEmptySlice(node.Args[0])
	}
	return false
}

// selfExecHeadWritten reports whether a body may write the first element of
// a slice variable: an assignment to an element at an index other than a
// constant above zero.
func selfExecHeadWritten(b *selfExecBody, key any) bool {
	// The functions that may write a package variable are not known here.
	if b.decl == nil {
		return true
	}
	written := false
	ast.Inspect(b.decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return !written
		}
		for _, lhs := range assign.Lhs {
			index, ok := ast.Unparen(lhs).(*ast.IndexExpr)
			if !ok || b.key(index.X) != key {
				continue
			}
			lit, ok := index.Index.(*ast.BasicLit)
			if !ok || lit.Kind != token.INT || lit.Value == "0" {
				written = true
			}
		}
		return !written
	})
	return written
}

// assignedOnce returns the value of the only assignment of a variable in a
// body and the number of its assignments; the value is nil when the
// assignment takes a later result of a call.
func (a *selfExecAnalysis) assignedOnce(b *selfExecBody, key any) (ast.Expr, int) {
	assign, i, count := a.assignedAt(b, key)
	if count == 0 {
		return nil, 0
	}
	return selfExecAssigned(assign, i), count
}

// assignedAt returns the last assignment of a variable in a body, the
// index of the variable in it and the number of the assignments; an append
// to the variable itself is not counted.
func (a *selfExecAnalysis) assignedAt(b *selfExecBody, key any) (selfExecAssign, int, int) {
	var found selfExecAssign
	index, count := 0, 0
	for _, assign := range a.facts(b).assigns {
		for i, target := range assign.lhs {
			if target == key && !selfExecAppendsTo(b, assign, i, key) {
				found, index = assign, i
				count++
			}
		}
	}
	return found, index, count
}

// selfExecAppendsTo reports an assignment that appends to the variable it
// assigns, x = append(x, ...): the first element stays.
func selfExecAppendsTo(b *selfExecBody, assign selfExecAssign, i int, key any) bool {
	call, ok := ast.Unparen(selfExecAssigned(assign, i)).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	fun, ok := call.Fun.(*ast.Ident)
	return ok && fun.Name == "append" && b.key(call.Args[0]) == key
}

// selfExecNames decodes the names of a node.
func selfExecNames(names string) map[string][]string {
	known := map[string][]string{}
	if names == "" {
		return known
	}
	for pair := range strings.SplitSeq(names, "\x00") {
		key, values, _ := strings.Cut(pair, "=")
		known[key] = strings.Split(values, "\x01")
	}
	return known
}
