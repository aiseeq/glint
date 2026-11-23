package gorules

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"golang.org/x/tools/go/types/typeutil"
)

// dedupWinner finds a call inside a map loop to a closure or a function of the
// same file that keeps only the first value written for a slot - it returns
// early when seen[slot] is taken, or writes only while it is free - when the
// loop hands it a value carrying the entry and a slot that is not the map key:
//
//	add := func(line int, text string) {
//	    if taken[line] { return }
//	    taken[line] = true
//	    out = append(out, Report{line, text})
//	}
//	for owner, lines := range owners {
//	    for _, line := range lines { add(line, "written by "+owner) }   // two owners of a line: the walk picks the name
//	}
//
// Sorting the result does not help: the order of what was kept is stable, but
// which of the entries sharing a slot was kept is the walk order, which Go
// randomizes. Not such a claim: a slot built from the map key or a local of the
// loop computed from it, which no two entries share; a value with nothing of
// the entry beyond the slot, directly or through a local, which reads the same
// whoever wins; a test that compares the slot with the value (keep the
// largest), which a comparison and not the walk decides; a test that does not
// stop the write, or writes the entry only while the slot is taken, where the
// last entry wins; a seen map the callee makes afresh on every call; and state
// of one entry or one iteration, which the other entries never reach.
func dedupWinner(fn *ast.FuncDecl, file *ast.File, rangeStmt *ast.RangeStmt, info *types.Info) (*ast.CallExpr, string, bool) {
	tainted := dedupTaint(rangeStmt)
	key, _ := rangeTargetNames(rangeStmt)
	keyed := keyTaint(rangeStmt, key)
	var (
		found  *ast.CallExpr
		callee string
	)
	inspectLoopBody(rangeStmt, info, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != nil || !callCarriesEntry(call, tainted) {
			return
		}
		target, ok := resolveDedupCallee(fn, file, call, info)
		if ok && target.keepsFirstEntry(fn, rangeStmt, key, keyed, tainted, info) {
			found, callee = call, types.ExprString(call.Fun)
		}
	})
	return found, callee, found != nil
}

// dedupTaint returns the names that carry the entry the loop is at: its key
// and value, the locals the body declares from them, and the variables of a
// nested walk over them (for _, h := range hits). One walk in source order is
// enough: a name is declared before it is read.
func dedupTaint(rangeStmt *ast.RangeStmt) map[string]bool {
	key, values := rangeTargetNames(rangeStmt)
	tainted := map[string]bool{}
	for _, name := range append([]string{key}, values...) {
		if name != "" {
			tainted[name] = true
		}
	}
	mark := func(expr ast.Expr) {
		if ident, ok := expr.(*ast.Ident); ok {
			tainted[ident.Name] = true
		}
	}
	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE && len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					if helpers.MentionsAnyName(node.Rhs[i], tainted) {
						mark(lhs)
					}
				}
			}
		case *ast.RangeStmt:
			if helpers.MentionsAnyName(node.X, tainted) {
				mark(node.Key)
				mark(node.Value)
			}
		}
		return true
	})
	return tainted
}

// keyTaint returns the loop key and the locals the body declares from it,
// p := dir + "/" + n: a slot built from any of them is unique per entry. A
// lookup by the key (v := m[k]) reads the value, which entries may share, and
// does not count.
func keyTaint(rangeStmt *ast.RangeStmt, key string) map[string]bool {
	keyed := map[string]bool{key: true}
	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" && mentionsOutsideIndex(assign.Rhs[i], keyed) {
				keyed[ident.Name] = true
			}
		}
		return true
	})
	return keyed
}

// mentionsOutsideIndex reports whether the expression reads one of the names
// other than as the index of a lookup.
func mentionsOutsideIndex(expr ast.Expr, names map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IndexExpr:
			found = found || mentionsOutsideIndex(node.X, names)
			return false
		case *ast.Ident:
			found = found || names[node.Name]
		}
		return !found
	})
	return found
}

// callCarriesEntry reports whether an argument or the receiver of the call
// reads the entry: a call given nothing of it has nothing of it to keep.
func callCarriesEntry(call *ast.CallExpr, tainted map[string]bool) bool {
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && helpers.MentionsAnyName(selector.X, tainted) {
		return true
	}
	return argsMention(call.Args, tainted)
}

// dedupCallee is the body a call runs, with the caller's expressions for its
// parameters and receiver.
type dedupCallee struct {
	// span holds what the callee declares: a name declared inside it lives
	// one call.
	span ast.Node
	body *ast.BlockStmt
	// bound maps a parameter or the receiver to what the caller passes: one
	// expression, or the arguments a variadic parameter collects.
	bound map[types.Object][]ast.Expr
	// derived maps a local of the callee to the parameters its value comes
	// from: line := at.Line carries at.
	derived map[types.Object]map[types.Object]bool
	// sources maps a local of the callee to the expressions assigned to it.
	sources map[types.Object][]ast.Expr
}

// resolveDedupCallee finds the body of a call to a closure the function binds
// to a local name, or to a function or method declared in the same file.
func resolveDedupCallee(fn *ast.FuncDecl, file *ast.File, call *ast.CallExpr, info *types.Info) (*dedupCallee, bool) {
	var c *dedupCallee
	if ident, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if v, ok := info.Uses[ident].(*types.Var); ok {
			if lit := closureOf(fn, v, info); lit != nil {
				c = &dedupCallee{span: lit, body: lit.Body}
				c.bind(lit.Type, nil, call, info)
			}
		}
	}
	if callee := typeutil.StaticCallee(info, call); c == nil && callee != nil && file != nil {
		callee = callee.Origin()
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if ok && funcDecl.Body != nil && info.Defs[funcDecl.Name] == callee {
				c = &dedupCallee{span: funcDecl, body: funcDecl.Body}
				c.bind(funcDecl.Type, funcDecl.Recv, call, info)
				break
			}
		}
	}
	if c == nil {
		return nil, false
	}
	c.derive(info)
	return c, true
}

// closureOf returns the function literal the function assigns to the local
// variable, when it assigns one.
func closureOf(fn *ast.FuncDecl, v *types.Var, info *types.Info) *ast.FuncLit {
	var lit *ast.FuncLit
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if lit != nil {
			return false
		}
		var names []*ast.Ident
		var values []ast.Expr
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				ident, _ := lhs.(*ast.Ident)
				names = append(names, ident)
			}
			values = node.Rhs
		case *ast.ValueSpec:
			names, values = node.Names, node.Values
		default:
			return true
		}
		if len(names) != len(values) {
			return true
		}
		for i, name := range names {
			if name != nil && info.ObjectOf(name) == v {
				if found, ok := ast.Unparen(values[i]).(*ast.FuncLit); ok {
					lit = found
				}
			}
		}
		return lit == nil
	})
	return lit
}

// bind maps the parameters and the receiver of the callee to the caller's
// arguments and receiver expression; a variadic parameter takes the rest of
// the arguments. Unnamed parameters stay unbound: Go names all parameters of a
// function or none, and the body cannot read an unnamed one.
func (c *dedupCallee) bind(fnType *ast.FuncType, recv *ast.FieldList, call *ast.CallExpr, info *types.Info) {
	c.bound = map[types.Object][]ast.Expr{}
	if recv != nil && len(recv.List) == 1 && len(recv.List[0].Names) == 1 {
		if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
			if obj := info.Defs[recv.List[0].Names[0]]; obj != nil {
				c.bound[obj] = []ast.Expr{selector.X}
			}
		}
	}
	i := 0
	for _, field := range fnType.Params.List {
		_, variadic := field.Type.(*ast.Ellipsis)
		for _, name := range field.Names {
			obj := info.Defs[name]
			switch {
			case obj == nil || i >= len(call.Args):
			case variadic:
				c.bound[obj] = call.Args[i:]
			default:
				c.bound[obj] = call.Args[i : i+1]
			}
			i++
		}
	}
}

// derive records, in source order, which parameters each local of the callee
// is computed from.
func (c *dedupCallee) derive(info *types.Info) {
	c.derived = map[types.Object]map[types.Object]bool{}
	c.sources = map[types.Object][]ast.Expr{}
	ast.Inspect(c.body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				c.flowInto(lhs, rhsFor(node, i), info)
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if i < len(node.Values) {
					c.flowInto(name, node.Values[i], info)
				}
			}
		case *ast.RangeStmt:
			c.flowInto(node.Key, node.X, info)
			c.flowInto(node.Value, node.X, info)
		}
		return true
	})
}

// rhsFor returns the value assigned to the i-th target: its own expression,
// or the one call or comma-ok expression that fills all targets.
func rhsFor(assign *ast.AssignStmt, i int) ast.Expr {
	if len(assign.Lhs) == len(assign.Rhs) {
		return assign.Rhs[i]
	}
	return assign.Rhs[0]
}

// flowInto adds the parameters of the source to a variable of the callee the
// source is assigned to.
func (c *dedupCallee) flowInto(target, source ast.Expr, info *types.Info) {
	ident, ok := target.(*ast.Ident)
	if !ok {
		return
	}
	obj := info.ObjectOf(ident)
	if !c.declares(obj) {
		return
	}
	c.sources[obj] = append(c.sources[obj], source)
	params := c.paramsIn(source, info)
	if len(params) == 0 {
		return
	}
	if c.derived[obj] == nil {
		c.derived[obj] = map[types.Object]bool{}
	}
	maps.Copy(c.derived[obj], params)
}

// keepsFirstEntry reports whether the callee guards a write on a slot, the
// call fills that slot from something other than the loop key, and the
// guarded write keeps more of the entry than the slot in state that outlives
// the function.
func (c *dedupCallee) keepsFirstEntry(fn *ast.FuncDecl, rangeStmt *ast.RangeStmt, key string, keyed, tainted map[string]bool, info *types.Info) bool {
	entry := c.entryParams(tainted)
	for _, guard := range c.guards(rangeStmt, key, info) {
		if c.slotOfKey(guard.slot.Index, keyed, info) {
			continue
		}
		// The seen map and the slot are what the guard may read; a value
		// read beside them - directly or through a local the init computed
		// (d := size - best[line]) - makes the test a comparison, not a claim.
		slot := chainsIn(guard.slot.Index)
		if c.readsEntryBeyond(guard.test.Cond, c.besideSeenMap(entry, guard.slot, info), slot, info) {
			continue
		}
		if c.keepsEntry(fn, guard, c.besideSlotValue(entry, guard.slot.Index, loopAliases(rangeStmt, info), info), slot, info) {
			return true
		}
	}
	return false
}

// besideSeenMap returns the entry parameters other than those the seen map is
// read through: ok in _, ok := f.seen[line] reports the slot of f's own map,
// not a value of f.
func (c *dedupCallee) besideSeenMap(entry map[types.Object]bool, slot *ast.IndexExpr, info *types.Info) map[types.Object]bool {
	seenMap := c.paramsIn(slot.X, info)
	beside := map[types.Object]bool{}
	for param := range entry {
		if !seenMap[param] {
			beside[param] = true
		}
	}
	return beside
}

// besideSlotValue returns the entry parameters other than those the caller
// fills with the very value the slot is: after p := n, adopt(p, n) keeps n,
// which is the slot, so whoever wins, the same value is kept. Only a slot that
// is a whole parameter counts: a slot of key.ID says nothing of key.Name.
func (c *dedupCallee) besideSlotValue(entry map[types.Object]bool, index ast.Expr, aliases map[types.Object]string, info *types.Info) map[types.Object]bool {
	spell := func(arg ast.Expr) string {
		if ident, ok := ast.Unparen(arg).(*ast.Ident); ok {
			if source, ok := aliases[info.Uses[ident]]; ok {
				return source
			}
		}
		return types.ExprString(arg)
	}
	slotValues := map[string]bool{}
	if ident, ok := ast.Unparen(index).(*ast.Ident); ok {
		for _, arg := range c.bound[info.Uses[ident]] {
			slotValues[spell(arg)] = true
		}
	}
	beside := map[types.Object]bool{}
	for param := range entry {
		same := true
		for _, arg := range c.bound[param] {
			same = same && slotValues[spell(arg)]
		}
		if !same {
			beside[param] = true
		}
	}
	return beside
}

// loopAliases returns the locals the loop body declares as a copy of another
// value (p := n) and assigns nowhere else, by how that value is spelled. An
// increment (p++) keeps p a function of n, so whoever wins under a slot of p
// keeps the same n, and does not count as a write.
func loopAliases(rangeStmt *ast.RangeStmt, info *types.Info) map[types.Object]string {
	aliases := map[types.Object]string{}
	writes := map[types.Object]int{}
	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			obj := info.ObjectOf(ident)
			writes[obj]++
			if info.Defs[ident] == obj && len(assign.Lhs) == len(assign.Rhs) {
				aliases[obj] = types.ExprString(assign.Rhs[i])
			}
		}
		return true
	})
	for obj, count := range writes {
		if count > 1 {
			delete(aliases, obj)
		}
	}
	return aliases
}

// dedupGuard is an if that tests a slot the callee also fills.
type dedupGuard struct {
	test *ast.IfStmt
	// slot is how the slot is spelled: taken[line].
	slot *ast.IndexExpr
	// marks are the statements that fill the slot.
	marks []ast.Node
}

// freeSpan returns where the statements that run while the slot is still
// free sit: the branch of the guard that fills the slot, or - after a guard
// whose branch leaves (return, continue, break) - the rest of the body. A
// guard whose taken branch only overwrites (t.again[slot] = name) lets the
// last entry win, and is no claim; one that neither leaves nor fills the slot
// in a branch keeps every entry.
func (g dedupGuard) freeSpan(body *ast.BlockStmt) (from, to token.Pos, ok bool) {
	within := func(branch ast.Node) bool {
		for _, mark := range g.marks {
			if mark.Pos() >= branch.Pos() && mark.End() <= branch.End() {
				return true
			}
		}
		return false
	}
	switch {
	case within(g.test.Body):
		return g.test.Body.Pos(), g.test.Body.End(), true
	case g.test.Else != nil && within(g.test.Else):
		return g.test.Else.Pos(), g.test.Else.End(), true
	case leaves(g.test.Body):
		return g.test.End(), body.End(), true
	}
	return token.NoPos, token.NoPos, false
}

// leaves reports whether a block ends with a return, continue or break.
func leaves(block *ast.BlockStmt) bool {
	if len(block.List) == 0 {
		return false
	}
	switch block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return true
	}
	return false
}

// guards returns the ifs that test seen[slot] - in the condition or in the
// comma-ok init - for a slot the callee also assigns. The seen map must be
// one the entries share: one the callee declares starts empty on every call,
// and one of the entry - picked by the loop key, a field of the entry, a local
// of one iteration - is filled by that entry alone.
func (c *dedupCallee) guards(rangeStmt *ast.RangeStmt, key string, info *types.Info) []dedupGuard {
	var guards []dedupGuard
	ast.Inspect(c.body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		for _, part := range []ast.Node{ifStmt.Init, ifStmt.Cond} {
			if part == nil {
				continue
			}
			ast.Inspect(part, func(m ast.Node) bool {
				index, ok := m.(*ast.IndexExpr)
				if !ok || c.declaresRoot(index.X, info) || c.ofOneEntry(index.X, rangeStmt, key, info) {
					return true
				}
				if marks := c.slotMarks(index); len(marks) > 0 {
					guards = append(guards, dedupGuard{test: ifStmt, slot: index, marks: marks})
				}
				return true
			})
		}
		return true
	})
	return guards
}

// ofOneEntry reports whether the caller hands the callee a map of the entry the
// loop is at: dirs[dir].seen for the key dir, f.seen for the value f, or a map
// the iteration made.
func (c *dedupCallee) ofOneEntry(seenMap ast.Expr, rangeStmt *ast.RangeStmt, key string, info *types.Info) bool {
	root := assignedRoot(seenMap)
	if root == nil {
		return false
	}
	obj := info.ObjectOf(root)
	if args, ok := c.bound[obj]; ok {
		if len(args) != 1 {
			return false
		}
		if patternkit.Mentions(args[0], key) {
			return true
		}
		if root = assignedRoot(args[0]); root == nil {
			return false
		}
		obj = info.ObjectOf(root)
	}
	return obj != nil && obj.Pos() >= rangeStmt.Pos() && obj.Pos() < rangeStmt.Body.End()
}

// slotMarks returns the statements of the callee that write the slot it
// tested: assign it or count it up.
func (c *dedupCallee) slotMarks(index *ast.IndexExpr) []ast.Node {
	spelled := types.ExprString(index)
	var marks []ast.Node
	ast.Inspect(c.body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if types.ExprString(lhs) == spelled {
					marks = append(marks, node)
					break
				}
			}
		case *ast.IncDecStmt:
			if types.ExprString(node.X) == spelled {
				marks = append(marks, node)
			}
		}
		return true
	})
	return marks
}

// slotOfKey reports whether the caller builds the slot from the loop key or a
// local of the loop computed from it: a map holds a key once, so no two
// entries share such a slot.
func (c *dedupCallee) slotOfKey(index ast.Expr, keyed map[string]bool, info *types.Info) bool {
	for param := range c.paramsIn(index, info) {
		if argsMention(c.bound[param], keyed) {
			return true
		}
	}
	return false
}

// entryParams returns the parameters, the receiver included, that the caller
// fills from the entry.
func (c *dedupCallee) entryParams(tainted map[string]bool) map[types.Object]bool {
	entry := map[types.Object]bool{}
	for param, args := range c.bound {
		if argsMention(args, tainted) {
			entry[param] = true
		}
	}
	return entry
}

// keepsEntry reports whether a write the guard lets through only once per
// slot keeps more of the entry than the slot - in the value, or in an index
// of the target - in a target that outlives the function.
func (c *dedupCallee) keepsEntry(fn *ast.FuncDecl, guard dedupGuard, entry map[types.Object]bool, slot map[string]bool, info *types.Info) bool {
	from, to, ok := guard.freeSpan(c.body)
	if !ok {
		return false
	}
	kept := false
	ast.Inspect(c.body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if kept || !ok || assign.Pos() < from || assign.End() > to {
			return !kept
		}
		for i, lhs := range assign.Lhs {
			carries := c.readsEntryBeyond(rhsFor(assign, i), entry, slot, info) || c.indexCarries(lhs, entry, slot, info)
			if carries && c.targetLeaves(fn, lhs, info) {
				kept = true
			}
		}
		return !kept
	})
	return kept
}

// indexCarries reports whether an index of the target reads more of the
// entry than the slot: set[pair{line, owner}] = true keeps the owner as much
// as a value would.
func (c *dedupCallee) indexCarries(target ast.Expr, entry map[types.Object]bool, slot map[string]bool, info *types.Info) bool {
	carries := false
	ast.Inspect(target, func(n ast.Node) bool {
		if index, ok := n.(*ast.IndexExpr); ok && c.readsEntryBeyond(index.Index, entry, slot, info) {
			carries = true
		}
		return !carries
	})
	return carries
}

// readsEntryBeyond reports whether the expression reads the entry other than
// through the slot itself: text in Report{line, text} when the slot is line,
// f.Name when it is f.Line.
//
// A local is followed to what was assigned to it and checked the same way:
// e := &Entry{Path: p} keeps nothing beyond the slot p.
func (c *dedupCallee) readsEntryBeyond(node ast.Node, entry map[types.Object]bool, slot map[string]bool, info *types.Info) bool {
	return c.readsBeyond(node, entry, slot, info, map[types.Object]bool{})
}

func (c *dedupCallee) readsBeyond(node ast.Node, entry map[types.Object]bool, slot map[string]bool, info *types.Info, followed map[types.Object]bool) bool {
	found := false
	forEachChain(node, func(chain ast.Expr, root *ast.Ident) {
		if found || slot[types.ExprString(chain)] {
			return
		}
		obj := info.Uses[root]
		if entry[obj] {
			found = true
			return
		}
		if followed[obj] {
			return
		}
		followed[obj] = true
		for _, source := range c.sources[obj] {
			if c.readsBeyond(source, entry, slot, info, followed) {
				found = true
				return
			}
		}
	})
	return found
}

// chainsIn returns how the names and selector chains the expression reads are
// spelled.
func chainsIn(expr ast.Expr) map[string]bool {
	chains := map[string]bool{}
	forEachChain(expr, func(chain ast.Expr, _ *ast.Ident) {
		chains[types.ExprString(chain)] = true
	})
	return chains
}

// forEachChain calls visit with each outermost name or selector chain the
// node reads (line, at.Line, b.seen) and the name the chain starts from.
func forEachChain(node ast.Node, visit func(chain ast.Expr, root *ast.Ident)) {
	if node == nil {
		return
	}
	ast.Inspect(node, func(n ast.Node) bool {
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		root := chainRoot(expr)
		if root == nil {
			return true
		}
		visit(expr, root)
		return false
	})
}

// chainRoot returns the name a name or a chain of selections starts from, nil
// for any other expression.
func chainRoot(expr ast.Expr) *ast.Ident {
	switch node := expr.(type) {
	case *ast.Ident:
		return node
	case *ast.SelectorExpr:
		return chainRoot(node.X)
	}
	return nil
}

// targetLeaves reports whether a target the callee assigns outlives the
// caller: package state, the caller's parameters, receiver or results, or a
// local of the caller that escapes it. A local of the callee does not.
func (c *dedupCallee) targetLeaves(fn *ast.FuncDecl, target ast.Expr, info *types.Info) bool {
	root := assignedRoot(target)
	if root == nil {
		return false
	}
	obj := info.ObjectOf(root)
	if args, ok := c.bound[obj]; ok {
		if len(args) != 1 {
			return false
		}
		if root = assignedRoot(args[0]); root == nil {
			return false
		}
		obj = info.ObjectOf(root)
	} else if c.declares(obj) {
		return false
	}
	switch v := obj.(type) {
	case *types.PkgName:
		return true
	case *types.Var:
		if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
			return true
		}
		if v.Pos() >= fn.Pos() && v.Pos() < fn.Body.Lbrace {
			return true // declared in the caller's signature
		}
		return escapesFunction(fn, root.Name, info)
	}
	return false
}

// assignedRoot returns the variable an assignment target starts from: out in
// out, c.byPos[pos], *p or (*p).items.
func assignedRoot(expr ast.Expr) *ast.Ident {
	for {
		switch node := ast.Unparen(expr).(type) {
		case *ast.Ident:
			return node
		case *ast.SelectorExpr:
			expr = node.X
		case *ast.IndexExpr:
			expr = node.X
		case *ast.StarExpr:
			expr = node.X
		case *ast.UnaryExpr:
			if node.Op != token.AND {
				return nil
			}
			expr = node.X
		default:
			return nil
		}
	}
}

// declaresRoot reports whether the expression starts from a name the callee
// declares itself, its parameters left aside: such a map starts afresh on
// every call.
func (c *dedupCallee) declaresRoot(expr ast.Expr, info *types.Info) bool {
	root := assignedRoot(expr)
	if root == nil {
		return true
	}
	obj := info.ObjectOf(root)
	if _, ok := c.bound[obj]; ok {
		return false
	}
	return c.declares(obj)
}

// declares reports whether the object is declared inside the callee.
func (c *dedupCallee) declares(obj types.Object) bool {
	return obj != nil && obj.Pos() >= c.span.Pos() && obj.Pos() < c.span.End()
}

// paramsIn returns the parameters the expression reads directly or through a
// variable computed from them. An index picks an element and passes nothing
// of itself on: ok in _, ok := seen[line] does not carry line.
func (c *dedupCallee) paramsIn(expr ast.Node, info *types.Info) map[types.Object]bool {
	params := map[types.Object]bool{}
	if expr == nil {
		return params
	}
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IndexExpr:
			maps.Copy(params, c.paramsIn(node.X, info))
			return false
		case *ast.Ident:
			obj := info.Uses[node]
			if _, bound := c.bound[obj]; bound {
				params[obj] = true
			}
			maps.Copy(params, c.derived[obj])
		}
		return true
	})
	return params
}
