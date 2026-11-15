package duplication

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"math"
	"math/bits"
	"slices"
	"strconv"
	"strings"
)

// nearCopyThreshold is the similarity from which a function is a copy of a
// library function that it does not match token for token: the larger of
// the share of the token sequence the two bodies have in common (2·LCS over
// both lengths) and the share of statements they have in common, order
// aside. A copy adapted to another element type (a pointer for an index, a
// field for the slice itself) or with independent statements swapped keeps
// most of the sequence or all of the statements; a function that only shares
// the shape of the code does not get there, as the measure on the consumer
// projects shows.
const nearCopyThreshold = 0.8

// minGoNearCopyTokens and minTSNearCopyTokens keep short bodies, which agree
// by chance, out of the near comparison; an exact Go copy of them is still
// found by its normalized body. A Go body prints a token per node and per its
// end, so 40 tokens are the 20 nodes of minimumDuplicateBodyNodes; 20
// TypeScript tokens are a function of two or three statements.
const (
	minGoNearCopyTokens = 40
	minTSNearCopyTokens = 20
)

// nearBody is the comparable form of a function body: its normalized token
// sequence, with every variable as one placeholder, the hashes of its
// statements, the anchors a copy keeps — the functions it calls, its
// operators, its literals and package-level values — and the roles of its
// statements. A function that calls another function, compares the other way
// or carries a value the library function does not is no copy of it however
// alike the rest is.
type nearBody struct {
	Tokens []string   `json:"tokens"`
	Stmts  []uint64   `json:"stmts"`
	Roles  []nearRole `json:"roles"`
	// Owners is the statement in Roles every token belongs to, -1 for none;
	// Vars the number of the variable a token is, nearAnchor for a literal
	// or the name of a called function, -1 for another token.
	Owners []int    `json:"owners"`
	Vars   []int    `json:"vars"`
	Calls  []string `json:"calls"`
	Ops    []string `json:"ops"`
	Lits   []string `json:"lits"`
	// Roots is the variable whose field a field variable in Vars reads.
	Roots map[int]int `json:"roots,omitempty"`
}

// field records that field reads a field of the variable root.
func (b *nearBodyBuilder) field(field, root int) {
	if b.body.Roots == nil {
		b.body.Roots = make(map[int]int)
	}
	b.body.Roots[field] = root
}

// nearAnchor marks a literal, the name of a called function, an operator or a
// jump in Vars.
const nearAnchor = -2

// nearFieldBase numbers the fields of the variables of a Go function, which
// stand in the roles as variables of their own, apart from the variables.
const nearFieldBase = 1 << 20

// isNearJump reports whether an anchor is a jump: return, break, continue,
// goto or fallthrough.
func isNearJump(tok nearToken) bool {
	if tok.vr != nearAnchor {
		return false
	}
	switch tok.text {
	case "(ReturnStmt", "return", "break", "continue":
		return true
	}
	return strings.HasPrefix(tok.text, "(BranchStmt")
}

// nearRole is a statement as sameRoles reads it: its shape, the hash of the
// statements that hold it and of its tokens with the variables, literals and
// called functions masked; the hash of its literals and called functions in
// their order; its variables in their order, numbered by their first
// appearance in the function as the exact key numbers them; and the
// statement that holds it, -1 for none.
type nearRole struct {
	Shape   uint64 `json:"s"`
	Anchors uint64 `json:"a"`
	Locals  []int  `json:"l,omitempty"`
	// Writes are the variables of Locals the statement writes.
	Writes []int `json:"w,omitempty"`
	// Parallel marks an assignment of several values at once, which reads
	// all of them before it writes any.
	Parallel bool `json:"t,omitempty"`
	// Fixed marks a statement nothing proves independent of the others: one
	// that calls a function, takes an address, sends or receives, makes a
	// closure or a subslice. It keeps its place among the statements.
	Fixed bool `json:"x,omitempty"`
	// Memory is how the statement uses what is reached through a pointer,
	// a slice, a map or, in TypeScript, an object: another name may reach
	// the same, so nothing proves a write there apart from a read.
	Memory memoryUse `json:"m,omitempty"`
	Parent int       `json:"p"`
}

// memoryUse is how a statement uses what is reached through a reference.
type memoryUse uint8

const (
	memoryNone memoryUse = iota
	memoryRead
	memoryWrite
)

// nearBodyBuilder collects a nearBody in one pass over the body: every token
// goes to the sequence and to the innermost statement that holds it, so the
// work is linear in the size of the function. Roles, Owners and Vars are
// collected for a detailed body only: a function of the project needs them
// when it comes near a library function, which few do.
type nearBodyBuilder struct {
	body     nearBody
	detailed bool
	open     []nearStmt
	// roleOf is the index in Roles of every statement opened, by its order
	// of opening, -1 for one with no tokens.
	roleOf []int
	calls  map[string]bool
	ops    map[string]bool
	lits   map[string]bool
}

type nearStmt struct {
	id    int
	hash  uint64
	role  nearRole
	count int
}

// Masks of the shape of a statement: a literal and a called function are
// compared by place in sameRoles, not by shape.
const (
	nearLiteralMask = "$lit"
	nearCallMask    = "$call"
)

func newNearBodyBuilder(detailed bool) *nearBodyBuilder {
	return &nearBodyBuilder{detailed: detailed, calls: map[string]bool{}, ops: map[string]bool{}, lits: map[string]bool{}}
}

// emit adds a token that is the same in every form of the body.
func (b *nearBodyBuilder) emit(tok string) { b.add(tok, tok, "", -1) }

// emitLocal adds the variable the function numbers num.
func (b *nearBodyBuilder) emitLocal(num int) { b.add("$L", "$L", "", num) }

// emitVar adds the variable the function numbers num, which the statement
// writes when write is set.
func (b *nearBodyBuilder) emitVar(num int, write bool) {
	b.emitLocal(num)
	if write && b.detailed && len(b.open) > 0 {
		top := &b.open[len(b.open)-1]
		top.role.Writes = append(top.role.Writes, num)
	}
}

// parallel marks the innermost open statement as an assignment of several
// values at once.
func (b *nearBodyBuilder) parallel() {
	if b.detailed && len(b.open) > 0 {
		b.open[len(b.open)-1].role.Parallel = true
	}
}

// touch notes that the innermost open statement reads, or writes, what is
// reached through a reference.
func (b *nearBodyBuilder) touch(use memoryUse) {
	if b.detailed && len(b.open) > 0 {
		top := &b.open[len(b.open)-1]
		top.role.Memory = max(top.role.Memory, use)
	}
}

// fix marks the innermost open statement as one that keeps its place.
func (b *nearBodyBuilder) fix() {
	if b.detailed && len(b.open) > 0 {
		b.open[len(b.open)-1].role.Fixed = true
	}
}

// emitAnchor adds a literal or the name of a called function: tok in the
// sequence, value among the anchors of its statement, mask in its shape.
func (b *nearBodyBuilder) emitAnchor(tok, value, mask string) { b.add(tok, mask, value, nearAnchor) }

func (b *nearBodyBuilder) add(tok, shape, anchor string, vr int) {
	b.body.Tokens = append(b.body.Tokens, tok)
	if len(b.open) == 0 {
		if b.detailed {
			b.body.Vars = append(b.body.Vars, vr)
			b.body.Owners = append(b.body.Owners, -1)
		}
		return
	}
	top := &b.open[len(b.open)-1]
	top.hash = fnvMix(top.hash, tok)
	top.count++
	if !b.detailed {
		return
	}
	b.body.Vars = append(b.body.Vars, vr)
	b.body.Owners = append(b.body.Owners, top.id)
	top.role.Shape = fnvMix(top.role.Shape, shape)
	if anchor != "" {
		top.role.Anchors = fnvMix(top.role.Anchors, anchor)
	}
	if vr >= 0 {
		top.role.Locals = append(top.role.Locals, vr)
	}
}

// fresh reports whether the innermost open statement holds no token yet.
func (b *nearBodyBuilder) fresh() bool {
	return len(b.open) > 0 && b.open[len(b.open)-1].count == 0
}

// fnvMix adds one token and a separator to an FNV-1a hash.
func fnvMix(hash uint64, tok string) uint64 {
	for i := 0; i < len(tok); i++ {
		hash ^= uint64(tok[i])
		hash *= fnvPrime64
	}
	hash ^= 0xff
	return hash * fnvPrime64
}

// context is what a statement inside st starts from: the shape and the
// anchors of st so far, so the statements of a then branch and of an else
// branch, of two loops, or of two checks that call other functions have
// other shapes.
func (st *nearStmt) context() uint64 { return (st.role.Shape ^ st.role.Anchors) * fnvPrime64 }

// openStmt opens a statement inside the innermost open one.
func (b *nearBodyBuilder) openStmt() {
	if len(b.open) == 0 {
		b.openSeeded(fnvOffset64, -1)
		return
	}
	top := &b.open[len(b.open)-1]
	b.openSeeded(top.context(), top.id)
}

// openSeeded opens a statement whose shape starts from seed, inside the
// statement opened as parent, -1 for none.
func (b *nearBodyBuilder) openSeeded(seed uint64, parent int) {
	b.open = append(b.open, nearStmt{id: len(b.roleOf), hash: fnvOffset64, role: nearRole{Shape: seed, Anchors: fnvOffset64, Parent: parent}})
	b.roleOf = append(b.roleOf, -1)
}

// closeStmt closes the innermost statement and returns what a statement
// inside it starts from and its order of opening.
func (b *nearBodyBuilder) closeStmt() (uint64, int) {
	last := b.open[len(b.open)-1]
	b.open = b.open[:len(b.open)-1]
	if last.count > 0 {
		b.body.Stmts = append(b.body.Stmts, last.hash)
		if b.detailed {
			b.roleOf[last.id] = len(b.body.Roles)
			b.body.Roles = append(b.body.Roles, last.role)
		}
	}
	return last.context(), last.id
}

func (b *nearBodyBuilder) finish() nearBody {
	for len(b.open) > 0 {
		b.closeStmt()
	}
	b.orderRoles()
	slices.Sort(b.body.Stmts)
	b.body.Calls = slices.Sorted(maps.Keys(b.calls))
	b.body.Ops = slices.Sorted(maps.Keys(b.ops))
	b.body.Lits = slices.Sorted(maps.Keys(b.lits))
	return b.body
}

// orderRoles puts the roles, which close inner first, in the order the
// statements open, a statement before the statements it holds, and points
// Owners and Parent at that order.
func (b *nearBodyBuilder) orderRoles() {
	if !b.detailed {
		return
	}
	final := make([]int, len(b.roleOf))
	roles := make([]nearRole, 0, len(b.body.Roles))
	for id, index := range b.roleOf {
		final[id] = -1
		if index >= 0 {
			final[id] = len(roles)
			roles = append(roles, b.body.Roles[index])
		}
	}
	for i := range roles {
		if parent := roles[i].Parent; parent >= 0 {
			roles[i].Parent = final[parent]
		}
	}
	for i, id := range b.body.Owners {
		if id >= 0 {
			b.body.Owners[i] = final[id]
		}
	}
	b.body.Roles = roles
}

// goNearBody normalizes a Go function body for the near comparison: the
// printing of blockNormalizer, with every variable of the function as one
// placeholder in the sequence, so that the numbering of variables, which
// follows their order, does not tell a copy with swapped statements from its
// original; the roles of a detailed body keep the numbers.
func goNearBody(info *types.Info, fd *ast.FuncDecl, detailed bool) nearBody {
	w := &goNearWalker{n: newFunctionBlockNormalizer(info, fd), b: newNearBodyBuilder(detailed), own: funcPackage(fd, info), fields: make(map[string]int)}
	w.body = fd.Body
	if detailed {
		w.writes = goWrites(fd.Body)
	}
	w.walk(fd.Body)
	return w.b.finish()
}

// goWrites collects what a body writes: the left side of an assignment, the
// operand of ++ and --, the key and the value of a range, down to the
// variable an index, a slice or a field of it writes.
func goWrites(body *ast.BlockStmt) map[ast.Node]bool {
	out := make(map[ast.Node]bool)
	mark := func(e ast.Expr) {
		for e != nil {
			out[e] = true
			switch x := e.(type) {
			case *ast.IndexExpr:
				e = x.X
			case *ast.IndexListExpr:
				e = x.X
			case *ast.SliceExpr:
				e = x.X
			case *ast.SelectorExpr:
				e = x.X
			case *ast.StarExpr:
				e = x.X
			case *ast.ParenExpr:
				e = x.X
			default:
				e = nil
			}
		}
	}
	ast.Inspect(body, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				mark(lhs)
			}
		case *ast.IncDecStmt:
			mark(x.X)
		case *ast.RangeStmt:
			mark(x.Key)
			mark(x.Value)
		}
		return true
	})
	return out
}

// goEffect reports whether node, apart from what it holds, may do what
// nothing proves independent of the statements around it: a call but of
// len, cap or a conversion, an address taken, a send or a receive, a range
// over a channel or a function, a closure, a subslice that shares what it
// cuts.
func goEffect(info *types.Info, node ast.Node) bool {
	switch x := node.(type) {
	case *ast.CallExpr:
		if info.Types[x.Fun].IsType() {
			return false
		}
		if id, ok := ast.Unparen(x.Fun).(*ast.Ident); ok {
			if builtin, ok := info.Uses[id].(*types.Builtin); ok {
				return builtin.Name() != "len" && builtin.Name() != "cap"
			}
		}
		return true
	case *ast.UnaryExpr:
		return x.Op == token.AND || x.Op == token.ARROW
	case *ast.RangeStmt:
		if t := info.TypeOf(x.X); t != nil {
			switch t.Underlying().(type) {
			case *types.Chan, *types.Signature:
				return true
			}
		}
		return false
	case *ast.SendStmt, *ast.FuncLit, *ast.SliceExpr:
		return true
	}
	return false
}

// goReaches reports whether node, apart from what it holds, reaches what
// another name may reach too: an element of a slice or a map, what a
// pointer points to, the elements a range reads, the length of a map or a
// channel.
func goReaches(info *types.Info, node ast.Node) bool {
	switch x := node.(type) {
	case *ast.IndexExpr:
		return goReference(info.TypeOf(x.X))
	case *ast.StarExpr:
		return !info.Types[x.X].IsType()
	case *ast.SelectorExpr:
		selection := info.Selections[x]
		return selection != nil && selection.Kind() == types.FieldVal && selection.Indirect()
	case *ast.RangeStmt:
		return goReference(info.TypeOf(x.X))
	case *ast.CallExpr:
		if len(x.Args) == 1 && info.TypeOf(x.Args[0]) != nil {
			switch info.TypeOf(x.Args[0]).Underlying().(type) {
			case *types.Map, *types.Chan:
				return true
			}
		}
	}
	return false
}

// goReference reports whether a value of type t reaches what another value
// may reach: a slice, a map or a pointer.
func goReference(t types.Type) bool {
	if t == nil {
		return false
	}
	switch t.Underlying().(type) {
	case *types.Slice, *types.Map, *types.Pointer:
		return true
	}
	return false
}

// note marks the statement open with what node, apart from what it holds,
// does: fixes it in its place for an effect (goEffect), notes a read or a
// write of what a reference reaches (goReaches).
func (w *goNearWalker) note(node ast.Node) {
	if !w.b.detailed {
		return
	}
	if goEffect(w.n.info, node) {
		w.b.fix()
	}
	if goReaches(w.n.info, node) {
		use := memoryRead
		if w.writes[node] {
			use = memoryWrite
		}
		w.b.touch(use)
	}
}

// goEffectFree reports whether node holds nothing goEffect sees.
func goEffectFree(info *types.Info, node ast.Node) bool {
	free := true
	ast.Inspect(node, func(n ast.Node) bool {
		if free && n != nil && goEffect(info, n) {
			free = false
		}
		return free
	})
	return free
}

type goNearWalker struct {
	n   *blockNormalizer
	b   *nearBodyBuilder
	own *types.Package
	// callees holds the names of called functions not printed yet, which the
	// shape of their statement masks: a selector, printed as one atom, and
	// its last name, printed otherwise.
	callees []calleeName
	// fields numbers the fields of variables the body reads.
	fields map[string]int
	// writes holds what the body writes (goWrites), for a detailed body.
	writes map[ast.Node]bool
	// body is the body walked; uses counts the reads of its objects
	// (goUses), once a swap through a temporary needs them.
	body *ast.BlockStmt
	uses map[types.Object]int
	// assigns is what the body assigns (goAssignments), once a variable
	// named a second time needs it; aliases maps every such name to what
	// it names.
	assigns *goAssigned
	aliases map[types.Object]ast.Expr
}

type calleeName struct{ sel, name ast.Node }

func (w *goNearWalker) walk(root ast.Node) {
	var stack []ast.Node
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if isElseBlock(top, stack) {
				w.b.closeStmt()
			}
			w.b.emit(")")
			if isNearStmt(top) {
				w.b.closeStmt()
			}
			return false
		}
		if !isNearStmt(node) {
			w.note(node)
		}
		switch x := node.(type) {
		case *ast.ParenExpr:
			w.walk(x.X)
			return false
		case *ast.BlockStmt:
			if list, swapped := w.tupleSwaps(x.List); swapped {
				w.openNode(x)
				elseBlock := isElseBlock(x, stack)
				if elseBlock {
					w.b.openStmt()
					w.b.emit("else")
				}
				for _, stmt := range list {
					w.walk(stmt)
				}
				if elseBlock {
					w.b.closeStmt()
				}
				w.b.emit(")")
				return false
			}
		case *ast.Ident:
			if target, ok := w.aliases[w.n.info.ObjectOf(x)]; ok {
				w.walk(target)
				return false
			}
			w.packageValue(x)
			w.name(x, w.n.ident(x))
			return false
		case *ast.BasicLit:
			value := goLiteralValue(x)
			w.b.emitAnchor(x.Value, value, nearLiteralMask)
			w.b.lits[value] = true
			return false
		case *ast.SelectorExpr:
			if atom, ok := w.n.selector(x); ok {
				w.packageValue(x.Sel)
				w.name(x, atom)
				return false
			}
			if w.field(x) {
				return false
			}
		case *ast.Comment, *ast.CommentGroup:
			return false
		case *ast.CallExpr:
			if callee := w.callee(x); callee != "" {
				w.b.calls[callee] = true
				if w.b.detailed {
					w.markCallee(x.Fun)
				}
			}
		case *ast.BinaryExpr:
			w.b.ops[x.Op.String()] = true
			if w.commuted(x) {
				w.openNode(x)
				w.walk(x.Y)
				w.walk(x.X)
				w.b.emit(")")
				return false
			}
		case *ast.AssignStmt:
			if w.rewritten(x) {
				return false
			}
		case *ast.UnaryExpr:
			if x.Op == token.NOT {
				w.b.ops[x.Op.String()] = true
			}
		}
		if isNearStmt(node) {
			w.openStmt(node)
			w.note(node)
		}
		w.openNode(node)
		if isElseBlock(node, stack) {
			w.b.openStmt()
			w.b.emit("else")
		}
		stack = append(stack, node)
		return true
	})
}

// openNode emits the kind of node; an operator of an expression, an
// increment and a jump are anchors, which keep their places as literals do.
func (w *goNearWalker) openNode(node ast.Node) {
	kind := "(" + nodeKind(node)
	switch node.(type) {
	case *ast.BinaryExpr, *ast.UnaryExpr, *ast.IncDecStmt, *ast.BranchStmt, *ast.ReturnStmt:
		w.b.emitAnchor(kind, kind, kind)
	default:
		w.b.emit(kind)
	}
}

// alias reports whether assign names a variable of the function or a field
// of one a second time, y := v, and records y to stand for v: a copy may
// read a value through a name of its own. Neither name may be set again,
// and y may write into what it names only when that is shared, a slice, a
// map or a pointer.
func (w *goNearWalker) alias(assign *ast.AssignStmt) bool {
	if assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return false
	}
	name, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || name.Name == "_" {
		return false
	}
	root, field, local := w.localValue(assign.Rhs[0])
	if !local {
		return false
	}
	if w.assigns == nil {
		assigned := goAssignments(w.n.info, w.body)
		w.assigns = &assigned
	}
	obj := w.n.info.ObjectOf(name)
	if obj == nil || w.assigns.rebound[obj] || w.assigns.into[obj] && !sharesValue(obj.Type()) || !w.assigns.keeps(root, field, w.n.info.TypeOf(assign.Rhs[0])) {
		return false
	}
	if !w.untouchedWhileNamed(assign, obj) {
		return false
	}
	if w.aliases == nil {
		w.aliases = make(map[types.Object]ast.Expr)
	}
	w.aliases[obj] = assign.Rhs[0]
	return true
}

// untouchedWhileNamed reports whether nothing may change what assign names
// a second time while obj names it: nothing after assign in the scope of
// obj calls or takes an address (goEffect), since a call may change a value
// a name of its own keeps.
func (w *goNearWalker) untouchedWhileNamed(assign *ast.AssignStmt, obj types.Object) bool {
	from, to := assign.End(), obj.Parent().End()
	free := true
	ast.Inspect(w.body, func(node ast.Node) bool {
		if !free || node == nil || node.End() <= from || node.Pos() >= to {
			return false
		}
		free = node.Pos() < from || !goEffect(w.n.info, node)
		return free
	})
	return free
}

// localValue returns the variable of the function e is, or whose field it
// is, with the name of the field, and whether e is either.
func (w *goNearWalker) localValue(e ast.Expr) (types.Object, string, bool) {
	field := ""
	if sel, ok := e.(*ast.SelectorExpr); ok {
		obj, isVar := w.n.info.ObjectOf(sel.Sel).(*types.Var)
		if !isVar || !obj.IsField() {
			return nil, "", false
		}
		e, field = sel.X, sel.Sel.Name
	}
	id, ok := e.(*ast.Ident)
	if !ok {
		return nil, "", false
	}
	v, isVar := w.n.info.ObjectOf(id).(*types.Var)
	return v, field, isVar && !v.IsField() && v.Pos() >= w.n.lo && v.Pos() < w.n.hi
}

func sharesValue(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Slice, *types.Map, *types.Pointer, *types.Chan:
		return true
	}
	return false
}

// goAssigned is what a body assigns: the variables and the fields of
// variables it sets again after they are declared, and the variables it
// writes into, at an index, a field or through a pointer.
type goAssigned struct {
	rebound map[types.Object]bool
	fields  map[fieldRef]bool
	into    map[types.Object]bool
}

// fieldRef is a field of a variable.
type fieldRef struct {
	root types.Object
	name string
}

func goAssignments(info *types.Info, body *ast.BlockStmt) goAssigned {
	out := goAssigned{rebound: map[types.Object]bool{}, fields: map[fieldRef]bool{}, into: map[types.Object]bool{}}
	into := func(e ast.Expr) {
		for e != nil {
			switch x := ast.Unparen(e).(type) {
			case *ast.IndexExpr:
				e = x.X
			case *ast.IndexListExpr:
				e = x.X
			case *ast.SelectorExpr:
				e = x.X
			case *ast.StarExpr:
				e = x.X
			case *ast.Ident:
				if obj := info.ObjectOf(x); obj != nil {
					out.into[obj] = true
				}
				e = nil
			default:
				e = nil
			}
		}
	}
	mark := func(e ast.Expr) {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			if obj := info.ObjectOf(x); obj != nil && info.Defs[x] == nil {
				out.rebound[obj] = true
			}
			return
		case *ast.SelectorExpr:
			if id, ok := ast.Unparen(x.X).(*ast.Ident); ok {
				out.fields[fieldRef{info.ObjectOf(id), x.Sel.Name}] = true
			}
		}
		into(e)
	}
	ast.Inspect(body, func(node ast.Node) bool {
		switch x := node.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				mark(lhs)
			}
		case *ast.IncDecStmt:
			mark(x.X)
		case *ast.RangeStmt:
			if x.Key != nil {
				mark(x.Key)
			}
			if x.Value != nil {
				mark(x.Value)
			}
		case *ast.UnaryExpr:
			// What is taken by address may be set through the pointer.
			if x.Op == token.AND {
				mark(x.X)
			}
		}
		return true
	})
	return out
}

// keeps reports whether the body never sets the variable root, or its
// field when one is named, again, nor writes into a value of type t of it
// that is not shared.
func (a goAssigned) keeps(root types.Object, field string, t types.Type) bool {
	if a.rebound[root] || field != "" && a.fields[fieldRef{root, field}] {
		return false
	}
	return !a.into[root] || sharesValue(t)
}

// tupleSwaps rewrites every swap through a temporary in list, t := a; a = b;
// b = t, as the swap a, b = b, a it is, when the body reads t nowhere else,
// and reports whether it found one.
func (w *goNearWalker) tupleSwaps(list []ast.Stmt) ([]ast.Stmt, bool) {
	var out []ast.Stmt
	swapped := false
	for i := 0; i < len(list); i++ {
		if i+2 < len(list) {
			if swap := w.tupleSwap(list[i], list[i+1], list[i+2]); swap != nil {
				if !swapped {
					out = append(make([]ast.Stmt, 0, len(list)), list[:i]...)
					swapped = true
				}
				out = append(out, swap)
				i += 2
				continue
			}
		}
		if swapped {
			out = append(out, list[i])
		}
	}
	return out, swapped
}

func (w *goNearWalker) tupleSwap(first, second, third ast.Stmt) ast.Stmt {
	save, move, back := singleAssign(first, token.DEFINE), singleAssign(second, token.ASSIGN), singleAssign(third, token.ASSIGN)
	if save == nil || move == nil || back == nil {
		return nil
	}
	tmp, ok := save.Lhs[0].(*ast.Ident)
	read, isIdent := back.Rhs[0].(*ast.Ident)
	if !ok || !isIdent || w.n.info.ObjectOf(tmp) == nil || w.n.info.ObjectOf(read) != w.n.info.ObjectOf(tmp) {
		return nil
	}
	if types.ExprString(save.Rhs[0]) != types.ExprString(move.Lhs[0]) || types.ExprString(move.Rhs[0]) != types.ExprString(back.Lhs[0]) {
		return nil
	}
	if !w.swapPlace(move.Lhs[0], back.Lhs[0]) || !w.swapPlace(back.Lhs[0], move.Lhs[0]) {
		return nil
	}
	if w.uses == nil {
		w.uses = goUses(w.n.info, w.body)
	}
	if w.uses[w.n.info.ObjectOf(tmp)] != 1 {
		return nil
	}
	return &ast.AssignStmt{Lhs: []ast.Expr{move.Lhs[0], back.Lhs[0]}, Tok: token.ASSIGN, Rhs: []ast.Expr{move.Rhs[0], save.Rhs[0]}}
}

// swapPlace reports whether e, one of the two places of a swap through a
// temporary, is a place the write to the other, written, leaves where it
// is: a name, or a field, an element at a name or a constant or what a
// pointer points to of a place written is not, at an index written is not.
// t := xs[k]; xs[k] = xs[xs[k]-1]; xs[xs[k]-1] = t reads
// the new xs[k] for its last place, which the swap does not.
func (w *goNearWalker) swapPlace(e, written ast.Expr) bool {
	other := types.ExprString(written)
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return true
		case *ast.SelectorExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr:
			id, name := x.Index.(*ast.Ident)
			if name && id.Name == other || !name && w.n.info.Types[x.Index].Value == nil {
				return false
			}
			e = x.X
		default:
			return false
		}
		if types.ExprString(e) == other {
			return false
		}
	}
}

// rewritten prints an assignment that stands for another, a second name of
// a variable or a swap from the other end, as the other and reports whether
// it did; for another assignment it notes its operator.
func (w *goNearWalker) rewritten(x *ast.AssignStmt) bool {
	if w.alias(x) {
		return true
	}
	if swap := w.orderedSwap(x); swap != nil {
		w.walk(swap)
		return true
	}
	if x.Tok != token.ASSIGN && x.Tok != token.DEFINE {
		w.b.ops[x.Tok.String()] = true
	}
	return false
}

// openStmt opens the statement node, marked when it assigns several values
// at once.
func (w *goNearWalker) openStmt(node ast.Node) {
	w.b.openStmt()
	if assign, ok := node.(*ast.AssignStmt); ok && len(assign.Rhs) > 1 {
		w.b.parallel()
	}
}

// orderedSwap is a swap a, b = b, a written with the value of the variable
// declared later first, b, a = a, b, as the other, which it is: a copy may
// swap from either end. It is nil for another assignment.
func (w *goNearWalker) orderedSwap(x *ast.AssignStmt) *ast.AssignStmt {
	if len(x.Lhs) != 2 || len(x.Rhs) != 2 {
		return nil
	}
	first, second := types.ExprString(x.Lhs[0]), types.ExprString(x.Lhs[1])
	if first != types.ExprString(x.Rhs[1]) || second != types.ExprString(x.Rhs[0]) || !w.declaredBefore(x.Lhs[1], x.Lhs[0]) {
		return nil
	}
	return &ast.AssignStmt{Lhs: []ast.Expr{x.Lhs[1], x.Lhs[0]}, Tok: token.ASSIGN, Rhs: []ast.Expr{x.Rhs[1], x.Rhs[0]}}
}

// declaredBefore reports whether, at the first name where they differ, a
// names a variable declared before the one b names.
func (w *goNearWalker) declaredBefore(a, b ast.Expr) bool {
	left, right := goNames(a), goNames(b)
	for k := range min(len(left), len(right)) {
		l, r := w.n.info.ObjectOf(left[k]), w.n.info.ObjectOf(right[k])
		if l != r {
			return l != nil && r != nil && l.Pos() < r.Pos()
		}
	}
	return false
}

// goNames lists the names in e in their order.
func goNames(e ast.Expr) []*ast.Ident {
	var out []*ast.Ident
	ast.Inspect(e, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok {
			out = append(out, id)
		}
		return true
	})
	return out
}

// singleAssign is stmt when it assigns one value to one name with tok.
func singleAssign(stmt ast.Stmt, tok token.Token) *ast.AssignStmt {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != tok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return nil
	}
	return assign
}

// goUses counts the reads of every object in body.
func goUses(info *types.Info, body *ast.BlockStmt) map[types.Object]int {
	out := make(map[types.Object]int)
	ast.Inspect(body, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok {
			if obj := info.Uses[id]; obj != nil {
				out[obj]++
			}
		}
		return true
	})
	return out
}

// commuted reports whether a commutative operation is written with the
// smaller operand first, which the body prints second, as a copy may write
// b + v*k for v*k + b. A sum of texts does not commute.
func (w *goNearWalker) commuted(x *ast.BinaryExpr) bool {
	switch x.Op {
	case token.EQL, token.NEQ:
	case token.ADD, token.MUL, token.AND, token.OR, token.XOR:
		basic, ok := w.n.info.TypeOf(x).(*types.Basic)
		if !ok || basic.Info()&types.IsNumeric == 0 {
			return false
		}
	default:
		return false
	}
	return nodeCount(x.X) < nodeCount(x.Y) && goEffectFree(w.n.info, x.X) && goEffectFree(w.n.info, x.Y)
}

// nodeCount counts the nodes of an expression as the body prints them: a
// selector, a field or a qualified name, is one, a parenthesis none.
func nodeCount(node ast.Node) int {
	n := 0
	ast.Inspect(node, func(node ast.Node) bool {
		switch node.(type) {
		case nil, *ast.ParenExpr:
			return true
		case *ast.SelectorExpr:
			n++
			return false
		}
		n++
		return true
	})
	return n
}

// field emits a field of a variable of the function as a variable of its
// own, numbered by the variable and the field: a copy that reads one field
// in the place of another is another function, as with variables, and a
// copy that reads a field where the library function reads a variable reads
// it in the same place.
func (w *goNearWalker) field(sel *ast.SelectorExpr) bool {
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	if obj, ok := w.n.info.ObjectOf(sel.Sel).(*types.Var); !ok || !obj.IsField() {
		return false
	}
	// Naming the variable numbers it, when it is a variable of the function.
	root := w.n.ident(id)
	rootNum, local := w.n.locals[w.n.info.ObjectOf(id)]
	if !local {
		return false
	}
	key := root + "." + sel.Sel.Name
	num, known := w.fields[key]
	if !known {
		num = nearFieldBase + len(w.fields)
		w.fields[key] = num
	}
	w.b.field(num, rootNum)
	w.b.emitVar(num, w.writes[sel])
	return true
}

// isElseBlock reports whether node is the else block of the statement on top
// of stack. The block is a statement of its own for the near comparison, so
// that the statements it holds are held otherwise than those of the then
// block: a statement moved from one branch to the other is no copy.
func isElseBlock(node ast.Node, stack []ast.Node) bool {
	if len(stack) == 0 {
		return false
	}
	parent, ok := stack[len(stack)-1].(*ast.IfStmt)
	_, block := node.(*ast.BlockStmt)
	return ok && block && parent.Else == node
}

// name emits a printed name: a numbered variable, the name of a called
// function or another name.
func (w *goNearWalker) name(node ast.Node, tok string) {
	if strings.HasPrefix(tok, "$L") {
		if num, err := strconv.Atoi(tok[2:]); err == nil {
			w.b.emitVar(num, w.writes[node])
			return
		}
	}
	for i, callee := range w.callees {
		if callee.sel == node || callee.name == node {
			w.callees = slices.Delete(w.callees, i, i+1)
			w.b.emitAnchor(tok, tok, nearCallMask)
			return
		}
	}
	w.b.emit(tok)
}

// markCallee marks the name callee reads.
func (w *goNearWalker) markCallee(fun ast.Expr) {
	switch fun := ast.Unparen(fun).(type) {
	case *ast.Ident:
		w.callees = append(w.callees, calleeName{name: fun})
	case *ast.SelectorExpr:
		w.callees = append(w.callees, calleeName{sel: fun, name: fun.Sel})
	case *ast.IndexExpr:
		w.markCallee(fun.X)
	case *ast.IndexListExpr:
		w.markCallee(fun.X)
	}
}

// packageValue counts a package-level constant or variable among the
// literals: a copy that reads its own constant where the library function
// has a number is another function, however equal the constant is today.
func (w *goNearWalker) packageValue(id *ast.Ident) {
	obj := w.n.info.ObjectOf(id)
	switch obj.(type) {
	case *types.Const, *types.Var:
	default:
		return
	}
	if obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
		w.b.lits["v:"+obj.Pkg().Path()+"."+obj.Name()] = true
	}
}

func isNearStmt(node ast.Node) bool {
	if _, ok := node.(ast.Stmt); !ok {
		return false
	}
	_, block := node.(*ast.BlockStmt)
	return !block
}

// callee names the function or method a call reaches: a function of the
// function's own package by its name alone, so a copy that calls its own copy
// of a library helper still matches; others by their full name, methods by
// their name. Conversions and builtins are no anchors: a copy for another
// type converts and allocates its own way.
func (w *goNearWalker) callee(call *ast.CallExpr) string {
	var id *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	case *ast.IndexExpr:
		return w.callee(&ast.CallExpr{Fun: fun.X})
	case *ast.IndexListExpr:
		return w.callee(&ast.CallExpr{Fun: fun.X})
	default:
		return ""
	}
	fn, ok := w.n.info.ObjectOf(id).(*types.Func)
	if !ok {
		return ""
	}
	if fn.Signature().Recv() != nil {
		return "." + fn.Name()
	}
	if fn.Pkg() != nil && fn.Pkg() == w.own {
		return "~" + fn.Name()
	}
	return fn.FullName()
}

func goLiteralValue(lit *ast.BasicLit) string {
	if lit.Kind == token.STRING || lit.Kind == token.CHAR {
		if value, err := strconv.Unquote(lit.Value); err == nil {
			return "s:" + value
		}
	}
	return lit.Value
}

// nearCandidate is a library function in the form the near comparison reads:
// match holds, for every token of the body, the positions it takes, as a bit
// set for the bit-parallel LCS.
type nearCandidate struct {
	fn    libraryMatch
	body  nearBody
	match map[string][]uint64
	// shapes indexes the statements of the body by their shape.
	shapes map[uint64][]int
	calls  string
	ops    string
}

// matchWordBits is the number of library tokens a word of a match set holds.
const matchWordBits = 64

func newNearCandidate(fn libraryMatch, body nearBody) *nearCandidate {
	words := (len(body.Tokens) + matchWordBits - 1) / matchWordBits
	match := make(map[string][]uint64)
	for i, tok := range body.Tokens {
		set := match[tok]
		if set == nil {
			set = make([]uint64, words)
			match[tok] = set
		}
		set[i/matchWordBits] |= 1 << (i % matchWordBits)
	}
	shapes := make(map[uint64][]int, len(body.Roles))
	for i, role := range body.Roles {
		shapes[role.Shape] = append(shapes[role.Shape], i)
	}
	return &nearCandidate{fn: fn, body: body, match: match, shapes: shapes, calls: strings.Join(body.Calls, "\x00"), ops: strings.Join(body.Ops, "\x00")}
}

// nearIndex groups library functions by the functions they call and their
// operators: a copy keeps both, so only a group can hold its original.
type nearIndex struct {
	groups    map[string][]*nearCandidate
	minTokens int
}

func newNearIndex(candidates []*nearCandidate, minTokens int) *nearIndex {
	idx := &nearIndex{groups: make(map[string][]*nearCandidate), minTokens: minTokens}
	for _, c := range candidates {
		key := c.calls + "\x01" + c.ops
		idx.groups[key] = append(idx.groups[key], c)
	}
	for key := range idx.groups {
		slices.SortFunc(idx.groups[key], func(a, b *nearCandidate) int {
			if libraryMatchLess(a.fn, b.fn) {
				return -1
			}
			if libraryMatchLess(b.fn, a.fn) {
				return 1
			}
			return 0
		})
	}
	return idx
}

// best returns the library function body is closest to, at nearCopyThreshold
// or above, and the similarity, and the body in detail, which detail makes
// for the first library function that comes near.
func (idx *nearIndex) best(body nearBody, detail func() nearBody) (*nearCandidate, float64, nearBody) {
	if idx == nil || len(body.Tokens) < idx.minTokens {
		return nil, 0, body
	}
	key := strings.Join(body.Calls, "\x00") + "\x01" + strings.Join(body.Ops, "\x00")
	var best *nearCandidate
	bestScore := 0.0
	detailed := false
	for _, c := range idx.groups[key] {
		if !subsetOf(body.Lits, c.body.Lits) {
			continue
		}
		score := nearSimilarity(c, body)
		if score < nearCopyThreshold || score <= bestScore {
			continue
		}
		if !detailed {
			body, detailed = detail(), true
		}
		if sameRoles(c, body) {
			best, bestScore = c, score
		}
	}
	return best, bestScore, body
}

func subsetOf(sub, set []string) bool {
	for _, value := range sub {
		if _, found := slices.BinarySearch(set, value); !found {
			return false
		}
	}
	return true
}

// sameRoles reports whether a body keeps the roles of the library function:
// the statements of a body that have the shape of a statement of the library
// function agree with it — the same literals and called functions in the same
// places, and variables that stand for the variables of the library function
// one to one — and so do the variables in the rest of the two bodies, in the
// order they keep. A literal or a call moved to another place, or a variable
// in the place of another (a value below the range set to its upper bound,
// slice bounds swapped), makes another function of the same tokens.
//
// Statements of a shape the library function has once are paired first, as
// they pair for certain; then each statement of a shape it has more than once
// takes the first statement of that shape that agrees and is held by the
// partner of the statement that holds it, and every statement of the side
// with fewer must find one. Statements moved, as a copy may move
// independent ones, still pair by shape; the rest is compared in order, with
// the statements that hold a statement left unpaired, so that a check that
// trades the statements it guards with another check is compared in place.
func sameRoles(c *nearCandidate, body nearBody) bool {
	roles := body.Roles
	shapes := make(map[uint64][]int, len(roles))
	for i, role := range roles {
		shapes[role.Shape] = append(shapes[role.Shape], i)
	}
	m := &roleMapping{forward: map[int]int{}, back: map[int]int{}}
	ownPartner, libPartner := unpaired(len(roles)), unpaired(len(c.body.Roles))
	var shared []int
	for i, role := range roles {
		lib := c.shapes[role.Shape]
		switch {
		case len(lib) == 0:
		case len(lib) == 1 && len(shapes[role.Shape]) == 1:
			if !m.unify(role, c.body.Roles[lib[0]]) {
				return false
			}
			ownPartner[i], libPartner[lib[0]] = lib[0], i
		default:
			shared = append(shared, i)
		}
	}
	paired := make(map[uint64]int)
	for _, i := range shared {
		role := roles[i]
		for _, j := range c.shapes[role.Shape] {
			if libPartner[j] < 0 && heldAlike(role, c.body.Roles[j], ownPartner) && m.unify(role, c.body.Roles[j]) {
				ownPartner[i], libPartner[j] = j, i
				paired[role.Shape]++
				break
			}
		}
	}
	for _, i := range shared {
		shape := roles[i].Shape
		if paired[shape] < min(len(shapes[shape]), len(c.shapes[shape])) {
			return false
		}
	}
	unpairHolders(roles, ownPartner, libPartner)
	unpairHolders(c.body.Roles, libPartner, ownPartner)
	if !keepsDependentOrder(roles, c.body.Roles, ownPartner, body.Roots) {
		return false
	}
	same, matched := m.alignRest(
		restSide{tokens: unpairedTokens(c.body, libPartner), roles: c.body.Roles, roots: c.body.Roots},
		restSide{tokens: unpairedTokens(body, ownPartner), roles: roles, roots: body.Roots})
	if !same {
		return false
	}
	partner := ownPartner
	if len(matched) > 0 {
		partner = restPartners(ownPartner, matched)
		if !keepsDependentOrder(roles, c.body.Roles, partner, body.Roots) || !keepsParallel(roles, c.body.Roles, partner) {
			return false
		}
	}
	return keepsOwnValues(roles, partner)
}

// keepsOwnValues reports whether no statement that keeps its place runs
// between a statement of the body that stands for none of the library
// function and the last statement that reads what it writes: old := p.Name;
// p.SetName(n); return old reads the name from before the call, where the
// library function, which reads p.Name after it, reads the new one.
func keepsOwnValues(roles []nearRole, partner []int) bool {
	lastRead := make(map[int]int)
	for k, role := range roles {
		for _, v := range role.Locals {
			lastRead[v] = k
		}
	}
	nextFixed := len(roles)
	for i := len(roles) - 1; i >= 0; i-- {
		if partner[i] < 0 {
			for _, v := range roles[i].Writes {
				// A value nothing reads gives 0, before every statement after i.
				if lastRead[v] >= nextFixed {
					return false
				}
			}
		}
		if roles[i].Fixed {
			nextFixed = i
		}
	}
	return true
}

// restPartners adds to the partners of the paired statements the statement
// of the library function every other statement of the body shares the
// most tokens with in the alignment of sameRest, the first of those.
func restPartners(paired []int, matched map[[2]int]int) []int {
	partner := slices.Clone(paired)
	best := make(map[int]int)
	for pair, count := range matched {
		own, lib := pair[0], pair[1]
		if count > best[own] || count == best[own] && lib < partner[own] {
			best[own], partner[own] = count, lib
		}
	}
	return partner
}

// keepsParallel reports whether the statements of the body that stand for
// one assignment of several values at once of the library function, which
// reads all of them before it writes any, read nothing an earlier one of
// them writes: xs[i] = xs[j]; xs[j] = xs[i] loses a value that the swap
// xs[i], xs[j] = xs[j], xs[i] keeps.
func keepsParallel(roles, lib []nearRole, partner []int) bool {
	written := make(map[int]map[int]bool)
	for i, p := range partner {
		if p < 0 || !lib[p].Parallel {
			continue
		}
		before := written[p]
		if before == nil {
			before = make(map[int]bool)
			written[p] = before
		}
		for _, v := range roles[i].Locals {
			if before[v] {
				return false
			}
		}
		for _, v := range roles[i].Writes {
			before[v] = true
		}
	}
	return true
}

// keepsDependentOrder reports whether the statements of a body with a
// partner in the library function, lib, run in the order of their partners
// where nothing proves them independent. A statement that keeps its place
// (Fixed) on either side, or holds one, runs after every statement whose
// partner runs before its partner and before every one whose partner runs
// after. Other statements depend on each other when one writes a variable
// the other reads without writing it. A field stands for its variable as
// well: writing the variable writes its fields, writing a field writes the
// variable for the statements that read it, but two fields of one variable
// are apart. A copy may swap two lookups, two counts or two rewrites of one
// value, but not a rewrite of a value and a statement that reads it, which
// then reads another value. A statement opens before the statements it
// holds, on both sides, so the two keep their order.
func keepsDependentOrder(roles, lib []nearRole, partner []int, roots map[int]int) bool {
	last := -1
	inOrder := true
	for _, p := range partner {
		if p >= 0 {
			inOrder = inOrder && p >= last
			last = max(last, p)
		}
	}
	if inOrder {
		return true
	}
	if !keepsFixedPlaces(heldFixed(roles), heldFixed(lib), partner) {
		return false
	}
	vars := statementVars(roles)
	access := make(map[int]*varAccess)
	at := func(v int) *varAccess {
		if access[v] == nil {
			access[v] = &varAccess{}
		}
		return access[v]
	}
	for i, sv := range vars {
		if partner[i] < 0 {
			continue
		}
		for v := range sv.writes {
			at(v).writers = append(at(v).writers, i)
			if root, field := roots[v]; field {
				at(root).fieldWriters = append(at(root).fieldWriters, i)
			}
		}
		for v := range sv.reads {
			at(v).readers = append(at(v).readers, i)
			if root, field := roots[v]; field {
				at(root).fieldReaders = append(at(root).fieldReaders, i)
			}
		}
	}
	for v, a := range access {
		if !a.inOrder(partner) || v == nearMemory && !a.writesInOrder(partner) {
			return false
		}
	}
	return true
}

// nearMemory stands among the variables of statementVars for what is
// reached through a reference, which two writes may both change.
const nearMemory = -2

// heldFixed marks every statement of roles that keeps its place or holds
// one that does.
func heldFixed(roles []nearRole) []bool {
	out := make([]bool, len(roles))
	for i := len(roles) - 1; i >= 0; i-- {
		out[i] = out[i] || roles[i].Fixed
		if p := roles[i].Parent; p >= 0 && out[i] {
			out[p] = true
		}
	}
	return out
}

// keepsFixedPlaces reports whether every statement of the body that keeps
// its place, or whose partner does, has no statement before it with a later
// partner and none after it with an earlier one.
func keepsFixedPlaces(own, lib []bool, partner []int) bool {
	later := make([]int, len(partner)+1)
	later[len(partner)] = math.MaxInt
	for i := len(partner) - 1; i >= 0; i-- {
		later[i] = later[i+1]
		if partner[i] >= 0 {
			later[i] = min(later[i], partner[i])
		}
	}
	before := -1
	for i, p := range partner {
		if p < 0 {
			continue
		}
		if (own[i] || lib[p]) && (before > p || later[i+1] < p) {
			return false
		}
		before = max(before, p)
	}
	return true
}

// varAccess is how the statements use one variable: those that write it,
// read it, and, for a variable with fields, write or read a field of it.
type varAccess struct {
	writers, fieldWriters []int
	readers, fieldReaders []int
}

// keptPair reports whether statements x and y of a body run in the order of
// their partners, or stand for one statement.
func keptPair(partner []int, x, y int) bool {
	return partner[x] == partner[y] || (x < y) == (partner[x] < partner[y])
}

// writesInOrder reports whether every two writers keep their order.
func (a *varAccess) writesInOrder(partner []int) bool {
	for k, w := range a.writers {
		for _, other := range a.writers[k+1:] {
			if !keptPair(partner, w, other) {
				return false
			}
		}
	}
	return true
}

func (a *varAccess) inOrder(partner []int) bool {
	for _, w := range a.writers {
		for _, r := range a.readers {
			if !keptPair(partner, w, r) {
				return false
			}
		}
		for _, r := range a.fieldReaders {
			if !keptPair(partner, w, r) {
				return false
			}
		}
	}
	for _, f := range a.fieldWriters {
		for _, r := range a.readers {
			if !keptPair(partner, f, r) {
				return false
			}
		}
	}
	return true
}

// stmtVars are the variables a statement, with the statements it holds,
// writes and those it reads without writing them.
type stmtVars struct {
	writes map[int]bool
	reads  map[int]bool
}

// statementVars collects the variables of every statement with those of the
// statements it holds; a statement comes before the statements it holds.
func statementVars(roles []nearRole) []stmtVars {
	out := make([]stmtVars, len(roles))
	for i := range out {
		out[i] = stmtVars{writes: map[int]bool{}, reads: map[int]bool{}}
	}
	for i := len(roles) - 1; i >= 0; i-- {
		for _, v := range roles[i].Writes {
			out[i].writes[v] = true
		}
		for _, v := range roles[i].Locals {
			out[i].reads[v] = true
		}
		switch roles[i].Memory {
		case memoryWrite:
			out[i].writes[nearMemory] = true
		case memoryRead:
			out[i].reads[nearMemory] = true
		}
		if p := roles[i].Parent; p >= 0 {
			maps.Copy(out[p].writes, out[i].writes)
			maps.Copy(out[p].reads, out[i].reads)
		}
	}
	for i := range out {
		for v := range out[i].writes {
			delete(out[i].reads, v)
		}
	}
	return out
}

// heldAlike reports whether a statement of the body and one of the library
// function of its shape are held alike: both by no statement, or the one by
// the partner of the other. A statement held by a check that pairs with
// another check moved from one check to another. The shape starts from what
// holds a statement, so statements of one shape are both held or both not.
func heldAlike(role, lib nearRole, ownPartner []int) bool {
	return role.Parent < 0 || ownPartner[role.Parent] == lib.Parent
}

// unpaired is a partner list of n statements with none paired yet.
func unpaired(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = -1
	}
	return out
}

// unpairHolders unpairs, with their partners, the statements that hold a
// statement of roles without a partner.
func unpairHolders(roles []nearRole, partner, other []int) {
	for i := range roles {
		if partner[i] >= 0 {
			continue
		}
		for p := roles[i].Parent; p >= 0 && partner[p] >= 0; p = roles[p].Parent {
			other[partner[p]] = -1
			partner[p] = -1
		}
	}
}

// nearToken is a token of a statement that sameRoles did not pair, with the
// number of the variable it is, or -1, and the statement it is of.
type nearToken struct {
	text string
	vr   int
	stmt int
}

func unpairedTokens(body nearBody, partner []int) []nearToken {
	var out []nearToken
	for i, owner := range body.Owners {
		if owner >= 0 && partner[owner] < 0 {
			out = append(out, nearToken{text: body.Tokens[i], vr: body.Vars[i], stmt: owner})
		}
	}
	return out
}

// restSide is what sameRest reads of one side: the tokens of the statements
// sameRoles did not pair and the statements.
type restSide struct {
	tokens []nearToken
	roles  []nearRole
	roots  map[int]int
}

// maxRestAlignCells bounds the table of sameRest; the rest of two bodies
// larger than that is no copy, since nothing compares it.
const maxRestAlignCells = 1 << 22

// sameRest aligns the tokens of the statements sameRoles did not pair by a
// longest common subsequence. Where the alignment skips a literal, a called
// function or a variable on both sides between two matched tokens, one stands
// in the place of the other: another function; so does a literal or a call the
// alignment skips on both sides anywhere, and a variable skipped on both
// sides with its counterpart, written in one place in the body and in another
// in the library function, as when two checks trade what they guard or a
// variable and a literal trade places. A statement the alignment matches must
// be held as its counterpart is (heldInPlace). The variables
// the alignment matches are checked together with the pairs sameRoles made.
// An adapted copy may merge variables (one pointer for the index and the
// element of the library function) or split one, so a variable may stand for
// several; what it may not do is cross: a variable that stands for two of the
// library function, one of which another variable stands for too, as when the
// bounds of a range trade places in a statement written as a block in one body
// and on one line in the other.
func (m *roleMapping) sameRest(libSide, ownSide restSide) bool {
	same, _ := m.alignRest(libSide, ownSide)
	return same
}

// alignRest is sameRest that returns as well how many tokens every two
// statements the alignment matches share.
func (m *roleMapping) alignRest(libSide, ownSide restSide) (bool, map[[2]int]int) {
	lib, own := libSide.tokens, ownSide.tokens
	rows, cols := len(lib)+1, len(own)+1
	switch {
	case len(own) == 0:
		return !slices.ContainsFunc(lib, isNearJump), nil
	case len(lib) == 0:
		return true, nil
	case rows*cols > maxRestAlignCells:
		return false, nil
	}
	table := restTable(lib, own)
	edges := make(map[[2]int]bool, len(m.forward))
	for from, to := range m.forward {
		edges[[2]int{from, to}] = true
	}
	libSkipped, ownSkipped := false, false
	libLeft, ownLeft := make(map[string]bool), make(map[string]bool)
	libVars, ownVars := make(map[int]bool), make(map[int]bool)
	stmts := make(map[[2]int]int)
	for i, j := 0, 0; i < len(lib) || j < len(own); {
		at := i*cols + j
		switch {
		case i < len(lib) && j < len(own) && lib[i].text == own[j].text:
			if lib[i].vr >= 0 && own[j].vr >= 0 {
				edges[[2]int{own[j].vr, lib[i].vr}] = true
			}
			stmts[[2]int{own[j].stmt, lib[i].stmt}]++
			libSkipped, ownSkipped = false, false
			i++
			j++
		case j == len(own) || i < len(lib) && table[at+cols] >= table[at+1]:
			if isNearJump(lib[i]) {
				return false, nil
			}
			libSkipped = skipToken(lib[i], libLeft, libVars) || libSkipped
			i++
		default:
			ownSkipped = skipToken(own[j], ownLeft, ownVars) || ownSkipped
			j++
		}
		if libSkipped && ownSkipped {
			return false, nil
		}
	}
	for text := range libLeft {
		if ownLeft[text] {
			return false, nil
		}
	}
	return heldInPlace(stmts, libSide, ownSide) && keptApart(edges, libVars, ownVars, libSide.roots, ownSide.roots), stmts
}

// restTable is the table of the longest common subsequence of the suffixes
// of lib and own, a row per token of lib.
func restTable(lib, own []nearToken) []uint16 {
	cols := len(own) + 1
	table := make([]uint16, (len(lib)+1)*cols)
	for i := len(lib) - 1; i >= 0; i-- {
		for j := len(own) - 1; j >= 0; j-- {
			at := i*cols + j
			switch {
			case lib[i].text == own[j].text:
				table[at] = table[at+cols+1] + 1
			case table[at+cols] >= table[at+1]:
				table[at] = table[at+cols]
			default:
				table[at] = table[at+1]
			}
		}
	}
	return table
}

// keptApart reports whether the variables keep their places: none skipped
// on both sides together with the one it stands for, and none crossing. A
// field that stands for what its variable stands for is that variable, as
// when a copy reads the slice of an element where the library function
// reads the element; two fields of one variable are two variables.
func keptApart(edges map[[2]int]bool, libVars, ownVars map[int]bool, libRoots, ownRoots map[int]int) bool {
	ownDegree, libDegree := make(map[int]int), make(map[int]int)
	kept := make([][2]int, 0, len(edges))
	for edge := range edges {
		if ownVars[edge[0]] && libVars[edge[1]] {
			return false
		}
		ownRoot, ownField := ownRoots[edge[0]]
		libRoot, libField := libRoots[edge[1]]
		if ownField && edges[[2]int{ownRoot, edge[1]}] || libField && edges[[2]int{edge[0], libRoot}] {
			continue
		}
		kept = append(kept, edge)
		ownDegree[edge[0]]++
		libDegree[edge[1]]++
	}
	for _, edge := range kept {
		if ownDegree[edge[0]] > 1 && libDegree[edge[1]] > 1 {
			return false
		}
	}
	return true
}

// skipToken records a literal or a called function the alignment skips in
// left, a variable in vars, and reports whether tok is either.
func skipToken(tok nearToken, left map[string]bool, vars map[int]bool) bool {
	switch {
	case tok.vr >= 0:
		vars[tok.vr] = true
	case tok.vr == nearAnchor:
		left[tok.text] = true
	default:
		return false
	}
	return true
}

// heldInPlace reports whether every two statements the alignment matches
// are held alike: both by no statement, by statements the alignment matches
// as well, or the one by a statement that matches the other, as a check
// written as a block in one body and on one line in the other. A statement
// moved from one branch of a check to the other, or out of a check, is not.
// The holders of a statement sameRoles left unpaired are unpaired too
// (unpairHolders), so the alignment is all that pairs them.
func heldInPlace(stmts map[[2]int]int, lib, own restSide) bool {
	for pair := range stmts {
		ownHolder, libHolder := own.roles[pair[0]].Parent, lib.roles[pair[1]].Parent
		switch {
		case ownHolder < 0 && libHolder < 0:
		case stmts[[2]int{ownHolder, libHolder}] > 0, stmts[[2]int{ownHolder, pair[1]}] > 0, stmts[[2]int{pair[0], libHolder}] > 0:
		default:
			return false
		}
	}
	return true
}

// roleMapping is the correspondence of the variables of a body with the
// variables of the library function, both ways.
type roleMapping struct{ forward, back map[int]int }

// pair makes own stand for lib, and fails when either stands for another.
// forward and back stay inverse, so when both are mapped, own standing for
// lib is lib standing for own.
func (m *roleMapping) pair(own, lib int) bool {
	to, mapped := m.forward[own]
	_, taken := m.back[lib]
	switch {
	case mapped && taken:
		return to == lib
	case mapped || taken:
		return false
	}
	m.forward[own], m.back[lib] = lib, own
	return true
}

// unify pairs a statement of the body with a statement of the library
// function of its shape: it fails, and changes nothing, when their anchors
// differ or a variable would stand for two.
func (m *roleMapping) unify(role, lib nearRole) bool {
	if role.Anchors != lib.Anchors || len(role.Locals) != len(lib.Locals) {
		return false
	}
	var added []int
	for k, local := range role.Locals {
		_, known := m.forward[local]
		if !m.pair(local, lib.Locals[k]) {
			for _, undo := range added {
				delete(m.back, m.forward[undo])
				delete(m.forward, undo)
			}
			return false
		}
		if !known {
			added = append(added, local)
		}
	}
	return true
}

// nearSimilarity is the larger of the token sequence share and the statement
// share of the two bodies. The bounds by length come first: neither share can
// exceed 2·min/(a+b), and most pairs stop there.
func nearSimilarity(c *nearCandidate, body nearBody) float64 {
	a, b := len(c.body.Tokens), len(body.Tokens)
	score := 0.0
	if 2*float64(min(a, b))/float64(a+b) >= nearCopyThreshold {
		score = 2 * float64(lcsLength(c, body.Tokens)) / float64(a+b)
	}
	sa, sb := len(c.body.Stmts), len(body.Stmts)
	if sa > 0 && sb > 0 && 2*float64(min(sa, sb))/float64(sa+sb) >= nearCopyThreshold {
		score = max(score, 2*float64(commonSorted(c.body.Stmts, body.Stmts))/float64(sa+sb))
	}
	return score
}

// lcsLength is the length of the longest common subsequence of the library
// body and tokens, by the bit-parallel algorithm of Hyyrö: one pass over
// tokens, a word operation per 64 library tokens.
func lcsLength(c *nearCandidate, tokens []string) int {
	m := len(c.body.Tokens)
	words := (m + matchWordBits - 1) / matchWordBits
	v := make([]uint64, words)
	for i := range v {
		v[i] = ^uint64(0)
	}
	for _, tok := range tokens {
		match := c.match[tok]
		if match == nil {
			continue
		}
		var carry uint64
		for i := range v {
			u := v[i] & match[i]
			sum, next := bits.Add64(v[i], u, carry)
			v[i] = sum | (v[i] &^ match[i])
			carry = next
		}
	}
	zeros := 0
	for i := range v {
		word := v[i]
		if i == words-1 && m%matchWordBits != 0 {
			word |= ^uint64(0) << (m % matchWordBits)
		}
		zeros += matchWordBits - bits.OnesCount64(word)
	}
	return zeros
}

func commonSorted(a, b []uint64) int {
	common, i, j := 0, 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			common++
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return common
}
