package duplication

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
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
}

// nearAnchor marks a literal or the name of a called function in Vars.
const nearAnchor = -2

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
	Parent  int    `json:"p"`
}

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
	w := &goNearWalker{n: newFunctionBlockNormalizer(info, fd), b: newNearBodyBuilder(detailed), own: funcPackage(fd, info)}
	w.walk(fd.Body)
	return w.b.finish()
}

type goNearWalker struct {
	n   *blockNormalizer
	b   *nearBodyBuilder
	own *types.Package
	// callees holds the names of called functions not printed yet, which the
	// shape of their statement masks: a selector, printed as one atom, and
	// its last name, printed otherwise.
	callees []calleeName
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
		switch x := node.(type) {
		case *ast.ParenExpr:
			w.walk(x.X)
			return false
		case *ast.Ident:
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
		case *ast.AssignStmt:
			if x.Tok != token.ASSIGN && x.Tok != token.DEFINE {
				w.b.ops[x.Tok.String()] = true
			}
		case *ast.UnaryExpr:
			if x.Op == token.NOT {
				w.b.ops[x.Op.String()] = true
			}
		}
		if isNearStmt(node) {
			w.b.openStmt()
		}
		if isElseBlock(node, stack) {
			w.b.emit("(" + nodeKind(node))
			w.b.openStmt()
			w.b.emit("else")
		} else {
			w.b.emit("(" + nodeKind(node))
		}
		stack = append(stack, node)
		return true
	})
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
			w.b.emitLocal(num)
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
	return m.sameRest(
		restSide{tokens: unpairedTokens(c.body, libPartner), roles: c.body.Roles},
		restSide{tokens: unpairedTokens(body, ownPartner), roles: roles})
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
}

// maxRestAlignCells bounds the table of sameRest; the rest of two bodies
// larger than that is left to the share and the anchors.
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
	lib, own := libSide.tokens, ownSide.tokens
	rows, cols := len(lib)+1, len(own)+1
	if len(lib) == 0 || len(own) == 0 || rows*cols > maxRestAlignCells {
		return true
	}
	table := restTable(lib, own)
	edges := make(map[[2]int]bool, len(m.forward))
	for from, to := range m.forward {
		edges[[2]int{from, to}] = true
	}
	libSkipped, ownSkipped := false, false
	libLeft, ownLeft := make(map[string]bool), make(map[string]bool)
	libVars, ownVars := make(map[int]bool), make(map[int]bool)
	stmts := make(map[[2]int]bool)
	for i, j := 0, 0; i < len(lib) || j < len(own); {
		at := i*cols + j
		switch {
		case i < len(lib) && j < len(own) && lib[i].text == own[j].text:
			if lib[i].vr >= 0 && own[j].vr >= 0 {
				edges[[2]int{own[j].vr, lib[i].vr}] = true
			}
			stmts[[2]int{own[j].stmt, lib[i].stmt}] = true
			libSkipped, ownSkipped = false, false
			i++
			j++
		case j == len(own) || i < len(lib) && table[at+cols] >= table[at+1]:
			libSkipped = skipToken(lib[i], libLeft, libVars) || libSkipped
			i++
		default:
			ownSkipped = skipToken(own[j], ownLeft, ownVars) || ownSkipped
			j++
		}
		if libSkipped && ownSkipped {
			return false
		}
	}
	for text := range libLeft {
		if ownLeft[text] {
			return false
		}
	}
	return heldInPlace(stmts, libSide, ownSide) && keptApart(edges, libVars, ownVars)
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
// on both sides together with the one it stands for, and none crossing.
func keptApart(edges map[[2]int]bool, libVars, ownVars map[int]bool) bool {
	ownDegree, libDegree := make(map[int]int), make(map[int]int)
	for edge := range edges {
		if ownVars[edge[0]] && libVars[edge[1]] {
			return false
		}
		ownDegree[edge[0]]++
		libDegree[edge[1]]++
	}
	for edge := range edges {
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
func heldInPlace(stmts map[[2]int]bool, lib, own restSide) bool {
	for pair := range stmts {
		ownHolder, libHolder := own.roles[pair[0]].Parent, lib.roles[pair[1]].Parent
		switch {
		case ownHolder < 0 && libHolder < 0:
		case stmts[[2]int{ownHolder, libHolder}], stmts[[2]int{ownHolder, pair[1]}], stmts[[2]int{pair[0], libHolder}]:
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
