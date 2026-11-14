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
// sequence, the hashes of its statements, and the anchors a copy keeps — the
// functions it calls, its operators, its literals and package-level values. A function that calls
// another function, compares the other way or carries a value the library
// function does not is no copy of it however alike the rest is.
type nearBody struct {
	Tokens []string `json:"tokens"`
	Stmts  []uint64 `json:"stmts"`
	Calls  []string `json:"calls"`
	Ops    []string `json:"ops"`
	Lits   []string `json:"lits"`
}

// nearBodyBuilder collects a nearBody in one pass over the body: every token
// goes to the sequence and to the innermost statement that holds it, so the
// work is linear in the size of the function.
type nearBodyBuilder struct {
	body  nearBody
	open  []nearStmt
	calls map[string]bool
	ops   map[string]bool
	lits  map[string]bool
}

type nearStmt struct {
	hash  uint64
	count int
}

func newNearBodyBuilder() *nearBodyBuilder {
	return &nearBodyBuilder{calls: map[string]bool{}, ops: map[string]bool{}, lits: map[string]bool{}}
}

func (b *nearBodyBuilder) emit(tok string) {
	b.body.Tokens = append(b.body.Tokens, tok)
	if len(b.open) == 0 {
		return
	}
	top := &b.open[len(b.open)-1]
	top.hash = fnvMix(top.hash, tok)
	top.count++
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

func (b *nearBodyBuilder) openStmt() { b.open = append(b.open, nearStmt{hash: 14695981039346656037}) }

func (b *nearBodyBuilder) closeStmt() {
	last := b.open[len(b.open)-1]
	b.open = b.open[:len(b.open)-1]
	if last.count > 0 {
		b.body.Stmts = append(b.body.Stmts, last.hash)
	}
}

func (b *nearBodyBuilder) finish() nearBody {
	for len(b.open) > 0 {
		b.closeStmt()
	}
	slices.Sort(b.body.Stmts)
	b.body.Calls = slices.Sorted(maps.Keys(b.calls))
	b.body.Ops = slices.Sorted(maps.Keys(b.ops))
	b.body.Lits = slices.Sorted(maps.Keys(b.lits))
	return b.body
}

// goNearBody normalizes a Go function body for the near comparison: the
// printing of blockNormalizer, with every variable of the function as one
// placeholder, so that the numbering of variables, which follows their
// order, does not tell a copy with swapped statements from its original.
func goNearBody(info *types.Info, fd *ast.FuncDecl) nearBody {
	w := &goNearWalker{n: newFunctionBlockNormalizer(info, fd), b: newNearBodyBuilder(), own: funcPackage(fd, info)}
	w.walk(fd.Body)
	return w.b.finish()
}

type goNearWalker struct {
	n   *blockNormalizer
	b   *nearBodyBuilder
	own *types.Package
}

func (w *goNearWalker) walk(root ast.Node) {
	var stack []ast.Node
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
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
			w.b.emit(anonymousLocal(w.n.ident(x)))
			return false
		case *ast.BasicLit:
			w.b.emit(x.Value)
			w.b.lits[goLiteralValue(x)] = true
			return false
		case *ast.SelectorExpr:
			if atom, ok := w.n.selector(x); ok {
				w.packageValue(x.Sel)
				w.b.emit(anonymousLocal(atom))
				return false
			}
		case *ast.Comment, *ast.CommentGroup:
			return false
		case *ast.CallExpr:
			if callee := w.callee(x); callee != "" {
				w.b.calls[callee] = true
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
		stack = append(stack, node)
		w.b.emit("(" + nodeKind(node))
		return true
	})
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

// anonymousLocal prints every numbered variable of the function as one
// placeholder.
func anonymousLocal(tok string) string {
	if strings.HasPrefix(tok, "$L") {
		return "$L"
	}
	return tok
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
	calls string
	ops   string
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
	return &nearCandidate{fn: fn, body: body, match: match, calls: strings.Join(body.Calls, "\x00"), ops: strings.Join(body.Ops, "\x00")}
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
// or above, and the similarity.
func (idx *nearIndex) best(body nearBody) (*nearCandidate, float64) {
	if idx == nil || len(body.Tokens) < idx.minTokens {
		return nil, 0
	}
	key := strings.Join(body.Calls, "\x00") + "\x01" + strings.Join(body.Ops, "\x00")
	var best *nearCandidate
	bestScore := 0.0
	for _, c := range idx.groups[key] {
		if !subsetOf(body.Lits, c.body.Lits) {
			continue
		}
		score := nearSimilarity(c, body)
		if score >= nearCopyThreshold && score > bestScore {
			best, bestScore = c, score
		}
	}
	return best, bestScore
}

func subsetOf(sub, set []string) bool {
	for _, value := range sub {
		if _, found := slices.BinarySearch(set, value); !found {
			return false
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
