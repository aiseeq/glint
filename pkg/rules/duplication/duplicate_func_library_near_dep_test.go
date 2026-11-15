package duplication

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// The library grows a pair from its name, joins parts, splits them into
// keys and values, measures a joined text, sums parsed fields, spreads
// sorted values and reverses a slice.
const libraryDependentSource = `package lib

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

type Pair struct {
	Name string
	Size int
}

func Grow(p Pair, min int) int {
	n := 0
	p.Name = strings.TrimSpace(p.Name)
	extra := p.Size * 2
	if len(p.Name) > min {
		n += len(p.Name)
	}
	if strings.HasPrefix(p.Name, "x") {
		n--
	}
	return n + extra
}

func Join(parts []string, sep string) string {
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(strings.TrimSpace(p))
	}
	return b.String()
}

func Split(parts []string, sep string) (string, string) {
	var keys, vals strings.Builder
	for _, p := range parts {
		k, v, _ := strings.Cut(p, sep)
		keys.WriteString(strings.TrimSpace(k))
		vals.WriteString(strings.TrimSpace(v))
	}
	return keys.String(), vals.String()
}

func Measure(parts []string, sep string) (int, int) {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p)
		b.WriteString(sep)
	}
	size := b.Len()
	text := strings.ToUpper(b.String())
	return size, len(text)
}

func SumParsed(fields []string, min int) (int, int) {
	n, total, seen := 0, 0, 0
	for _, f := range fields {
		seen++
		fmt.Sscan(f, &n)
		if n < min {
			continue
		}
		total += n
	}
	return total, seen
}

func Spread(xs []int, k int) int {
	ys := slices.Clone(xs)
	sort.Ints(ys)
	lo := ys[0]
	hi := ys[len(ys)-1]
	if hi-lo < k {
		return 0
	}
	return hi - lo
}

func Reverse(xs []int) int {
	n := 0
	for i, j := 0, len(xs)-1; i < j; i, j = i+1, j-1 {
		xs[i], xs[j] = xs[j], xs[i]
		n++
	}
	return n
}

`

// A copy keeps the order of the statements that depend on each other
// through a field of a variable, a call of its method, its address or a
// slice passed on; it may move a statement that reads another field, calls a
// method that changes nothing or works on another variable. A swap through
// a temporary is one only when it puts the temporary back.
func TestDuplicateFuncOfLibraryNearCopyDependencies(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"name read before the pair is replaced": {`package app

import (
	"strings"

	"example.com/owner/lib"
)

func payprovGrow(q lib.Pair, lim int) int {
	c := 0
	if len(q.Name) > lim {
		c += len(q.Name)
	}
	q = lib.Pair{Name: strings.TrimSpace(q.Name), Size: q.Size}
	extra := q.Size * 2
	if strings.HasPrefix(q.Name, "x") {
		c--
	}
	return c + extra
}
`, ""},
		"name read before it is trimmed": {`package app

import (
	"strings"

	"example.com/owner/lib"
)

func payprovGrow(q lib.Pair, lim int) int {
	c := 0
	extra := q.Size * 2
	if len(q.Name) > lim {
		c += len(q.Name)
	}
	q.Name = strings.TrimSpace(q.Name)
	if strings.HasPrefix(q.Name, "x") {
		c--
	}
	return c + extra
}
`, ""},
		"size read before the name is trimmed": {`package app

import (
	"strings"

	"example.com/owner/lib"
)

func payprovGrow(q lib.Pair, lim int) int {
	c := 0
	extra := q.Size * 2
	q.Name = strings.TrimSpace(q.Name)
	if len(q.Name) > lim {
		c += len(q.Name)
	}
	if strings.HasPrefix(q.Name, "x") {
		c--
	}
	return c + extra
}
`, "Function payprovGrow is a near copy (100% alike) of function Grow"},
		"separator written after each part": {`package app

import "strings"

func payprovJoin(items []string, delim string) string {
	var sb strings.Builder
	for n, it := range items {
		sb.WriteString(strings.TrimSpace(it))
		if n > 0 {
			sb.WriteString(delim)
		}
	}
	return sb.String()
}
`, ""},
		"values written before the keys": {`package app

import "strings"

func payprovSplit(items []string, delim string) (string, string) {
	var ks, vs strings.Builder
	for _, it := range items {
		k, v, _ := strings.Cut(it, delim)
		vs.WriteString(strings.TrimSpace(v))
		ks.WriteString(strings.TrimSpace(k))
	}
	return ks.String(), vs.String()
}
`, "Function payprovSplit is a near copy (100% alike) of function Split"},
		"text read before the size": {`package app

import "strings"

func payprovMeasure(items []string, delim string) (int, int) {
	var sb strings.Builder
	for _, it := range items {
		sb.WriteString(it)
		sb.WriteString(delim)
	}
	text := strings.ToUpper(sb.String())
	size := sb.Len()
	return size, len(text)
}
`, "Function payprovMeasure is a near copy (100% alike) of function Measure"},
		"size read before the parts are written": {`package app

import "strings"

func payprovMeasure(items []string, delim string) (int, int) {
	var sb strings.Builder
	size := sb.Len()
	for _, it := range items {
		sb.WriteString(it)
		sb.WriteString(delim)
	}
	text := strings.ToUpper(sb.String())
	return size, len(text)
}
`, ""},
		"bound checked before the field is parsed": {`package app

import "fmt"

func payprovSum(items []string, lim int) (int, int) {
	v, sum, count := 0, 0, 0
	for _, it := range items {
		count++
		if v < lim {
			continue
		}
		fmt.Sscan(it, &v)
		sum += v
	}
	return sum, count
}
`, ""},
		"field parsed before it is counted": {`package app

import "fmt"

func payprovSum(items []string, lim int) (int, int) {
	v, sum, count := 0, 0, 0
	for _, it := range items {
		fmt.Sscan(it, &v)
		count++
		if v < lim {
			continue
		}
		sum += v
	}
	return sum, count
}
`, "Function payprovSum is a near copy (100% alike) of function SumParsed"},
		"low read before the sort": {`package app

import (
	"slices"
	"sort"
)

func payprovSpread(vals []int, gap int) int {
	ws := slices.Clone(vals)
	lo := ws[0]
	sort.Ints(ws)
	hi := ws[len(ws)-1]
	if hi-lo < gap {
		return 0
	}
	return hi - lo
}
`, ""},
		"high read before the low": {`package app

import (
	"slices"
	"sort"
)

func payprovSpread(vals []int, gap int) int {
	ws := slices.Clone(vals)
	sort.Ints(ws)
	hi := ws[len(ws)-1]
	lo := ws[0]
	if hi-lo < gap {
		return 0
	}
	return hi - lo
}
`, "Function payprovSpread is a near copy (100% alike) of function Spread"},
		"swap through a temporary that loses a value": {`package app

func payprovReverse(vals []int) int {
	c := 0
	for lo, hi := 0, len(vals)-1; lo < hi; lo, hi = lo+1, hi-1 {
		t := vals[lo]
		vals[lo] = vals[hi]
		vals[hi] = vals[lo]
		_ = t
		c++
	}
	return c
}
`, ""},
		"swap through a temporary from the other end": {`package app

func payprovReverse(vals []int) int {
	c := 0
	for lo, hi := 0, len(vals)-1; lo < hi; lo, hi = lo+1, hi-1 {
		t := vals[hi]
		vals[hi] = vals[lo]
		vals[lo] = t
		c++
	}
	return c
}
`, "Function payprovReverse is a near copy (100% alike) of function Reverse"},
		"swap written from the other end": {`package app

func payprovReverse(vals []int) int {
	c := 0
	for lo, hi := 0, len(vals)-1; lo < hi; lo, hi = lo+1, hi-1 {
		vals[hi], vals[lo] = vals[lo], vals[hi]
		c++
	}
	return c
}
`, "Function payprovReverse is a near copy (100% alike) of function Reverse"},
		"swap written as two assignments": {`package app

func payprovReverse(vals []int) int {
	c := 0
	for lo, hi := 0, len(vals)-1; lo < hi; lo, hi = lo+1, hi-1 {
		vals[lo] = vals[hi]
		vals[hi] = vals[lo]
		c++
	}
	return c
}
`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, libraryDependentSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// The TypeScript library counts trimmed texts, joins parts, splits them into
// keys and values and spreads sorted values.
const libraryDependentTS = `export function trimCount(xs: string[], n: number): number {
  let c = 0
  for (let s of xs) {
    s = s.trim()
    if (s.length > n) c += 1
    if (s.startsWith('#')) c -= 1
  }
  return c
}

export function joinParts(parts: string[], sep: string): string[] {
  const out: string[] = []
  for (const p of parts) {
    if (out.length > 0) out.push(sep)
    out.push(p.trim())
  }
  return out
}

export function splitPairs(parts: string[], sep: string): string[][] {
  const keys: string[] = []
  const vals: string[] = []
  for (const p of parts) {
    const at = p.indexOf(sep)
    keys.push(p.slice(0, at).trim())
    vals.push(p.slice(at + 1).trim())
  }
  return [keys, vals]
}

export function spread(xs: number[], k: number): number {
  const ys = xs.slice()
  sortNumbers(ys)
  const lo = ys[0]
  const hi = ys[ys.length - 1]
  if (hi - lo < k) return 0
  return Math.max(hi - lo, 0)
}

function sortNumbers(xs: number[]): void {
  xs.sort((a, b) => a - b)
}
`

// TypeScript copies keep the order of statements that depend on each other
// through a field of a variable, a call of its method or a value passed on,
// and may move a check that only adds, a call on another value or a read.
func TestDuplicateFuncOfLibraryTypeScriptDependencies(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"length read before the trim": {`export function payprovCount(items: string[], lim: number): number {
  let k = 0
  for (let it of items) {
    if (it.length > lim) k += 1
    it = it.trim()
    if (it.startsWith('#')) k -= 1
  }
  return k
}
`, ""},
		"checks in the other order": {`export function payprovCount(items: string[], lim: number): number {
  let k = 0
  for (let it of items) {
    it = it.trim()
    if (it.startsWith('#')) k -= 1
    if (it.length > lim) k += 1
  }
  return k
}
`, "Function payprovCount is a near copy (100% alike) of function trimCount"},
		"separator pushed after each part": {`export function payprovJoin(items: string[], delim: string): string[] {
  const res: string[] = []
  for (const it of items) {
    res.push(it.trim())
    if (res.length > 0) res.push(delim)
  }
  return res
}
`, ""},
		"values pushed before the keys": {`export function payprovSplit(items: string[], delim: string): string[][] {
  const ks: string[] = []
  const vs: string[] = []
  for (const it of items) {
    const at = it.indexOf(delim)
    vs.push(it.slice(at + 1).trim())
    ks.push(it.slice(0, at).trim())
  }
  return [ks, vs]
}
`, "Function payprovSplit is a near copy (100% alike) of function splitPairs"},
		"low read before the sort": {`export function payprovSpread(vals: number[], gap: number): number {
  const ws = vals.slice()
  const lo = ws[0]
  sortNumbers(ws)
  const hi = ws[ws.length - 1]
  if (hi - lo < gap) return 0
  return Math.max(hi - lo, 0)
}
`, ""},
		"high read before the low": {`export function payprovSpread(vals: number[], gap: number): number {
  const ws = vals.slice()
  sortNumbers(ws)
  const hi = ws[ws.length - 1]
  const lo = ws[0]
  if (hi - lo < gap) return 0
  return Math.max(hi - lo, 0)
}
`, "Function payprovSpread is a near copy (100% alike) of function spread"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := tsDependentFindings(t, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

func tsDependentFindings(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return tsLibraryFilesFindings(t, map[string]string{
		"lib.go":       "package lib\n",
		"ts/dep.ts":    libraryDependentTS,
		"package.json": `{"name": "@owner/lib"}`,
	}, "frontend/dep.ts", "backend", source)
}

// changedVars lists the variables a call changes in the statements of body,
// in order.
func changedVars(body nearBody) []int {
	var out []int
	for _, role := range body.Roles {
		out = append(out, role.Changes...)
	}
	return out
}

// A Go body records what a call may change: the receiver of a method on a
// pointer or of a slice type, a slice passed to a function, the first value
// of copy and delete, what is taken by address; not the receiver of a method
// on a value, a value passed to len, the source of copy or a number passed
// on.
func TestGoNearBodyChanges(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

type payprovCounter struct{ n int }

func (c *payprovCounter) Add(k int) { c.n += k }

func (c payprovCounter) Get() int { return c.n }

type payprovList []int

func (l payprovList) Fill(v int) {
	for i := range l {
		l[i] = v
	}
}

func payprovSink(xs []int) {}

func payprovRead(n int) int { return n }

type payprovWriter interface{ Write(n int) }

func payprovSinkAny(w payprovWriter) {}

func payprovUse(c payprovCounter, l payprovList, xs, ys []int, m map[int]int, n int, w, v payprovWriter, f func([]int), zs []int) int {
	_ = c.Get()
	c.Add(1)
	l.Fill(2)
	payprovSink(xs)
	_ = len(ys)
	copy(ys, xs)
	delete(m, n)
	_ = payprovRead(n)
	_ = payprovList(xs)
	w.Write(n)
	payprovSinkAny(v)
	f(zs)
	p := &n
	return *p
}
`)
	body := bodies["payprovUse"]
	// Numbered as they appear: c 0, l 1, xs 2, ys 3, m 4, n 5, w 6, v 7,
	// f 8, zs 9, p 10.
	assert.Equal(t, []int{0, 1, 2, 3, 4, 6, 7, 9, 5}, changedVars(body))
}

// Every method, function and package the lists of calls that change nothing
// name exists, under the name types.Func.FullName gives it.
func TestGoPureCallsExist(t *testing.T) {
	imp := importer.ForCompiler(token.NewFileSet(), "source", nil)
	lookup := func(path string) *types.Package {
		pkg, err := imp.Import(path)
		require.NoError(t, err, path)
		return pkg
	}
	for path := range goPurePackages {
		lookup(path)
	}
	for name := range goPureFuncs {
		dot := strings.LastIndex(name, ".")
		fn, ok := lookup(name[:dot]).Scope().Lookup(name[dot+1:]).(*types.Func)
		require.True(t, ok, name)
		assert.Equal(t, name, fn.FullName())
	}
	for name := range goPureMethods {
		recv, method, ok := strings.Cut(strings.TrimPrefix(name, "("), ").")
		require.True(t, ok, name)
		pointer := strings.HasPrefix(recv, "*")
		recv = strings.TrimPrefix(recv, "*")
		var named types.Type
		if dot := strings.LastIndex(recv, "."); dot >= 0 {
			named = lookup(recv[:dot]).Scope().Lookup(recv[dot+1:]).Type()
		} else {
			named = types.Universe.Lookup(recv).Type()
		}
		if pointer {
			named = types.NewPointer(named)
		}
		obj, _, _ := types.LookupFieldOrMethod(named, true, nil, method)
		fn, ok := obj.(*types.Func)
		require.True(t, ok, name)
		assert.Equal(t, name, fn.FullName())
	}
}

// A TypeScript body records what a call may change: the value a method that
// changes it is called on, a value passed to a function or a constructor
// that may keep it; not the value of a method that only reads, nor what is
// passed to Math, to a method that only reads, to new Set, inside an array
// or an object, a check or the parameters of a function.
func TestTSNearBodyChanges(t *testing.T) {
	src := parseTSSource(strings.Split(`function payprovUse(out: string[], s: string, ys: number[], xs: number[], a: number, b: number, zs: number[]): number {
  out.push(s.trim())
  sortNumbers(ys)
  const m = Math.max(a, b)
  const set = new Set(xs)
  const other = new PayprovBag(xs)
  ys.sort((p, q) => p - q)
  payprovKeep(Math.abs(a), zs)
  payprovKeep([a, b, s], {a, b, s})
  function inner(k) { return k }
  if (b) return m
  if (s.startsWith(out[0])) return m
  const n = zs.items.length
  return set.size + other.size + n
}
`, "\n"))
	require.NotEmpty(t, src.funcs)
	body := src.tsNearBody(src.funcs[0], true)
	// Numbered as they appear: out 0, s 1, ys 2, m 3, a 4, b 5, set 6,
	// xs 7, other 8, p 9, q 10, zs 11.
	assert.Equal(t, []int{0, 2, 7, 2, 11}, changedVars(body))
}

// goNearBodiesImporting is goNearBodiesOf for a source that imports packages
// of the standard library.
func goNearBodiesImporting(t *testing.T, source string) map[string]nearBody {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "app.go", source, 0)
	require.NoError(t, err)
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	_, err = (&types.Config{Importer: importer.ForCompiler(fset, "source", nil)}).Check("app", fset, []*ast.File{file}, info)
	require.NoError(t, err)
	out := make(map[string]nearBody)
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok {
			out[fd.Name.Name] = goNearBody(info, fd, true)
		}
	}
	return out
}

// The functions of a package that changes nothing, the functions and the
// methods the lists name change nothing passed to them; others do.
func TestGoNearBodyChangesOfLibraryCalls(t *testing.T) {
	bodies := goNearBodiesImporting(t, `package app

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

func payprovUse(xs []string, ns []int, p []byte, x, y *big.Int) int {
	var b strings.Builder
	var buf bytes.Buffer
	_ = strings.Join(xs, ",")
	_ = fmt.Sprint(xs)
	_ = b.Len()
	_ = x.Cmp(y)
	sort.Ints(ns[1:])
	b.WriteString("a")
	buf.Read(p)
	return b.Len()
}
`)
	// Numbered as they appear: b 0, buf 1, xs 2, x 3, y 4, ns 5, p 6.
	assert.Equal(t, []int{5, 0, 1, 6}, changedVars(bodies["payprovUse"]))
}

// keepsDependentOrder lets two statements trade places unless one writes
// what the other reads, or both write it and a call changes it in one of
// them; a field is read and written with its variable, two fields of one
// variable are apart, and two statements that stand for one statement of
// the library function keep no order.
func TestKeepsDependentOrder(t *testing.T) {
	roots := map[int]int{10: 1, 11: 1}
	role := func(locals, writes, changes []int) nearRole {
		return nearRole{Locals: append(locals, writes...), Writes: writes, Changes: changes, Parent: -1}
	}
	for name, tc := range map[string]struct {
		roles   []nearRole
		partner []int
		kept    bool
	}{
		"write and read swapped":               {[]nearRole{role(nil, []int{1}, nil), role([]int{1}, nil, nil)}, []int{1, 0}, false},
		"writes of two variables":              {[]nearRole{role(nil, []int{1}, nil), role([]int{2}, nil, nil)}, []int{1, 0}, true},
		"variable written, field read":         {[]nearRole{role(nil, []int{1}, nil), role([]int{10}, nil, nil)}, []int{1, 0}, false},
		"field written, variable read":         {[]nearRole{role(nil, []int{10}, nil), role([]int{1}, nil, nil)}, []int{1, 0}, false},
		"field written, other field read":      {[]nearRole{role(nil, []int{10}, nil), role([]int{11}, nil, nil)}, []int{1, 0}, true},
		"two rewrites":                         {[]nearRole{role(nil, []int{1}, nil), role(nil, []int{1}, nil)}, []int{1, 0}, true},
		"two changes":                          {[]nearRole{role(nil, []int{1}, []int{1}), role(nil, []int{1}, []int{1})}, []int{1, 0}, false},
		"a rewrite and a change":               {[]nearRole{role(nil, []int{1}, nil), role(nil, []int{1}, []int{1})}, []int{1, 0}, false},
		"a change and a rewrite":               {[]nearRole{role(nil, []int{1}, []int{1}), role(nil, []int{1}, nil)}, []int{1, 0}, false},
		"variable and field changed":           {[]nearRole{role(nil, []int{1}, []int{1}), role(nil, []int{10}, []int{10})}, []int{1, 0}, false},
		"field and variable changed":           {[]nearRole{role(nil, []int{10}, []int{10}), role(nil, []int{1}, []int{1})}, []int{1, 0}, false},
		"variable and field rewritten":         {[]nearRole{role(nil, []int{1}, nil), role(nil, []int{10}, nil)}, []int{1, 0}, true},
		"one statement split in two":           {[]nearRole{role(nil, []int{1}, nil), role([]int{1}, nil, nil), role([]int{2}, nil, nil), role([]int{3}, nil, nil)}, []int{0, 0, 2, 1}, true},
		"held change":                          {[]nearRole{role(nil, nil, nil), {Locals: []int{1}, Writes: []int{1}, Changes: []int{1}, Parent: 0}, role(nil, []int{1}, []int{1})}, []int{1, 2, 0}, false},
		"variable rewritten, field changed":    {[]nearRole{role(nil, []int{1}, nil), role(nil, []int{10}, []int{10})}, []int{1, 0}, false},
		"held change, the holder alone paired": {[]nearRole{role(nil, nil, nil), {Locals: []int{1}, Writes: []int{1}, Changes: []int{1}, Parent: 0}, role(nil, []int{1}, nil)}, []int{1, -1, 0}, false},
		"held rewrite":                         {[]nearRole{role(nil, nil, nil), {Locals: []int{1}, Writes: []int{1}, Parent: 0}, role(nil, []int{1}, nil)}, []int{1, 2, 0}, true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.kept, keepsDependentOrder(tc.roles, tc.partner, roots))
		})
	}
}

// An assignment of several values at once is marked so, one of one value
// or of the values of one call is not.
func TestGoNearBodyParallelAssignments(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

func payprovPair() (int, int) { return 1, 2 }

func payprovSwap(a, b int) int {
	a, b = b, a+1
	a = b
	a, b = payprovPair()
	return a + b
}
`)
	var parallel []bool
	for _, role := range bodies["payprovSwap"].Roles {
		parallel = append(parallel, role.Parallel)
	}
	assert.Equal(t, []bool{true, false, false, false}, parallel)
}

// The statements of a body that stand for one assignment of several values
// at once read nothing an earlier one of them writes; for one assignment of
// one value they may.
func TestKeepsParallel(t *testing.T) {
	own := []nearRole{{Locals: []int{1, 2}, Writes: []int{1}, Parent: -1}, {Locals: []int{2, 1}, Writes: []int{2}, Parent: -1}, {Locals: []int{3}, Parent: -1}}
	assert.False(t, keepsParallel(own, []nearRole{{Parallel: true, Parent: -1}}, []int{0, 0, -1}))
	assert.True(t, keepsParallel(own, []nearRole{{Parent: -1}}, []int{0, 0, -1}))
	assert.True(t, keepsParallel(own[1:], []nearRole{{Parallel: true, Parent: -1}}, []int{0, 0}))
}

// A statement the alignment of the rest matches with several takes the one
// it shares the most tokens with, the first of those.
func TestRestPartners(t *testing.T) {
	matched := map[[2]int]int{{1, 2}: 2, {1, 3}: 2, {1, 4}: 1, {2, 5}: 1, {2, 4}: 3}
	for range 20 {
		assert.Equal(t, []int{0, 2, 4}, restPartners([]int{0, -1, -1}, matched))
	}
}

// A swap prints alike from either end; another assignment of two values
// prints as written.
func TestGoNearBodySwapOrder(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

func payprovSwap(a, b int) int {
	a, b = b, a
	return a - b
}

func payprovSwapBack(a, b int) int {
	b, a = a, b
	return a - b
}

func payprovKeepFirst(a, b int) int {
	b, a = a, 1
	return a - b
}

func payprovKeepFirstBack(a, b int) int {
	a, b = 1, a
	return a - b
}

func payprovKeepSecond(a, b int) int {
	b, a = 1, b
	return a - b
}

func payprovKeepSecondBack(a, b int) int {
	a, b = b, 1
	return a - b
}
`)
	assert.Equal(t, bodies["payprovSwap"].Tokens, bodies["payprovSwapBack"].Tokens)
	assert.NotEqual(t, bodies["payprovKeepFirst"].Tokens, bodies["payprovKeepFirstBack"].Tokens)
	assert.NotEqual(t, bodies["payprovKeepSecond"].Tokens, bodies["payprovKeepSecondBack"].Tokens)
}
