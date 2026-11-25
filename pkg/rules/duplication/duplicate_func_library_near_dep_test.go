package duplication

import (
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
// through a field of a variable and of every statement with a call: a call
// of a method, one that takes an address or one a slice is passed to may
// change what another statement reads. It may move a statement without a
// call that reads only values of its own, which no moved statement writes;
// an element of a slice is not the function's own. A swap through a
// temporary is one only when it puts the temporary back.
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
`, ""},
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
`, ""},
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
`, ""},
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
`, ""},
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
`, ""},
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
// through a field of a variable and of every statement with a call or an
// element; they may move a read of their own values without a call.
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
`, ""},
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
`, ""},
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
`, ""},
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

// fixedStmts lists, for every statement of body in order, whether it keeps
// its place.
func fixedStmts(body nearBody) []bool {
	var out []bool
	for _, role := range body.Roles {
		out = append(out, role.Fixed)
	}
	return out
}

// A Go statement keeps its place when it calls a function or a method, but
// len, cap or a conversion, appends, takes an address, sends, receives,
// ranges over a channel, makes a closure or a subslice; a statement that
// only holds such a statement does not itself.
func TestGoNearBodyFixed(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

type payprovList []int

func (l payprovList) Len() int { return len(l) }

func payprovRead(n int) int { return n }

func payprovUse(l payprovList, xs []int, n int, ch chan int) int {
	a := len(xs) + cap(xs)
	b := payprovList(xs)
	c := l.Len()
	d := payprovRead(n)
	xs = append(xs, n)
	p := &n
	ch <- n
	e := <-ch
	for v := range ch {
		a += v
	}
	f := func() int { return n }
	g := xs[1:]
	if a > 0 {
		a = payprovRead(a)
	}
	return a + len(b) + c + d + *p + e + f() + len(g)
}
`)
	assert.Equal(t, []bool{
		false, false, true, true, true, true, true, true,
		true, false,
		true, false, true,
		false, true,
		true,
	}, fixedStmts(bodies["payprovUse"]))
}

// A TypeScript statement keeps its place when it calls a function or a
// method, makes one, awaits, yields or constructs, but not when it reads a
// field or an element, checks or loops.
func TestTSNearBodyFixed(t *testing.T) {
	src := parseTSSource(strings.Split(`function payprovUse(out: string[], s: string, n: number): number {
  const a = out.length + out[0].length
  out.push(s)
  const f = (k: number) => k
  const g = function (k: number) { return k }
  const m = new Map()
  const t = payprovTag`+"`x`"+`
  if (n > 0) n = 1
  for (let i = 0; i < n; i++) a
  const h = f?.(n)
  const u = out[0](n)
  const v = (f)(n)
  const w = await n
  const x = yield n
  super(n)
  const y = (n)
  const k = new payprovBox
  const z = `+"`x`"+`
  const q = `+"`${n}`"+`
  return a + f(n)
}
`, "\n"))
	require.NotEmpty(t, src.funcs)
	body := src.tsNearBody(src.funcs[0], true)
	assert.Equal(t, []bool{
		true, true, true, true, false, true, true, false, false, false, false,
		true, true, true, true, true, true, false, true, false, true, true,
	}, fixedStmts(body))
}

// A Go statement keeps its place when it reads or writes what is not the
// function's own: an element of a slice or a map, a field through a
// pointer, a dereference, a range over a slice or a map, the length of a
// map, a variable of a package. A field of a value, an element of an array,
// a string and the length of a slice are its own.
func TestGoNearBodyForeignMemory(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

type payprovBox struct {
	n   int
	arr [2]int
}

var payprovCount int

func payprovUse(xs []int, m map[int]int, p *payprovBox, b payprovBox, s string, q *int, r *[2]int) int {
	a := xs[0] + m[1]
	xs[0] = a
	c := p.n
	p.n = c
	b.n = b.arr[0] + len(xs)
	b.arr[1] = int(s[0])
	d := *q
	*q = d
	for _, v := range xs {
		a += v
	}
	e := m[2]
	m[3] = e
	a += r[0]
	for k := range m {
		a += k
	}
	payprovCount++
	a += payprovCount
	return len(m)
}
`)
	assert.Equal(t, []bool{
		true, true, true, true, false, false,
		true, true, true, false,
		true, true, true, true, false, true, true, true,
	}, fixedStmts(bodies["payprovUse"]))
}

// A TypeScript statement keeps its place when it reads or writes a field or
// an element of a variable, loops over one or reads a name from outside the
// function; the length of a variable, only read, is its own.
func TestTSNearBodyForeignMemory(t *testing.T) {
	src := parseTSSource(strings.Split(`function payprovUse(xs: number[], o: { n: number }, m: Record<string, number>, k: string, f: (n: number) => number): number {
  let a = xs[0] + o.n
  xs[0] = a
  o.n += 1
  delete m[k]
  for (const v of xs) a += v
  for (const j in m) a += 1
  a = o?.n
  a = xs?.[0]
  a = f?.(1)
  a = a + 1
  a = xs.length
  a = xs.length.valueOf
  xs.length = 0
  a = payprovTotal
  a = xs.length?.valueOf
  a = xs.length[0]
  a = this.length
  a = a as payprovNum
  a = a satisfies payprovNum
  return a
}
`, "\n"))
	require.NotEmpty(t, src.funcs)
	body := src.tsNearBody(src.funcs[0], true)
	assert.Equal(t, []bool{
		true, true, true, true, true, false, true, false,
		true, true, true, false, false, true, true, true,
		true, true, true, false, true, false,
	}, fixedStmts(body))
}

// Statements that keep their place and stand for none of the other side
// stand after the same paired statement of the library function on both
// sides, as many on each.
func TestKeepsUnpairedFixed(t *testing.T) {
	plain := nearRole{Parent: -1}
	fixed := nearRole{Fixed: true, Parent: -1}
	for name, tc := range map[string]struct {
		roles, lib []nearRole
		partner    []int
		kept       bool
	}{
		"none unpaired":           {[]nearRole{fixed, plain}, []nearRole{fixed, plain}, []int{0, 1}, true},
		"one each at one place":   {[]nearRole{plain, fixed}, []nearRole{plain, fixed}, []int{0, -1}, true},
		"one each at two places":  {[]nearRole{plain, fixed}, []nearRole{fixed, plain}, []int{1, -1}, false},
		"one of its own":          {[]nearRole{plain, fixed}, []nearRole{plain}, []int{0, -1}, false},
		"one of the library":      {[]nearRole{plain}, []nearRole{plain, fixed}, []int{0}, false},
		"unpaired but not fixed":  {[]nearRole{plain, plain}, []nearRole{plain, plain}, []int{0, -1}, true},
		"after the latest paired": {[]nearRole{plain, plain, fixed}, []nearRole{plain, plain, plain, fixed}, []int{2, 0, -1}, true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.kept, keepsUnpairedFixed(tc.roles, tc.lib, tc.partner))
		})
	}
}

// A statement of the body that stands for none of the library function
// writes a value no statement after one that keeps its place reads.
func TestKeepsOwnValues(t *testing.T) {
	extra := nearRole{Locals: []int{1, 2}, Writes: []int{1}, Parent: -1}
	call := nearRole{Locals: []int{2}, Fixed: true, Parent: -1}
	read := nearRole{Locals: []int{1}, Parent: -1}
	plain := nearRole{Locals: []int{3}, Parent: -1}
	assert.False(t, keepsOwnValues([]nearRole{extra, call, read}, []int{-1, 0, 1}))
	assert.False(t, keepsOwnValues([]nearRole{extra, {Locals: []int{1}, Fixed: true, Parent: -1}}, []int{-1, 0}))
	assert.True(t, keepsOwnValues([]nearRole{extra, plain, read}, []int{-1, 0, 1}))
	assert.True(t, keepsOwnValues([]nearRole{extra, read, call}, []int{-1, 0, 1}))
	assert.True(t, keepsOwnValues([]nearRole{extra, call, read}, []int{2, 0, 1}))
	assert.True(t, keepsOwnValues([]nearRole{{Locals: []int{1}, Parent: -1}, call, read}, []int{-1, 0, 1}))
	assert.True(t, keepsOwnValues([]nearRole{call, extra, read}, []int{0, -1, 1}))
	assert.True(t, keepsOwnValues([]nearRole{extra, call}, []int{-1, 0}))
}

// keepsDependentOrder lets two statements trade places unless one writes
// what the other reads, both write one value, or one keeps its place, on
// either side; a field is read and written with its variable, two fields of
// one variable are apart, two updates of one value of one kind may trade
// places, also when a statement holds one and does nothing else to the
// value, and two statements that stand for one statement of the library
// function keep no order; a statement keeps its place against a jump that
// leaves a loop holding it on either side, though the other side holds it
// outside the loop.
func TestKeepsDependentOrder(t *testing.T) {
	roots := map[int]int{10: 1, 11: 1}
	role := func(locals, writes []int) nearRole {
		return nearRole{Locals: append(locals, writes...), Writes: writes, Parent: -1}
	}
	fixed := func(r nearRole) nearRole {
		r.Fixed = true
		return r
	}
	update := func(kind string, locals []int, v int) nearRole {
		r := role(locals, []int{v})
		r.Update = kind
		return r
	}
	plain := []nearRole{role(nil, nil), role(nil, nil), role(nil, nil), role(nil, nil)}
	for name, tc := range map[string]struct {
		roles, lib []nearRole
		partner    []int
		kept       bool
	}{
		"write and read swapped":              {[]nearRole{role(nil, []int{1}), role([]int{1}, nil)}, plain, []int{1, 0}, false},
		"writes of two variables":             {[]nearRole{role(nil, []int{1}), role([]int{2}, nil)}, plain, []int{1, 0}, true},
		"variable written, field read":        {[]nearRole{role(nil, []int{1}), role([]int{10}, nil)}, plain, []int{1, 0}, false},
		"field written, variable read":        {[]nearRole{role(nil, []int{10}), role([]int{1}, nil)}, plain, []int{1, 0}, false},
		"field written, other field read":     {[]nearRole{role(nil, []int{10}), role([]int{11}, nil)}, plain, []int{1, 0}, true},
		"two rewrites":                        {[]nearRole{role(nil, []int{1}), role(nil, []int{1})}, plain, []int{1, 0}, false},
		"two sums into one value":             {[]nearRole{update("+", []int{2}, 1), update("+", []int{3}, 1)}, plain, []int{1, 0}, true},
		"a sum and a product":                 {[]nearRole{update("+", []int{2}, 1), update("*", []int{3}, 1)}, plain, []int{1, 0}, false},
		"a sum and a rewrite":                 {[]nearRole{update("+", []int{2}, 1), role([]int{3}, []int{1})}, plain, []int{1, 0}, false},
		"a sum into two values":               {[]nearRole{update("+", []int{2}, 1), {Locals: []int{1, 4}, Writes: []int{1, 4}, Update: "+", Parent: -1}}, plain, []int{1, 0}, false},
		"sums in place":                       {[]nearRole{update("+", []int{2}, 1), update("*", []int{3}, 1)}, plain, []int{0, 1}, true},
		"variable and field rewritten":        {[]nearRole{role(nil, []int{1}), role(nil, []int{10})}, plain, []int{1, 0}, false},
		"field and variable rewritten":        {[]nearRole{role(nil, []int{10}), role(nil, []int{1})}, plain, []int{1, 0}, false},
		"two fields rewritten":                {[]nearRole{role(nil, []int{10}), role(nil, []int{11})}, plain, []int{1, 0}, true},
		"one statement split in two":          {[]nearRole{role(nil, []int{1}), role([]int{1}, nil), role([]int{2}, nil), role([]int{3}, nil)}, plain, []int{0, 0, 2, 1}, true},
		"held rewrite":                        {[]nearRole{role(nil, nil), {Locals: []int{1}, Writes: []int{1}, Parent: 0}, role(nil, []int{1})}, plain, []int{1, 2, 0}, false},
		"held sum":                            {[]nearRole{role(nil, nil), {Locals: []int{1}, Writes: []int{1}, Update: "+", Parent: 0}, update("+", nil, 1)}, plain, []int{1, 2, 0}, true},
		"held sum under a check of the value": {[]nearRole{role([]int{1}, nil), {Locals: []int{1}, Writes: []int{1}, Update: "+", Parent: 0}, update("+", nil, 1)}, plain, []int{1, 2, 0}, false},
		"held sum and product":                {[]nearRole{role(nil, nil), {Locals: []int{1}, Writes: []int{1}, Update: "+", Parent: 0}, {Locals: []int{1}, Writes: []int{1}, Update: "*", Parent: 0}, update("+", nil, 1)}, plain, []int{1, 2, 3, 0}, false},
		"held sum that reads another sum":     {[]nearRole{role(nil, nil), {Locals: []int{1, 2}, Writes: []int{1}, Update: "+", Parent: 0}, {Locals: []int{2}, Writes: []int{2}, Update: "+", Parent: 0}, update("+", nil, 2)}, plain, []int{1, 2, 3, 0}, false},
		"held rewrite of another value":       {[]nearRole{role(nil, nil), {Locals: []int{1}, Writes: []int{1}, Parent: 0}, role(nil, []int{2})}, plain, []int{1, 2, 0}, true},
		"sum that holds a sum of another":     {[]nearRole{update("+", []int{2}, 1), {Locals: []int{2}, Writes: []int{2}, Update: "+", Parent: 0}, update("+", nil, 2)}, plain, []int{1, 2, 0}, false},
		"rewrites standing for one statement": {[]nearRole{role(nil, []int{1}), role(nil, []int{1}), role(nil, nil)}, plain, []int{1, 1, 0}, true},
		"jump of the body moved":              {[]nearRole{role([]int{2}, nil), {Jump: true, Scope: -1, Parent: -1}}, plain, []int{1, 0}, false},
		"jump of the library moved":           {[]nearRole{role([]int{2}, nil), role([]int{3}, nil)}, []nearRole{{Jump: true, Scope: -1, Parent: -1}, role(nil, nil)}, []int{1, 0}, false},
		"moved past a jump of the body alone": {
			[]nearRole{role(nil, nil), {Jump: true, Scope: 0, Parent: 0}, {Parent: 0}},
			[]nearRole{role(nil, nil), role(nil, nil), {Jump: true, Scope: 1, Parent: 1}}, []int{1, 2, 0}, false},
		"moved past a jump of the library alone": {
			[]nearRole{role(nil, nil), role(nil, nil), {Jump: true, Scope: 1, Parent: 1}},
			[]nearRole{role(nil, nil), {Jump: true, Scope: 0, Parent: 0}, {Parent: 0}}, []int{2, 0, 1}, false},
		"fixed statement moved down":   {[]nearRole{fixed(role([]int{1}, nil)), role([]int{2}, nil)}, plain, []int{1, 0}, false},
		"fixed statement moved up":     {[]nearRole{role([]int{2}, nil), fixed(role([]int{1}, nil))}, plain, []int{1, 0}, false},
		"partner of a fixed one moved": {[]nearRole{role([]int{1}, nil), role([]int{2}, nil)}, []nearRole{fixed(role(nil, nil)), role(nil, nil)}, []int{1, 0}, false},
		"held fixed statement moved":   {[]nearRole{role(nil, nil), fixed(nearRole{Parent: 0}), role([]int{2}, nil)}, plain, []int{1, 2, 0}, false},
		"held fixed partner moved":     {[]nearRole{role([]int{2}, nil), role([]int{1}, nil)}, []nearRole{role(nil, nil), fixed(nearRole{Parent: 0})}, []int{1, 0}, false},
		"fixed statement in place":     {[]nearRole{fixed(role([]int{1}, nil)), role([]int{2}, nil), role([]int{3}, nil)}, plain, []int{0, 2, 1}, true},
		"fixed statement unpaired":     {[]nearRole{role([]int{2}, nil), fixed(role([]int{1}, nil)), role([]int{3}, nil)}, plain, []int{1, -1, 0}, true},

		"holder of a fixed one moved":     {[]nearRole{role([]int{2}, nil), role(nil, nil), fixed(nearRole{Parent: 1})}, plain, []int{1, 0, 2}, false},
		"fixed one after a far one":       {[]nearRole{role([]int{1}, nil), role([]int{2}, nil), fixed(role([]int{3}, nil))}, plain, []int{2, 0, 1}, false},
		"fixed statements of one partner": {[]nearRole{fixed(role(nil, nil)), fixed(role(nil, nil)), role([]int{3}, nil), role([]int{4}, nil)}, plain, []int{0, 0, 2, 1}, true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.kept, keepsDependentOrder(tc.roles, tc.lib, tc.partner, roots))
		})
	}
}

// A field that stands for a field makes its variable stand for the variable
// of the other and for nothing else, on either side; fields whose variables
// stand for nothing elsewhere keep their roots.
func TestRootsKept(t *testing.T) {
	ownRoots, libRoots := map[int]int{10: 1}, map[int]int{20: 2}
	edge := func(pairs ...[2]int) map[[2]int]bool {
		out := make(map[[2]int]bool)
		for _, pair := range pairs {
			out[pair] = true
		}
		return out
	}
	for name, tc := range map[string]struct {
		edges map[[2]int]bool
		kept  bool
	}{
		"fields and their variables":           {edge([2]int{10, 20}, [2]int{1, 2}), true},
		"fields alone":                         {edge([2]int{10, 20}, [2]int{3, 4}), true},
		"another variable for the variable":    {edge([2]int{10, 20}, [2]int{3, 2}), false},
		"the variable for another variable":    {edge([2]int{10, 20}, [2]int{1, 4}), false},
		"the variable for its own and another": {edge([2]int{10, 20}, [2]int{1, 2}, [2]int{1, 4}), true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.kept, rootsKept(tc.edges, libRoots, ownRoots))
		})
	}
}

// The partner in the body of a statement of the library function is the
// first statement that stands for it.
func TestInversePartner(t *testing.T) {
	assert.Equal(t, []int{0, 2, -1}, inversePartner([]int{0, 0, 1, -1}, 3))
}

// A jump keeps its place against the statements of the loop, the switch or
// the function it leaves, on either side, but not against the statements
// outside what it leaves.
func TestKeepsJumps(t *testing.T) {
	stmt := func(parent int) nearRole { return nearRole{Parent: parent} }
	jump := func(parent, scope int) nearRole { return nearRole{Parent: parent, Jump: true, Scope: scope} }
	// for { if c { continue }; n++ }; m++ in the order of the library.
	loop := []nearRole{stmt(-1), stmt(0), jump(1, 0), stmt(0), stmt(-1)}
	// for { if c { return } }; n++ with the return leaving the function.
	returns := []nearRole{stmt(-1), stmt(0), jump(1, -1), stmt(-1)}
	plain := []nearRole{stmt(-1), stmt(0), stmt(1), stmt(0), stmt(-1)}
	for name, tc := range map[string]struct {
		roles, lib []nearRole
		partner    []int
		kept       bool
	}{
		"in order":                          {loop, loop, []int{0, 1, 2, 3, 4}, true},
		"count moved before the continue":   {[]nearRole{stmt(-1), stmt(0), stmt(0), jump(2, 0), stmt(-1)}, loop, []int{0, 3, 1, 2, 4}, false},
		"count moved past the library jump": {[]nearRole{stmt(-1), stmt(0), stmt(0), stmt(2), stmt(-1)}, loop, []int{0, 3, 1, 2, 4}, false},
		"statement after the loop moved up": {[]nearRole{stmt(-1), stmt(-1), stmt(1), jump(2, 1), stmt(1)}, loop, []int{4, 0, 1, 2, 3}, true},
		"statement moved past a return":     {[]nearRole{stmt(-1), stmt(-1), stmt(1), jump(2, -1)}, returns, []int{3, 0, 1, 2}, false},
		"jump without a partner":            {[]nearRole{stmt(-1), stmt(0), stmt(0), jump(2, 0), stmt(-1)}, plain, []int{0, 3, 1, -1, 4}, true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.kept, keepsJumps(tc.roles, tc.partner) && keepsJumps(tc.lib, inversePartner(tc.partner, len(tc.lib))))
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
