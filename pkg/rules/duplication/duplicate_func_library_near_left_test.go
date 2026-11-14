package duplication

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// The library counts words, scales values, reverses a slice, wraps a text
// and finds the first value above a bound.
const libraryLeftoverSource = `package lib

import "strings"

func CountWords(s string, min int) map[string]int {
	m := make(map[string]int)
	for _, w := range strings.Fields(s) {
		if len(w) < min {
			continue
		}
		w = strings.Trim(w, ".,;:")
		m[strings.ToLower(w)]++
	}
	return m
}

func Scale(xs []float64, factor, offset float64) []float64 {
	out := make([]float64, 0, len(xs))
	for _, x := range xs {
		if x == 0 {
			out = append(out, offset)
			continue
		}
		out = append(out, x*factor+offset)
	}
	return out
}

func Reverse(xs []int) int {
	n := 0
	for i, j := 0, len(xs)-1; i < j; i, j = i+1, j-1 {
		xs[i], xs[j] = xs[j], xs[i]
		n++
	}
	return n
}

func Wrap(s, pre, post string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return pre + post
	}
	if strings.HasPrefix(s, pre) {
		s = s[len(pre):]
	}
	return pre + s + post
}

func FirstAbove(xs []int, min int) int {
	if len(xs) == 0 {
		return -2
	}
	for i, x := range xs {
		if x > min {
			return i
		}
	}
	return -1
}
`

// A copy keeps the order of statements that depend on each other, writes
// a sum or a product either way round, works on a field of its receiver,
// swaps through a temporary, names a variable twice and keeps its returns;
// a function that differs there is another function.
func TestDuplicateFuncOfLibraryNearCopyLeftovers(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"trim moved after the count": {`package app

import "strings"

func payprovCount(s string, min int) map[string]int {
	m := make(map[string]int)
	for _, w := range strings.Fields(s) {
		if len(w) < min {
			continue
		}
		m[strings.ToLower(w)]++
		w = strings.Trim(w, ".,;:")
	}
	return m
}
`, ""},
		"counter moved before the swap": {`package app

func payprovReverse(vals []int) int {
	c := 0
	for lo, hi := 0, len(vals)-1; lo < hi; lo, hi = lo+1, hi-1 {
		c++
		vals[lo], vals[hi] = vals[hi], vals[lo]
	}
	return c
}
`, "Function payprovReverse is a near copy (100% alike) of function Reverse"},
		"sum written the other way round": {`package app

func payprovScale(vs []float64, k, b float64) []float64 {
	res := make([]float64, 0, len(vs))
	for _, v := range vs {
		if v == 0 {
			res = append(res, b)
			continue
		}
		res = append(res, b+v*k)
	}
	return res
}
`, "Function payprovScale is a near copy (100% alike) of function Scale"},
		"sum over fields": {`package app

type payprovScaler struct{ factor, offset float64 }

func (s payprovScaler) apply(vs []float64) []float64 {
	res := make([]float64, 0, len(vs))
	for _, v := range vs {
		if v == 0 {
			res = append(res, s.offset)
			continue
		}
		res = append(res, v*s.factor+s.offset)
	}
	return res
}
`, "Function payprovScaler.apply is a near copy (100% alike) of function Scale"},
		"sum of other values the other way round": {`package app

func payprovScale(vs []float64, k, b float64) []float64 {
	res := make([]float64, 0, len(vs))
	for _, v := range vs {
		if v == 0 {
			res = append(res, b)
			continue
		}
		res = append(res, k+v*b)
	}
	return res
}
`, ""},
		"texts joined the other way round": {`package app

import "strings"

func payprovWrap(s, pre, post string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return pre + post
	}
	if strings.HasPrefix(s, pre) {
		s = s[len(pre):]
	}
	return post + (pre + s)
}
`, ""},
		"reverse over a field": {`package app

type payprovRing struct{ xs []int }

func (r payprovRing) reverse() int {
	n := 0
	for i, j := 0, len(r.xs)-1; i < j; i, j = i+1, j-1 {
		r.xs[i], r.xs[j] = r.xs[j], r.xs[i]
		n++
	}
	return n
}
`, "Function payprovRing.reverse is a near copy (100% alike) of function Reverse"},
		"reverse over a field writing back": {`package app

type payprovRing struct{ xs []int }

func (r payprovRing) reverse() int {
	n := 0
	for i, j := 0, len(r.xs)-1; i < j; i, j = i+1, j-1 {
		r.xs[i], r.xs[j] = r.xs[i], r.xs[j]
		n++
	}
	return n
}
`, ""},
		"swap through a temporary": {`package app

func payprovReverse(vals []int) int {
	c := 0
	for lo, hi := 0, len(vals)-1; lo < hi; lo, hi = lo+1, hi-1 {
		t := vals[lo]
		vals[lo] = vals[hi]
		vals[hi] = t
		c++
	}
	return c
}
`, "Function payprovReverse is a near copy (100% alike) of function Reverse"},

		"swap of an element with itself through a temporary": {`package app

func payprovReverse(vals []int) int {
	c := 0
	for lo, hi := 0, len(vals)-1; lo < hi; lo, hi = lo+1, hi-1 {
		t := vals[lo]
		vals[lo] = vals[lo]
		vals[lo] = t
		c++
	}
	return c
}
`, ""},
		"variable named twice": {`package app

func payprovScale(vs []float64, k, b float64) []float64 {
	res := make([]float64, 0, len(vs))
	for _, v := range vs {
		y := v
		if y == 0 {
			res = append(res, b)
			continue
		}
		res = append(res, y*k+b)
	}
	return res
}
`, "Function payprovScale is a near copy (100% alike) of function Scale"},
		"variable named twice in another role": {`package app

func payprovScale(vs []float64, k, b float64) []float64 {
	res := make([]float64, 0, len(vs))
	for _, v := range vs {
		y := v
		if y == 0 {
			res = append(res, b)
			continue
		}
		res = append(res, y*k+v)
	}
	return res
}
`, ""},
		"field read into a variable": {`package app

type payprovRing struct{ xs []int }

func (r payprovRing) reverse() int {
	xs := r.xs
	n := 0
	for i, j := 0, len(xs)-1; i < j; i, j = i+1, j-1 {
		xs[i], xs[j] = xs[j], xs[i]
		n++
	}
	return n
}
`, "Function payprovRing.reverse is a near copy (100% alike) of function Reverse"},
		"returns kept": {`package app

func payprovFirst(vals []int, floor int) int {
	if len(vals) == 0 {
		return -2
	}
	for at, v := range vals {
		if v > floor {
			return at
		}
	}
	return -1
}
`, "Function payprovFirst duplicates function FirstAbove"},
		"return dropped": {`package app

func payprovFirst(vals []int, floor int) int {
	if len(vals) == 0 {
		return -2
	}
	for at, v := range vals {
		if v > floor {
			_ = at
		}
	}
	return -1
}
`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, libraryLeftoverSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// The TypeScript library counts words, pads a text, finds the least value
// and the first value above a bound.
const libraryLeftoverTS = `export function countWords(s: string, min: number): Map<string, number> {
  const m = new Map<string, number>()
  for (let w of s.split(/\s+/)) {
    if (w.length < min) continue
    w = w.replace(/[.,;:]+$/, '')
    const key = w.toLowerCase()
    m.set(key, (m.get(key) ?? 0) + 1)
  }
  return m
}

export function pad(s: string, width: number, fill: string): string {
  let out = s
  while (out.length < width) {
    out = fill + out
  }
  if (out.length > width) {
    out = out.slice(out.length - width)
  }
  return out
}

export function leastOf(xs: number[]): number {
  let best = Number.MAX_SAFE_INTEGER
  for (const x of xs) {
    if (x < best) best = x
  }
  return best
}

export function firstAbove(xs: number[], min: number): number {
  if (xs.length === 0) return -2
  for (let i = 0; i < xs.length; i++) {
    if (xs[i] > min) return i
  }
  return -1
}
`

// TypeScript copies keep the order of dependent statements, the roles of the
// fields of this, the constants of Number and their returns.
func TestDuplicateFuncOfLibraryTypeScriptLeftovers(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"key lowered before the trim": {`function payprovCount(s: string, min: number): Map<string, number> {
  const m = new Map<string, number>()
  for (let w of s.split(/\s+/)) {
    if (w.length < min) continue
    const key = w.toLowerCase()
    w = w.replace(/[.,;:]+$/, '')
    m.set(key, (m.get(key) ?? 0) + 1)
  }
  return m
}
`, ""},
		"words counted": {`function payprovCount(text: string, least: number): Map<string, number> {
  const counts = new Map<string, number>()
  for (let word of text.split(/\s+/)) {
    if (word.length < least) continue
    word = word.replace(/[.,;:]+$/, '')
    const k = word.toLowerCase()
    counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  return counts
}
`, "Function payprovCount duplicates function countWords"},
		"pad over fields": {`export class PayprovPadder {
  constructor(private width: number, private fill: string) {}
  apply(s: string): string {
    let out = s
    while (out.length < this.width) {
      out = this.fill + out
    }
    if (out.length > this.width) {
      out = out.slice(out.length - this.width)
    }
    return out
  }
}
`, "Function apply is a near copy (100% alike) of function pad"},
		"pad over fields on the right": {`export class PayprovPadder {
  constructor(private width: number, private fill: string) {}
  apply(s: string): string {
    let out = s
    while (out.length < this.width) {
      out = out + this.fill
    }
    if (out.length > this.width) {
      out = out.slice(out.length - this.width)
    }
    return out
  }
}
`, ""},
		"pad over fields in other roles": {`export class PayprovPadder {
  constructor(private width: number, private limit: number, private fill: string) {}
  apply(s: string): string {
    let out = s
    while (out.length < this.width) {
      out = this.fill + out
    }
    if (out.length > this.limit) {
      out = out.slice(out.length - this.width)
    }
    return out
  }
}
`, ""},
		"pad over fields slicing the other way": {`export class PayprovPadder {
  constructor(private width: number, private fill: string) {}
  apply(s: string): string {
    let out = s
    while (out.length < this.width) {
      out = this.fill + out
    }
    if (out.length > this.width) {
      out = out.slice(this.width - out.length)
    }
    return out
  }
}
`, ""},
		"least kept": {`function payprovLeast(values: number[]): number {
  let low = Number.MAX_SAFE_INTEGER
  for (const v of values) {
    if (v < low) low = v
  }
  return low
}
`, "Function payprovLeast duplicates function leastOf"},
		"least from the other end": {`function payprovLeast(values: number[]): number {
  let low = Number.MIN_SAFE_INTEGER
  for (const v of values) {
    if (v < low) low = v
  }
  return low
}
`, ""},
		"first kept": {`function payprovFirst(vals: number[], floor: number): number {
  if (vals.length === 0) return -2
  for (let at = 0; at < vals.length; at++) {
    if (vals[at] > floor) return at
  }
  return -1
}
`, "Function payprovFirst duplicates function firstAbove"},
		"first without its return": {`function payprovFirst(vals: number[], floor: number): number {
  if (vals.length === 0) return -2
  for (let at = 0; at < vals.length; at++) {
    if (vals[at] > floor) at
  }
  return -1
}
`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			violations := tsLeftoverFindings(t, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

func tsLeftoverFindings(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return tsLibraryFilesFindings(t, map[string]string{
		"lib.go":       "package lib\n",
		"ts/left.ts":   libraryLeftoverTS,
		"package.json": `{"name": "@owner/lib"}`,
	}, "frontend/left.ts", "backend", source)
}

// goNearBodiesOf returns the detailed near bodies of the functions of a Go
// source that imports nothing, by name.
func goNearBodiesOf(t *testing.T, source string) map[string]nearBody {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "app.go", source, 0)
	require.NoError(t, err)
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	_, err = (&types.Config{}).Check("app", fset, []*ast.File{file}, info)
	require.NoError(t, err)
	out := make(map[string]nearBody)
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok {
			out[fd.Name.Name] = goNearBody(info, fd, true)
		}
	}
	return out
}

// writtenVars lists the variables the statements of body write, in order.
func writtenVars(body nearBody) []int {
	var out []int
	for _, role := range body.Roles {
		out = append(out, role.Writes...)
	}
	return out
}

// A Go body records what every statement writes: the left side of an
// assignment down to the variable an index or a field of it writes, the
// operand of ++, and the key and the value of a range.
func TestGoNearBodyWrites(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

type payprovBox struct{ n int }

func payprovFill(xs []int, b payprovBox, m map[int]int) {
	for i, x := range xs {
		xs[i] = x
		b.n = x
		m[x]++
	}
}
`)
	// Numbered as they appear: i 0, x 1, xs 2, b 3 and its field b.n, m 4.
	assert.Equal(t, []int{0, 1, 2, nearFieldBase, 4}, writtenVars(bodies["payprovFill"]))
}

// A sum or a product of numbers, and a comparison, print the larger
// operand first; a sum of texts keeps its order.
func TestGoNearBodyCommutes(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

func payprovA(xs []int, s string) (int, bool, string) {
	return 1 + xs[0]*2, 0 == len(xs), "a" + s[1:]
}

func payprovB(xs []int, s string) (int, bool, string) {
	return xs[0]*2 + 1, len(xs) == 0, s[1:] + "a"
}
`)
	a, b := bodies["payprovA"].Tokens, bodies["payprovB"].Tokens
	require.Equal(t, len(a), len(b))
	half := slices.Index(a, `"a"`)
	require.Positive(t, half)
	assert.Equal(t, a[:half-1], b[:half-1])
	assert.NotEqual(t, a[half-1:], b[half-1:])
}

// A swap through a temporary prints as the swap it is, but when the
// temporary is read again or the three statements move other values.
func TestGoNearBodySwapsThroughATemporary(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

func payprovTuple(xs []int, i, j int) int {
	xs[i], xs[j] = xs[j], xs[i]
	return 0
}

func payprovTemp(xs []int, i, j int) int {
	t := xs[i]
	xs[i] = xs[j]
	xs[j] = t
	return 0
}

func payprovReadAgain(xs []int, i, j int) int {
	t := xs[i]
	xs[i] = xs[j]
	xs[j] = t
	return t
}

func payprovOtherSave(xs []int, i, j int) int {
	t := xs[j]
	xs[i] = xs[j]
	xs[j] = t
	return 0
}

func payprovOtherBack(xs []int, i, j int) int {
	t := xs[i]
	xs[i] = xs[j]
	xs[i] = t
	return 0
}

func payprovOtherRead(xs []int, i, j int) int {
	t := xs[i]
	u := xs[j]
	xs[i] = xs[j]
	xs[j] = u
	return t
}

func payprovTupleReturn(xs []int, i, j, t int) int {
	xs[i], xs[j] = xs[j], xs[i]
	return t
}

func payprovOtherBackRead(xs []int, i, j, u int) int {
	t := xs[i]
	xs[i] = xs[j]
	xs[j] = u
	return t
}
`)
	tuple := bodies["payprovTuple"].Tokens
	assert.Equal(t, tuple, bodies["payprovTemp"].Tokens)
	for _, name := range []string{"payprovReadAgain", "payprovOtherSave", "payprovOtherBack", "payprovOtherRead"} {
		assert.NotEqual(t, tuple, bodies[name].Tokens, name)
	}
	// Read twice, or not read back, the temporary is no swap's.
	for _, name := range []string{"payprovReadAgain", "payprovOtherBackRead"} {
		assert.NotEqual(t, bodies["payprovTupleReturn"].Tokens, bodies[name].Tokens, name)
	}
}

// A second name of a variable or of a field of one prints as what it names,
// but not when either is set again, when the second name writes into a value
// it copied, when the value is taken by address, or when it names a value
// from outside the function.
func TestGoNearBodySecondNames(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

type payprovBox struct{ xs []int; arr [2]int }

var payprovShared []int

func payprovDirect(xs []int, b payprovBox) int {
	xs[0] = b.xs[0] + 1
	return xs[1] + b.xs[1]
}

func payprovNamed(xs []int, b payprovBox) int {
	ys := xs
	zs := b.xs
	ys[0] = zs[0] + 1
	return ys[1] + zs[1]
}

func payprovRebound(xs []int, b payprovBox) int {
	ys := xs
	ys = nil
	return len(ys) + len(b.xs)
}

func payprovSourceRebound(xs []int, b payprovBox) int {
	ys := xs
	xs = nil
	return len(ys) + len(xs) + len(b.xs)
}

func payprovFieldRebound(xs []int, b payprovBox) int {
	zs := b.xs
	b.xs = nil
	return len(zs) + len(xs) + len(b.xs)
}

func payprovCopyWritten(xs []int, b payprovBox) int {
	arr := b.arr
	arr[0] = 1
	return arr[0] + b.arr[0] + len(xs)
}

func payprovSourceWritten(xs []int, b payprovBox) int {
	arr := b.arr
	b.arr[0] = 1
	return arr[0] + b.arr[0] + len(xs)
}

func payprovAddressed(xs []int, b payprovBox) int {
	ys := xs
	p := &ys
	return len(*p) + len(xs) + len(b.xs)
}

func payprovOutside(xs []int, b payprovBox) int {
	ys := payprovShared
	return len(ys) + len(xs) + len(b.xs)
}
`)
	assert.Equal(t, bodies["payprovDirect"].Tokens, bodies["payprovNamed"].Tokens)
	for name, kept := range map[string]int{
		"payprovRebound":       2,
		"payprovSourceRebound": 2,
		"payprovFieldRebound":  2,
		"payprovCopyWritten":   2,
		"payprovSourceWritten": 2,
		"payprovAddressed":     2,
		"payprovOutside":       1,
	} {
		assert.Len(t, bodies[name].Roles, kept+1, name)
	}
}

// A TypeScript body records what every statement writes: a declared name,
// an assigned one, itself or at an index, and an incremented one, but not a
// name before ++ on the next line or after ++ on the line before.
func TestTSNearBodyWrites(t *testing.T) {
	src := parseTSSource(strings.Split(`function payprovFill(xs: number[], n: number, m: number): number {
  let a = n
  xs[0] = a
  ++m
  n++
  m
  return n +
    m
}
`, "\n"))
	require.NotEmpty(t, src.funcs)
	body := src.tsNearBody(src.funcs[0], true)
	// Numbered as they appear: a 0, n 1, xs 2, m 3.
	assert.Equal(t, []int{0, 2, 3, 1}, writtenVars(body))
}
