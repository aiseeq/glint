package duplication

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// The library grows a total of the package, adds through a pointer to a
// value of its own, to a field of one, and spans two bounds of a value.
const libraryForeignSource = `package lib

var Total int

func Grow(xs []int, k, lim int) int {
	Total += k
	n := Total * 2
	if n > lim {
		return lim
	}
	if n < 0 {
		return 0
	}
	for _, x := range xs {
		if x > n {
			n = x
		}
	}
	return n
}

func Twice(v, k int) int {
	ptr := &v
	*ptr += k
	w := v * 2
	if w < 0 {
		return 0
	}
	if w > 100 {
		return 100
	}
	return w
}

type Box struct{ N, M int }

func FieldTwice(b Box, k int) int {
	ptr := &b
	ptr.N += k
	w := b.N * 2
	if w < 0 {
		return 0
	}
	if w > 100 {
		return 100
	}
	return w + b.M
}

func Span(b Box, k int) int {
	lo := b.N * k
	hi := b.M + k
	v := hi - lo
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v + lo
}
`

// A statement that reads or writes what is not the function's own - a
// variable of a package, a value through a pointer, a field or an element
// of what a parameter reaches - keeps its place: nothing proves another
// statement apart from it. A copy over values of its own, its locals and
// the fields of a parameter it holds by value, may still move statements.
func TestDuplicateFuncOfLibraryNearCopyOverForeignMemory(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"total grown": {`package app

import "example.com/owner/lib"

func payprovGrow(vals []int, d, hi int) int {
	lib.Total += d
	c := lib.Total * 2
	if c > hi {
		return hi
	}
	if c < 0 {
		return 0
	}
	for _, v := range vals {
		if v > c {
			c = v
		}
	}
	return c
}
`, "duplicates function Grow of library"},
		"total doubled before it grows": {`package app

import "example.com/owner/lib"

func payprovGrow(vals []int, d, hi int) int {
	c := lib.Total * 2
	lib.Total += d
	if c > hi {
		return hi
	}
	if c < 0 {
		return 0
	}
	for _, v := range vals {
		if v > c {
			c = v
		}
	}
	return c
}
`, ""},
		"value added through a pointer": {`package app

func payprovTwice(x, d int) int {
	pt := &x
	*pt += d
	w := x * 2
	if w < 0 {
		return 0
	}
	if w > 100 {
		return 100
	}
	return w
}
`, "duplicates function Twice of library"},
		"value doubled before the pointer adds to it": {`package app

func payprovTwice(x, d int) int {
	pt := &x
	w := x * 2
	*pt += d
	if w < 0 {
		return 0
	}
	if w > 100 {
		return 100
	}
	return w
}
`, ""},
		"field doubled before the pointer adds to it": {`package app

import "example.com/owner/lib"

func payprovFieldTwice(bx lib.Box, d int) int {
	pt := &bx
	w := bx.N * 2
	pt.N += d
	if w < 0 {
		return 0
	}
	if w > 100 {
		return 100
	}
	return w + bx.M
}
`, ""},
		"bounds of a value spanned in another order": {`package app

import "example.com/owner/lib"

func payprovSpan(bx lib.Box, d int) int {
	hi := bx.M + d
	lo := bx.N * d
	v := hi - lo
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v + lo
}
`, "Function payprovSpan is a near copy (100% alike) of function Span"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, libraryForeignSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// The TypeScript library reads two getters, grows a shared state and a
// total of its module, mixes a configuration into the shared state, and
// spans two bounds.
const libraryForeignTS = `export class Ticker {
  private i = 0
  get next(): number {
    return this.i++
  }
  get seen(): number {
    return this.i
  }
}

export function readTick(t: Ticker, lim: number): number {
  const a = t.next
  const b = t.seen
  if (a > lim) return lim
  if (b === 0) return -1
  if (a < 0) return 0
  return a + b
}

export const state = { n: 0 }

export function bumpState(k: number, lim: number): number {
  state.n += k
  const v = state.n * 2
  if (v > lim) return lim
  if (v < 0) return 0
  if (v === 1) return -1
  return v
}

let total = 0

export function addTotal(k: number, lim: number): number {
  total += k
  const v = total * 2
  if (v > lim) return lim
  if (v < 0) return 0
  if (v === 1) return -1
  return v
}

export function mixDefaults(cfg: { n: number }, k: number): number {
  cfg.n = k
  const v = state.n * 2
  if (v > 100) return 100
  if (v < 0) return 0
  if (v === 1) return -1
  return v
}

export function setRead(p: { n: number }, q: { n: number }, k: number): number {
  q.n = k
  const v = p.n * 2
  if (v > 100) return 100
  if (v < 0) return 0
  if (v === 1) return -1
  return v
}

export function setGet(xs: number[], i: number, j: number, k: number): number {
  xs[i] = k
  const v = xs[j] * 2
  if (v > 100) return 100
  if (v < 0) return 0
  if (v === 1) return -1
  return v
}

export function span(lo: number, hi: number, k: number): number {
  const a = lo * k
  const b = hi - k
  const v = b - a
  if (v > hi) return hi
  if (v < lo) return lo
  return v + a
}
`

// A TypeScript statement that reads a property, which may be a getter, or
// reads or writes a name that is not the function's own, keeps its place.
func TestDuplicateFuncOfLibraryTypeScriptOverForeignMemory(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"ticks read": {`import { Ticker } from '@owner/lib'

export function payprovTick(tk: Ticker, hi: number): number {
  const x = tk.next
  const y = tk.seen
  if (x > hi) return hi
  if (y === 0) return -1
  if (x < 0) return 0
  return x + y
}
`, "duplicates function readTick of library"},
		"seen read before next raises it": {`import { Ticker } from '@owner/lib'

export function payprovTick(tk: Ticker, hi: number): number {
  const y = tk.seen
  const x = tk.next
  if (x > hi) return hi
  if (y === 0) return -1
  if (x < 0) return 0
  return x + y
}
`, ""},
		"shared state doubled before it grows": {`import { state } from '@owner/lib'

export function payprovBump(d: number, hi: number): number {
  const w = state.n * 2
  state.n += d
  if (w > hi) return hi
  if (w < 0) return 0
  if (w === 1) return -1
  return w
}
`, ""},
		"module total doubled before it grows": {`let total = 0

export function payprovAdd(d: number, hi: number): number {
  const w = total * 2
  total += d
  if (w > hi) return hi
  if (w < 0) return 0
  if (w === 1) return -1
  return w
}
`, ""},
		"shared state read before the configuration is written": {`import { state } from '@owner/lib'

export function payprovMix(c: { n: number }, d: number): number {
  const w = state.n * 2
  c.n = d
  if (w > 100) return 100
  if (w < 0) return 0
  if (w === 1) return -1
  return w
}
`, ""},
		"cell written and read": {`export function payprovSetRead(a: { n: number }, b: { n: number }, d: number): number {
  b.n = d
  const w = a.n * 2
  if (w > 100) return 100
  if (w < 0) return 0
  if (w === 1) return -1
  return w
}
`, "duplicates function setRead of library"},
		// Its read pairs with the read of setGet and leaves the writes of
		// both unpaired, at other places.
		"cell read before another is written": {`export function payprovSetRead(a: { n: number }, b: { n: number }, d: number): number {
  const w = a.n * 2
  b.n = d
  if (w > 100) return 100
  if (w < 0) return 0
  if (w === 1) return -1
  return w
}
`, ""},
		"bounds spanned in another order": {`export function payprovSpan(l: number, h: number, s: number): number {
  const y = h - s
  const x = l * s
  const v = y - x
  if (v > h) return h
  if (v < l) return l
  return v + x
}
`, "Function payprovSpan is a near copy (100% alike) of function span"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := tsForeignFindings(t, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

func tsForeignFindings(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return tsLibraryFilesFindings(t, map[string]string{
		"lib.go":        "package lib\n",
		"ts/foreign.ts": libraryForeignTS,
		"package.json":  `{"name": "@owner/lib"}`,
	}, "frontend/foreign.ts", "backend", source)
}
