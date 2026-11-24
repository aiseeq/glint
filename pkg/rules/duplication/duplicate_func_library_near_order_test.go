package duplication

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// The library scales and raises weights, wraps words, sums and counts the
// values from a floor up, finds a peak, divides, reads a byte, sets one
// counter and reads another, sums values apart by sign and tallies them.
const libraryOrderSource = `package lib

type Box struct{ N int }

func ScaleRaise(ws []int, f, cap int) int {
	total := 0
	for _, x := range ws {
		w := x
		w *= f
		w += 1
		if w > cap {
			w = cap
		}
		total += w
	}
	return total
}

func WrapOrder(words []string, sep string, width int) string {
	out := ""
	for _, w := range words {
		r := ""
		r += "["
		r += w
		r += "]"
		if len(r) > width {
			r = "[]"
		}
		out += r + sep
	}
	return out
}

func SumCount(xs []int, floor, cap int) (int, int) {
	sum, c := 0, 0
	for _, v := range xs {
		if v < floor {
			continue
		}
		sum += v
		c++
	}
	if sum > cap {
		sum = cap
	}
	return sum, c
}

func PeakCount(xs []int, start int) (int, int) {
	peak, c := start, 0
	for _, v := range xs {
		if v < 0 {
			continue
		}
		c++
		if v > peak {
			peak = v
		}
	}
	return peak, c
}

func Ratio(a, b, scale, limit int) int {
	if b == 0 {
		return 0
	}
	r := a / b
	r = r * scale
	if r > limit {
		r = limit
	}
	return r
}

func CharAt(s string, at int, fill byte) byte {
	if at < 0 || at >= len(s) {
		return fill
	}
	c := s[at]
	if c == ' ' {
		c = fill
	}
	return c
}

func Bump(a, b *Box, top int) int {
	if top < 0 {
		top = 0
	}
	b.N = top
	v := a.N * 2
	if v > top {
		v = top
	}
	return v + b.N
}

func Totals(xs []int, scale int) (int, int) {
	pos, neg := 0, 0
	for _, v := range xs {
		if v > 0 {
			pos += v * scale
		}
		if v < 0 {
			neg += v * scale
		}
	}
	return pos, neg
}

func FloatTally(xs []float64, bonus, floor, cap float64) float64 {
	total := 0.5
	for _, v := range xs {
		if v < floor {
			v = floor
		}
		total += v
		total += bonus
	}
	if total > cap {
		total = cap
	}
	return total
}

func Steps(xs []int, up, down, cap int) int {
	n := 0
	for _, v := range xs {
		if v > cap {
			continue
		}
		n++
		n += up
		n -= down
	}
	if n > cap {
		n = cap
	}
	return n
}

func CountFrom(n, step, floor int) (int, int) {
	c := 0
	for i := 0; i < n; i++ {
		if i%step == 0 {
			continue
		}
		c += i
	}
	k := step * floor
	return c, k
}

func Classify(n, step int) (int, int) {
	a, b := 0, 0
	for i := 0; i < n; i++ {
		switch i % step {
		case 0:
			continue
		case 1:
			a++
		}
		b++
	}
	return a, b
}

func Pairs(n, m, limit int) (int, int) {
	c, d := 0, 0
outer:
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			if i+j > limit {
				continue outer
			}
			c++
		}
		d++
	}
	return c, d
}

func Shift(s Box, p *Box, top int) int {
	if top < 0 {
		top = 0
	}
	p.N = top
	v := s.N * 3
	if v > top {
		v = top
	}
	return v + p.N
}

func Tally(xs []int, bonus, floor, cap int) int {
	total := 0
	for _, v := range xs {
		if v < floor {
			v = floor
		}
		total += v
		total += bonus
	}
	if total > cap {
		total = cap
	}
	return total
}
`

// A copy keeps the order of two writes of one variable unless both add to
// an integer or both multiply it, the place of a statement against a jump
// that skips it or a check that guards it, and reads no value a write
// through another pointer may change while it keeps a second name of it; a
// copy with independent statements swapped, also past a loop that a
// continue leaves, is still a copy.
func TestDuplicateFuncOfLibraryNearCopyOrderResidue(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"raised before it is scaled": {`package app

func payprovScale(ws []int, f, cap int) int {
	total := 0
	for _, x := range ws {
		w := x
		w += 1
		w *= f
		if w > cap {
			w = cap
		}
		total += w
	}
	return total
}
`, ""},
		"word before the bracket": {`package app

func payprovWrap(words []string, sep string, width int) string {
	out := ""
	for _, w := range words {
		r := ""
		r += w
		r += "["
		r += "]"
		if len(r) > width {
			r = "[]"
		}
		out += r + sep
	}
	return out
}
`, ""},
		"bonus added before the value": {`package app

func payprovTally(xs []int, bonus, floor, cap int) int {
	total := 0
	for _, v := range xs {
		if v < floor {
			v = floor
		}
		total += bonus
		total += v
	}
	if total > cap {
		total = cap
	}
	return total
}
`, "Function payprovTally is a near copy (100% alike) of function Tally"},
		"two sums into a float swapped": {`package app

func payprovTally(xs []float64, bonus, floor, cap float64) float64 {
	total := 0.5
	for _, v := range xs {
		if v < floor {
			v = floor
		}
		total += bonus
		total += v
	}
	if total > cap {
		total = cap
	}
	return total
}
`, ""},
		"increment, sum and subtraction swapped": {`package app

func payprovSteps(xs []int, up, down, cap int) int {
	n := 0
	for _, v := range xs {
		if v > cap {
			continue
		}
		n -= down
		n++
		n += up
	}
	if n > cap {
		n = cap
	}
	return n
}
`, "Function payprovSteps is a near copy (100% alike) of function Steps"},
		"product moved before the loop with a continue": {`package app

func payprovCountFrom(n, step, floor int) (int, int) {
	k := step * floor
	c := 0
	for i := 0; i < n; i++ {
		if i%step == 0 {
			continue
		}
		c += i
	}
	return c, k
}
`, "Function payprovCountFrom is a near copy (100% alike) of function CountFrom"},
		"field of a value named before the pointer writes": {`package app

type Box struct{ N int }

func payprovShift(s Box, p *Box, top int) int {
	if top < 0 {
		top = 0
	}
	old := s.N
	p.N = top
	v := old * 3
	if v > top {
		v = top
	}
	return v + p.N
}
`, "Function payprovShift is a near copy (100% alike) of function Shift"},
		"count moved before the switch with a continue": {`package app

func payprovClassify(n, step int) (int, int) {
	a, b := 0, 0
	for i := 0; i < n; i++ {
		b++
		switch i % step {
		case 0:
			continue
		case 1:
			a++
		}
	}
	return a, b
}
`, ""},
		"count moved before the loop a labelled continue leaves": {`package app

func payprovPairs(n, m, limit int) (int, int) {
	c, d := 0, 0
outer:
	for i := 0; i < n; i++ {
		d++
		for j := 0; j < m; j++ {
			if i+j > limit {
				continue outer
			}
			c++
		}
	}
	return c, d
}
`, ""},
		"sum before the guard": {`package app

func payprovSumCount(xs []int, floor, cap int) (int, int) {
	sum, c := 0, 0
	for _, v := range xs {
		sum += v
		if v < floor {
			continue
		}
		c++
	}
	if sum > cap {
		sum = cap
	}
	return sum, c
}
`, ""},
		"count before the continue": {`package app

func payprovPeak(xs []int, start int) (int, int) {
	peak, c := start, 0
	for _, v := range xs {
		c++
		if v < 0 {
			continue
		}
		if v > peak {
			peak = v
		}
	}
	return peak, c
}
`, ""},
		"count and sum swapped after the guard": {`package app

func payprovSumCount(xs []int, floor, cap int) (int, int) {
	sum, c := 0, 0
	for _, v := range xs {
		if v < floor {
			continue
		}
		c++
		sum += v
	}
	if sum > cap {
		sum = cap
	}
	return sum, c
}
`, "Function payprovSumCount is a near copy (100% alike) of function SumCount"},
		"division before the check of the divisor": {`package app

func payprovRatio(a, b, scale, limit int) int {
	r := a / b
	if b == 0 {
		return 0
	}
	r = r * scale
	if r > limit {
		r = limit
	}
	return r
}
`, ""},
		"byte read before the check of the length": {`package app

func payprovCharAt(s string, at int, fill byte) byte {
	c := s[at]
	if at < 0 || at >= len(s) {
		return fill
	}
	if c == ' ' {
		c = fill
	}
	return c
}
`, ""},
		"checks of the sign swapped": {`package app

func payprovTotals(vals []int, k int) (int, int) {
	up, down := 0, 0
	for _, x := range vals {
		if x < 0 {
			down += x * k
		}
		if x > 0 {
			up += x * k
		}
	}
	return up, down
}
`, "Function payprovTotals is a near copy (100% alike) of function Totals"},
		"counter named before the other pointer writes": {`package app

type Box struct{ N int }

func payprovBump(a, b *Box, top int) int {
	if top < 0 {
		top = 0
	}
	old := a.N
	b.N = top
	v := old * 2
	if v > top {
		v = top
	}
	return v + b.N
}
`, ""},
		"counter named after the other pointer writes": {`package app

type Box struct{ N int }

func payprovBump(a, b *Box, top int) int {
	if top < 0 {
		top = 0
	}
	b.N = top
	old := a.N
	v := old * 2
	if v > top {
		v = top
	}
	return v + b.N
}
`, "Function payprovBump is a near copy (100% alike) of function Bump"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, libraryOrderSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// The TypeScript library wraps words, scales and raises weights, sums and
// counts the values from a floor up and takes the spread of a quote.
const libraryOrderTS = `export interface Quote {
  bid: number
  ask: number
}

export function wrapOrder(words: string[], sep: string, width: number): string {
  let out = ''
  for (const w of words) {
    let r = ''
    r += '['
    r += w
    r += ']'
    if (r.length > width) r = '[]'
    out += r + sep
  }
  return out
}

export function scaleRaise(ws: number[], f: number, cap: number): number {
  let total = 0
  for (const x of ws) {
    let w = x
    w *= f
    w += 1
    if (w > cap) w = cap
    total += w
  }
  return total
}

export function sumCount(xs: number[], floor: number): number[] {
  if (floor < 0) {
    floor = 0
  }
  let sum = 0
  let c = 0
  for (const v of xs) {
    if (v < floor) continue
    sum += v
    c++
  }
  return [sum, c]
}

export function countUntil(xs: number[], stop: number, step: number): number {
  let c = 0
  for (const v of xs) {
    if (v === stop) return c
    c += step
  }
  return -c
}

export function sumBelow(xs: number[], cap: number, step: number): number {
  let c = 0
  for (const v of xs) {
    if (v > cap) throw v
    c += v * step
  }
  return c
}

export function pairs(n: number, m: number, limit: number): number[] {
  let c = 0
  let d = 0
  outer:
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < m; j++) {
      if (i + j > limit) continue outer
      c++
    }
    d++
  }
  return [c, d]
}

export function evens(xs: number[], step: number): number[] {
  let a = 0
  let b = 0
  for (const v of xs) {
    switch (v % step) {
      case 0:
        break
      default:
        a++
    }
    b++
  }
  return [a, b]
}

export function spanOf(xs: number[], floor: number): number {
  const [lo, mid, hi, top] = xs
  let span = hi - lo + mid
  if (span < floor) span = floor
  return span * top
}

export function pickNested(src: { q: Quote }, floor: number): number {
  const { q: { bid, ask } } = src
  let spread = ask - bid
  if (spread < floor) spread = floor
  return spread * 2 + bid
}

export function pickTraded(q: Quote, floor: number): number {
  const { bid, ask } = q
  let spread = ask - bid
  if (spread < floor) spread = floor
  return spread * 2 + bid
}

export function countFrom(n: number, step: number, floor: number): number[] {
  let c = 0
  for (let i = 0; i < n; i++) {
    if (i % step === 0) continue
    c += i
  }
  const k = step * floor
  return [c, k]
}

export function tally(xs: number[], bonus: number, cap: number): number {
  let total = 0
  for (const v of xs) {
    total += v
    total += bonus
  }
  if (total > cap) total = cap
  return total
}

export function quoteOf(bid: number, ask: number, floor: number): Quote {
  if (ask - bid < floor) ask = bid + floor
  if (bid < 0) bid = 0
  return { bid, ask }
}
`

// TypeScript copies keep the order of two writes of one variable, which
// may join texts, the place of a statement against a continue that skips
// it, but not against a loop it leaves, and the names of the properties
// they destructure or build an object from.
func TestDuplicateFuncOfLibraryTypeScriptOrderResidue(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"word before the bracket": {`function payprovWrap(words: string[], sep: string, width: number): string {
  let out = ''
  for (const w of words) {
    let r = ''
    r += w
    r += '['
    r += ']'
    if (r.length > width) r = '[]'
    out += r + sep
  }
  return out
}
`, ""},
		"raised before it is scaled": {`function payprovScale(ws: number[], f: number, cap: number): number {
  let total = 0
  for (const x of ws) {
    let w = x
    w += 1
    w *= f
    if (w > cap) w = cap
    total += w
  }
  return total
}
`, ""},
		"count before the return": {`function payprovCountUntil(xs: number[], stop: number, step: number): number {
  let c = 0
  for (const v of xs) {
    c += step
    if (v === stop) return c
  }
  return -c
}
`, ""},
		"sum before the throw": {`function payprovSumBelow(xs: number[], cap: number, step: number): number {
  let c = 0
  for (const v of xs) {
    c += v * step
    if (v > cap) throw v
  }
  return c
}
`, ""},
		"count moved before the loop a labelled continue leaves": {`function payprovPairs(n: number, m: number, limit: number): number[] {
  let c = 0
  let d = 0
  outer:
  for (let i = 0; i < n; i++) {
    d++
    for (let j = 0; j < m; j++) {
      if (i + j > limit) continue outer
      c++
    }
  }
  return [c, d]
}
`, ""},
		"count moved before the switch a break leaves": {`function payprovEvens(xs: number[], step: number): number[] {
  let a = 0
  let b = 0
  for (const v of xs) {
    b++
    switch (v % step) {
      case 0:
        break
      default:
        a++
    }
  }
  return [a, b]
}
`, "Function payprovEvens is a near copy (100% alike) of function evens"},
		"elements destructured under other names": {`function payprovSpan(vals: number[], least: number): number {
  const [a, b, c, d] = vals
  let width = c - a + b
  if (width < least) width = least
  return width * d
}
`, "Function payprovSpan duplicates function spanOf"},
		"nested properties destructured in the other order": {`function payprovSpread(src: { q: Quote }, floor: number): number {
  const { q: { ask, bid } } = src
  let spread = bid - ask
  if (spread < floor) spread = floor
  return spread * 2 + ask
}
`, ""},
		"nested properties destructured under other names": {`function payprovSpread(src: { q: Quote }, least: number): number {
  const { q: { bid: b, ask: a } } = src
  let gap = a - b
  if (gap < least) gap = least
  return gap * 2 + b
}
`, "Function payprovSpread duplicates function pickNested"},
		"count before the continue": {`function payprovSumCount(xs: number[], floor: number): number[] {
  if (floor < 0) {
    floor = 0
  }
  let sum = 0
  let c = 0
  for (const v of xs) {
    c++
    if (v < floor) continue
    sum += v
  }
  return [sum, c]
}
`, ""},
		"count and sum swapped after the continue": {`function payprovSumCount(xs: number[], floor: number): number[] {
  if (floor < 0) {
    floor = 0
  }
  let sum = 0
  let c = 0
  for (const v of xs) {
    if (v < floor) continue
    c++
    sum += v
  }
  return [sum, c]
}
`, "Function payprovSumCount is a near copy (100% alike) of function sumCount"},
		"product moved before the loop with a continue": {`function payprovCountFrom(n: number, step: number, floor: number): number[] {
  const k = step * floor
  let c = 0
  for (let i = 0; i < n; i++) {
    if (i % step === 0) continue
    c += i
  }
  return [c, k]
}
`, "Function payprovCountFrom is a near copy (100% alike) of function countFrom"},
		"two sums swapped, which may join texts": {`function payprovTally(xs: number[], bonus: number, cap: number): number {
  let total = 0
  for (const v of xs) {
    total += bonus
    total += v
  }
  if (total > cap) total = cap
  return total
}
`, ""},
		"properties destructured in the other order": {`function payprovSpread(q: Quote, floor: number): number {
  const { ask, bid } = q
  let spread = bid - ask
  if (spread < floor) spread = floor
  return spread * 2 + ask
}
`, ""},
		"properties destructured under other names": {`function payprovSpread(quote: Quote, least: number): number {
  const { bid: b, ask: a } = quote
  let gap = a - b
  if (gap < least) gap = least
  return gap * 2 + b
}
`, "Function payprovSpread duplicates function pickTraded"},
		"properties destructured as named": {`function payprovSpread(quote: Quote, least: number): number {
  const { bid, ask } = quote
  let gap = ask - bid
  if (gap < least) gap = least
  return gap * 2 + bid
}
`, "Function payprovSpread duplicates function pickTraded"},
		"object built under the other names": {`function payprovQuote(ask: number, bid: number, floor: number): Quote {
  if (bid - ask < floor) bid = ask + floor
  if (ask < 0) ask = 0
  return { ask, bid }
}
`, ""},
		"object built with the names as keys": {`function payprovQuote(lo: number, hi: number, least: number): Quote {
  if (hi - lo < least) hi = lo + least
  if (lo < 0) lo = 0
  return { bid: lo, ask: hi }
}
`, "Function payprovQuote duplicates function quoteOf"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := tsOrderFindings(t, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

func tsOrderFindings(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return tsLibraryFilesFindings(t, map[string]string{
		"lib.go":       "package lib\n",
		"ts/order.ts":  libraryOrderTS,
		"package.json": `{"name": "@owner/lib"}`,
	}, "frontend/order.ts", "backend", source)
}
