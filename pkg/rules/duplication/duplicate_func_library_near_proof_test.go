package duplication

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// The library renames a person, encodes a rune, drops a value, reads a word,
// receives a pair, prints a report, tallies through a closure, raises an
// item through a pointer, clips through a subslice, counts in a shared map,
// places values by swaps, blends two bounds and labels a person.
const libraryProofSource = `package lib

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type Person struct {
	Name string
	Tags []string
}

func (p *Person) SetName(n string) { p.Name = strings.TrimSpace(n) }

func Relabel(p *Person, n, tag string) string {
	p.SetName(n)
	if p.Name == "" {
		return "anon:" + tag
	}
	if tag == "" {
		return p.Name
	}
	return p.Name + ":" + tag
}

func Encode(buf []byte, r rune, pad byte) (byte, int) {
	n := utf8.EncodeRune(buf, r)
	head := buf[0]
	for i := n; i < len(buf); i++ {
		buf[i] = pad
	}
	if head == 0 {
		return pad, n
	}
	return head, n
}

func Remove(xs []int, i int) ([]int, int) {
	rest := append(xs[:i], xs[i+1:]...)
	last := xs[len(xs)-1]
	if len(rest) == 0 {
		return rest, -1
	}
	if last < 0 {
		return rest, 0
	}
	return rest, last
}

type Reader struct {
	B   []byte
	Pos int
}

func (r *Reader) Next() byte {
	c := r.B[r.Pos]
	r.Pos++
	return c
}

func Word(r *Reader, mask int) int {
	if r == nil {
		return 0
	}
	w := int(r.Next())<<8 | int(r.Next())
	if w&mask != 0 {
		return w & mask
	}
	return w
}

func Recv(ch chan string, sep string) string {
	k := <-ch
	v := <-ch
	if k == "" {
		return v
	}
	if v == "" {
		return k
	}
	return k + sep + v
}

func Report(xs []string, title string) int {
	fmt.Println(title)
	fmt.Println(strings.Repeat("-", len(title)))
	n := 0
	for _, x := range xs {
		fmt.Println(x)
		n++
	}
	return n
}

func Tally(xs []int, limit int) (int, int) {
	n := 0
	bump := func() { n++ }
	at := -1
	for _, x := range xs {
		bump()
		if x > limit && at < 0 {
			at = n
		}
	}
	return n, at
}

type Item struct{ N int }

func Raise(items []Item, i, k int) int {
	e := &items[i]
	e.N += k
	v := items[i].N * 2
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func Clip(xs []int, limit int) int {
	head := xs[:2]
	head[0] = limit
	first := xs[0]
	if first > limit {
		return limit
	}
	if first < 0 {
		return 0
	}
	return first
}

type Registry struct{ M map[string]int }

func (r Registry) Add(k string) { r.M[k]++ }

func (r Registry) Count(k string) int { return r.M[k] }

func Register(r Registry, k string, min int) int {
	r.Add(k)
	n := r.Count(k)
	if n < min {
		return min
	}
	if k == "" {
		return 0
	}
	return n
}

func Place(xs []int) int {
	n := 0
	for i := 0; i < len(xs); i++ {
		for xs[i] > 0 && xs[i] <= len(xs) && xs[xs[i]-1] != xs[i] {
			xs[i], xs[xs[i]-1] = xs[xs[i]-1], xs[i]
			n++
		}
	}
	return n
}

func Blend(lo, hi, k int) int {
	a := lo * k
	b := hi + k
	v := b + a*2
	if v > hi {
		return hi
	}
	if v < lo {
		return lo
	}
	return v
}

type Rect struct{ W, H, Max int }

func Area(r *Rect, k int) int {
	w := r.W * k
	h := r.H + k
	a := w * h
	if a > r.Max {
		return r.Max
	}
	if a < 0 {
		return 0
	}
	return a
}

func Label(p Person, tag string) string {
	if p.Name == "" {
		return "anon:" + tag
	}
	if len(p.Tags) > 2 {
		return p.Name + "+" + tag
	}
	if tag == "" {
		return p.Name
	}
	return p.Name + ":" + tag
}
`

// Without a proof that two statements are independent a copy keeps their
// order: a statement with a call, an address taken, a channel operation, a
// closure or a subslice keeps its place, operands with a call keep their
// order, a swap through a temporary is a swap only when its indexes are
// names or constants it does not write, and a second name stands for its
// value only when no call and no address taken come between. Fields read
// through a pointer are not the function's own and keep their order too. A
// copy that moves statements over values of its own without calls,
// commutes operands without calls or reads a value through a second name
// with no call between is still a copy.
func TestDuplicateFuncOfLibraryNearCopyWithoutProof(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"name relabeled": {`package app

import "example.com/owner/lib"

func payprovRelabel(q *lib.Person, s, t string) string {
	q.SetName(s)
	if q.Name == "" {
		return "anon:" + t
	}
	if t == "" {
		return q.Name
	}
	return q.Name + ":" + t
}
`, "duplicates function Relabel of library"},
		"old name kept under a second name before the rename": {`package app

import "example.com/owner/lib"

func payprovRelabel(q *lib.Person, s, t string) string {
	old := q.Name
	q.SetName(s)
	if old == "" {
		return "anon:" + t
	}
	if t == "" {
		return old
	}
	return old + ":" + t
}
`, ""},
		"name read under a second name": {`package app

import "example.com/owner/lib"

func payprovLabel(q lib.Person, t string) string {
	nm := q.Name
	if nm == "" {
		return "anon:" + t
	}
	if len(q.Tags) > 2 {
		return nm + "+" + t
	}
	if t == "" {
		return nm
	}
	return nm + ":" + t
}
`, "Function payprovLabel is a near copy (100% alike) of function Label"},
		"rune encoded": {`package app

import "unicode/utf8"

func payprovEncode(dst []byte, c rune, fill byte) (byte, int) {
	k := utf8.EncodeRune(dst, c)
	h := dst[0]
	for j := k; j < len(dst); j++ {
		dst[j] = fill
	}
	if h == 0 {
		return fill, k
	}
	return h, k
}
`, "duplicates function Encode of library"},
		"first byte read before the rune is encoded": {`package app

import "unicode/utf8"

func payprovEncode(dst []byte, c rune, fill byte) (byte, int) {
	h := dst[0]
	k := utf8.EncodeRune(dst, c)
	for j := k; j < len(dst); j++ {
		dst[j] = fill
	}
	if h == 0 {
		return fill, k
	}
	return h, k
}
`, ""},
		"last slot read before append shifts it": {`package app

func payprovRemove(vals []int, at int) ([]int, int) {
	l := vals[len(vals)-1]
	r := append(vals[:at], vals[at+1:]...)
	if len(r) == 0 {
		return r, -1
	}
	if l < 0 {
		return r, 0
	}
	return r, l
}
`, ""},
		"word read": {`package app

import "example.com/owner/lib"

func payprovWord(rd *lib.Reader, m int) int {
	if rd == nil {
		return 0
	}
	v := int(rd.Next())<<8 | int(rd.Next())
	if v&m != 0 {
		return v & m
	}
	return v
}
`, "duplicates function Word of library"},
		"word read little-endian": {`package app

import "example.com/owner/lib"

func payprovWord(rd *lib.Reader, m int) int {
	if rd == nil {
		return 0
	}
	v := int(rd.Next()) | int(rd.Next())<<8
	if v&m != 0 {
		return v & m
	}
	return v
}
`, ""},
		"value received first": {`package app

func payprovRecv(c chan string, s string) string {
	val := <-c
	key := <-c
	if key == "" {
		return val
	}
	if val == "" {
		return key
	}
	return key + s + val
}
`, ""},
		"underline printed above the title": {`package app

import (
	"fmt"
	"strings"
)

func payprovReport(rows []string, head string) int {
	fmt.Println(strings.Repeat("-", len(head)))
	fmt.Println(head)
	c := 0
	for _, r := range rows {
		fmt.Println(r)
		c++
	}
	return c
}
`, ""},
		"count noted before the closure raises it": {`package app

func payprovTally(vals []int, lim int) (int, int) {
	c := 0
	inc := func() { c++ }
	pos := -1
	for _, v := range vals {
		if v > lim && pos < 0 {
			pos = c
		}
		inc()
	}
	return c, pos
}
`, ""},
		"value read before the write through the pointer": {`package app

import "example.com/owner/lib"

func payprovRaise(list []lib.Item, at, d int) int {
	p := &list[at]
	r := list[at].N * 2
	p.N += d
	if r < 0 {
		return 0
	}
	if r > 100 {
		return 100
	}
	return r
}
`, ""},
		"first value read before the write through the subslice": {`package app

func payprovClip(vals []int, lim int) int {
	h := vals[:2]
	f := vals[0]
	h[0] = lim
	if f > lim {
		return lim
	}
	if f < 0 {
		return 0
	}
	return f
}
`, ""},
		"count read before the key is added through a value receiver": {`package app

import "example.com/owner/lib"

func payprovRegister(reg lib.Registry, key string, lo int) int {
	c := reg.Count(key)
	reg.Add(key)
	if c < lo {
		return lo
	}
	if key == "" {
		return 0
	}
	return c
}
`, ""},
		"swap through a temporary whose index reads the new value": {`package app

func payprovPlace(vals []int) int {
	c := 0
	for k := 0; k < len(vals); k++ {
		for vals[k] > 0 && vals[k] <= len(vals) && vals[vals[k]-1] != vals[k] {
			t := vals[k]
			vals[k] = vals[vals[k]-1]
			vals[vals[k]-1] = t
			c++
		}
	}
	return c
}
`, ""},
		"values placed": {`package app

func payprovPlace(vals []int) int {
	c := 0
	for k := 0; k < len(vals); k++ {
		for vals[k] > 0 && vals[k] <= len(vals) && vals[vals[k]-1] != vals[k] {
			vals[k], vals[vals[k]-1] = vals[vals[k]-1], vals[k]
			c++
		}
	}
	return c
}
`, "duplicates function Place of library"},
		"fields read through a pointer in another order": {`package app

import "example.com/owner/lib"

func payprovArea(q *lib.Rect, s int) int {
	h := q.H + s
	w := q.W * s
	a := w * h
	if a > q.Max {
		return q.Max
	}
	if a < 0 {
		return 0
	}
	return a
}
`, ""},
		"bounds blended in another order and operands commuted": {`package app

func payprovBlend(l, h, s int) int {
	y := h + s
	x := l * s
	v := x*2 + y
	if v > h {
		return h
	}
	if v < l {
		return l
	}
	return v
}
`, "Function payprovBlend is a near copy (100% alike) of function Blend"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, libraryProofSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// The TypeScript library merges a configuration, tallies through a closure,
// touches a cache, prints a report and limits two bounds.
const libraryProofTS = `export interface Cfg {
  size: number
}

export function mergeCfg(cfg: Cfg, extra: object, min: number): number {
  Object.assign(cfg, extra)
  const n = cfg.size
  if (n < min) return min
  if (n > 100) return 100
  return n
}

export function tally(xs: number[], limit: number): [number, number] {
  let n = 0
  const bump = () => { n++ }
  let at = -1
  for (const x of xs) {
    bump()
    if (x > limit && at < 0) at = n
  }
  return [n, at]
}

export interface Lru {
  get(k: string): string | undefined
  keys(): IterableIterator<string>
}

export function touch(c: Lru, k: string, d: string): string {
  const v = c.get(k)
  const oldest = c.keys().next().value
  if (v === undefined) return d
  if (oldest === k) return v
  return v + ':' + oldest
}

export function report(xs: string[], title: string): number {
  console.log(title)
  console.log('-'.repeat(title.length))
  let n = 0
  for (const x of xs) {
    console.log(x)
    n++
  }
  return n
}

export function bound(lo: number, hi: number, k: number): number {
  const a = lo * k
  const b = hi + k
  const v = b + a
  if (v > hi) return hi
  if (v < lo) return lo
  return v
}
`

// A TypeScript copy keeps the place of a statement with a call or a closure
// and may move statements without them.
func TestDuplicateFuncOfLibraryTypeScriptWithoutProof(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"configuration merged": {`export function payprovMerge(c: { size: number }, more: object, lo: number): number {
  Object.assign(c, more)
  const k = c.size
  if (k < lo) return lo
  if (k > 100) return 100
  return k
}
`, "duplicates function mergeCfg of library"},
		"size read before the merge": {`export function payprovMerge(c: { size: number }, more: object, lo: number): number {
  const k = c.size
  Object.assign(c, more)
  if (k < lo) return lo
  if (k > 100) return 100
  return k
}
`, ""},
		"count noted before the closure raises it": {`export function payprovTally(vals: number[], lim: number): [number, number] {
  let c = 0
  const inc = () => { c++ }
  let pos = -1
  for (const v of vals) {
    if (v > lim && pos < 0) pos = c
    inc()
  }
  return [c, pos]
}
`, ""},
		"oldest key taken before get moves the key": {`export function payprovTouch(cache: { get(k: string): string | undefined, keys(): IterableIterator<string> }, key: string, def: string): string {
  const first = cache.keys().next().value
  const val = cache.get(key)
  if (val === undefined) return def
  if (first === key) return val
  return val + ':' + first
}
`, ""},
		"underline printed above the title": {`export function payprovReport(rows: string[], head: string): number {
  console.log('-'.repeat(head.length))
  console.log(head)
  let c = 0
  for (const r of rows) {
    console.log(r)
    c++
  }
  return c
}
`, ""},
		"bounds limited in another order": {`export function payprovBound(l: number, h: number, s: number): number {
  const y = h + s
  const x = l * s
  const v = y + x
  if (v > h) return h
  if (v < l) return l
  return v
}
`, "Function payprovBound is a near copy (100% alike) of function bound"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := tsProofFindings(t, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

func tsProofFindings(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return tsLibraryFilesFindings(t, map[string]string{
		"lib.go":       "package lib\n",
		"ts/proof.ts":  libraryProofTS,
		"package.json": `{"name": "@owner/lib"}`,
	}, "frontend/proof.ts", "backend", source)
}
