package duplication

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The library sets another field of one pointer and reads a field of the
// other, reads one field and then sets it through the other pointer, or
// increments it, replaces a value that may hold it, sets it in a loop that
// reads it, or before a goto back, reads it in a statement with a call that
// sets it, copies a value with fields after another pointer sets one,
// checks one pointer and reads a field of the other, adds with plain
// assignments, adds or multiplies on a condition, adds a value a check
// reads or adds on a check of the value, adds in a loop, and counts the
// values a switch breaks out of.
const libraryLostSource = `package lib

type Box struct{ N, M int }

type Outer struct{ In Box }

func BumpOther(a, b *Box, top int) int {
	if top < 0 {
		top = 0
	}
	b.M = top
	v := a.N * 2
	if v > top {
		v = top
	}
	return v + b.M
}

func BumpAfter(a, b *Box, top int) int {
	if top < 0 {
		top = 0
	}
	v := a.N * 2
	b.N = top
	if v > top {
		v = top
	}
	return v + b.N
}

func BumpInc(a, b *Box, top int) int {
	if top < 0 {
		top = 0
	}
	b.N++
	v := a.N * 2
	if v > top {
		v = top
	}
	return v + b.N
}

func BumpInner(a *Box, b *Outer, top int) int {
	if top < 0 {
		top = 0
	}
	b.In = Box{M: top}
	v := a.N * 2
	if v > top {
		v = top
	}
	return v + b.In.M
}

func KeepIn(a *Outer, b *Box, xs []int, top int) Box {
	if top < 0 {
		top = 0
	}
	b.M = top
	v := a.In
	if v.N > top {
		v.N = top
	}
	for _, x := range xs {
		v.M -= x * 2
	}
	return v
}

func BumpEach(a, b *Box, xs []int, top int) int {
	t := 0
	for _, x := range xs {
		v := a.N * 2
		b.N = x
		if v > top {
			v = top
		}
		t += v
	}
	return t * 3
}

func BumpAgain(a, b *Box, top int) int {
	if top < 0 {
		top = 0
	}
again:
	v := a.N * 2
	b.N = top
	if v > top {
		top++
		goto again
	}
	return v + b.N
}

func Stepped(a, b *Box, top int) int {
	if top < 0 {
		top = 0
	}
	v := a.N * step(b)
	if v > top {
		v = top
	}
	return v + b.N
}

func step(b *Box) int {
	b.N++
	return 2
}

func Guard(p, q *Box, top int) int {
	if q == nil {
		return top
	}
	v := p.N * 2
	if v > top {
		v = top
	}
	for i := 0; i < top; i++ {
		v += i
	}
	return v + top
}

func BumpLoop(a, b *Box, xs []int, top int) int {
	t := 0
	for _, x := range xs {
		v := a.N * 2
		b.N = x
		if v > top {
			v = top
		}
		t += v
	}
	return t
}

func PlainLit(xs []int, k, lim int) int {
	t := 0
	for _, x := range xs {
		m := x
		m = m + 2
		m = m + k
		if m > lim {
			m = lim
		}
		t += m
	}
	return t
}

func PlainFrom(xs []int, k, lim int) int {
	t := 0
	for _, x := range xs {
		m := x
		m = m + 2
		m = k - m
		if m > lim {
			m = lim
		}
		t += m
	}
	return t
}

func PlainTwice(xs []int, k, lim int) int {
	t := 0
	for _, x := range xs {
		m := x
		m = m + 2
		m = m + m
		if m > lim {
			m = lim
		}
		t += m
	}
	return t
}

func CondAdd(xs []int, c bool, lim int) int {
	t := 0
	for _, x := range xs {
		m := x
		if c {
			m += 1
		}
		m += 2
		if m > lim {
			m = lim
		}
		t += m
	}
	return t
}

func CondMul(xs []int, c bool, lim int) int {
	t := 0
	for _, x := range xs {
		m := x
		if c {
			m *= 3
		}
		m += 2
		if m > lim {
			m = lim
		}
		t -= m
	}
	return t
}

func CondRead(xs []int, c bool, k, lim int) int {
	t := 0
	for _, x := range xs {
		m := x
		if c {
			m += k
			k++
		}
		k += 2
		if m > lim {
			m = lim
		}
		t += m * k
	}
	return t
}

func CondCheck(xs []int, lim int) int {
	t := 0
	for _, x := range xs {
		m := x
		if m > 3 {
			m += 1
		}
		m += 2
		if m > lim {
			m = lim
		}
		t ^= m
	}
	return t
}

func LoopAdd(n, k, lim int) int {
	m := k
	for i := 0; i < n; i++ {
		if i*k > lim {
			break
		}
		m += i
	}
	m += 2
	if m > lim {
		m = lim
	}
	return m * 3
}

func Classes(xs []int, lim int) (int, int) {
	a, b := 0, 0
	for _, v := range xs {
		b += v
		switch v % 3 {
		case 1:
			if v > lim {
				break
			}
			a++
		}
	}
	return a, b
}
`

// A copy may name a field of a pointer and keep the name past a write
// through another pointer that cannot reach the field — another field, both
// of a basic type — and past a write after the statement that reads the
// name last, also in a loop that names it anew, but not past a write in a
// loop that reads the name again or before a goto; a field of one pointer
// in the place of the field of another is no copy, also when every
// statement pairs by shape and the body adds one. A copy may swap two plain additions to an
// integer, and a statement that holds only additions to an integer, a check
// or a loop, with an addition to it, but not an assignment that reads the
// value in another place than an addition, nor a check that multiplies,
// reads what it adds to or reads the value in its condition. A break in a
// switch leaves the switch alone.
func TestDuplicateFuncOfLibraryNearCopyLostCopies(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"field named before the other pointer sets another field": {`package app

type Box struct{ N, M int }

func payprovBump(p, q *Box, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.N
	q.M = limit
	r := was * 2
	if r > limit {
		r = limit
	}
	return r + q.M
}
`, "Function payprovBump is a near copy (100% alike) of function BumpOther"},
		"field named and read before the other pointer sets it": {`package app

type Box struct{ N, M int }

func payprovBump(p, q *Box, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.N
	r := was * 2
	q.N = limit
	if r > limit {
		r = limit
	}
	return r + q.N
}
`, "Function payprovBump is a near copy (100% alike) of function BumpAfter"},
		"field named before the other pointer increments it": {`package app

type Box struct{ N, M int }

func payprovBump(p, q *Box, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.N
	q.N++
	r := was * 2
	if r > limit {
		r = limit
	}
	return r + q.N
}
`, ""},
		"field named before a value that may hold it is replaced": {`package app

type Box struct{ N, M int }

type Outer struct{ In Box }

func payprovBump(p *Box, q *Outer, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.N
	q.In = Box{M: limit}
	r := was * 2
	if r > limit {
		r = limit
	}
	return r + q.In.M
}
`, ""},
		"field named before a loop that reads it after the other pointer sets it": {`package app

type Box struct{ N, M int }

func payprovBump(p, q *Box, vals []int, limit int) int {
	sum := 0
	was := p.N
	for _, x := range vals {
		r := was * 2
		q.N = x
		if r > limit {
			r = limit
		}
		sum += r
	}
	return sum
}
`, ""},
		"field named in a loop before the other pointer sets it after the read": {`package app

type Box struct{ N, M int }

func payprovBump(p, q *Box, vals []int, limit int) int {
	sum := 0
	for _, x := range vals {
		was := p.N
		r := was * 2
		q.N = x
		if r > limit {
			r = limit
		}
		sum += r
	}
	return sum * 3
}
`, "Function payprovBump is a near copy (100% alike) of function BumpEach"},
		"value with fields named before the other pointer sets a field": {`package app

type Box struct{ N, M int }

type Outer struct{ In Box }

func payprovKeep(p *Outer, q *Box, vals []int, limit int) Box {
	if limit < 0 {
		limit = 0
	}
	was := p.In
	q.M = limit
	r := was
	if r.N > limit {
		r.N = limit
	}
	for _, x := range vals {
		r.M -= x * 2
	}
	return r
}
`, ""},
		"field named before a write a goto runs the read again after": {`package app

type Box struct{ N, M int }

func payprovBump(p, q *Box, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.N
again:
	r := was * 2
	q.N = limit
	if r > limit {
		limit++
		goto again
	}
	return r + q.N
}
`, ""},
		"field named before a call in the statement that reads the name": {`package app

type Box struct{ N, M int }

func payprovBump(p, q *Box, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.N
	r := was * step(q)
	if r > limit {
		r = limit
	}
	return r + q.N
}

func step(b *Box) int {
	b.N++
	return 2
}
`, ""},
		"field of the pointer the check reads in the place of the other": {`package app

type Box struct{ N, M int }

func payprovGuard(p, q *Box, limit int) int {
	if q == nil {
		return limit
	}
	r := q.N * 2
	if r > limit {
		r = limit
	}
	for j := 0; j < limit; j++ {
		r += j
	}
	return r + limit
}
`, ""},
		"field of the pointer the check reads in the place of the other, with a statement more": {`package app

type Box struct{ N, M int }

func payprovGuard(p, q *Box, limit int) int {
	if q == nil {
		return limit
	}
	r := q.N * 2
	if r > limit {
		r = limit
	}
	for j := 0; j < limit; j++ {
		r += j
	}
	limit++
	return r + limit
}
`, ""},
		"guard renamed": {`package app

type Box struct{ N, M int }

func payprovGuard(a, b *Box, limit int) int {
	if b == nil {
		return limit
	}
	r := a.N * 2
	if r > limit {
		r = limit
	}
	for j := 0; j < limit; j++ {
		r += j
	}
	return r + limit
}
`, "Function payprovGuard duplicates function Guard"},
		"plain additions swapped": {`package app

func payprovPlain(vals []int, k, most int) int {
	sum := 0
	for _, v := range vals {
		g := v
		g = g + k
		g = g + 2
		if g > most {
			g = most
		}
		sum += g
	}
	return sum
}
`, "Function payprovPlain is a near copy (100% alike) of function PlainLit"},
		"addition swapped with a subtraction from a value": {`package app

func payprovPlain(vals []int, k, most int) int {
	sum := 0
	for _, v := range vals {
		g := v
		g = k - g
		g = g + 2
		if g > most {
			g = most
		}
		sum += g
	}
	return sum
}
`, ""},
		"addition swapped with a doubling": {`package app

func payprovPlain(vals []int, k, most int) int {
	sum := 0
	for _, v := range vals {
		g := v
		g = g + g
		g = g + 2
		if g > most {
			g = most
		}
		sum += g
	}
	return sum
}
`, ""},
		"addition moved before a check that adds": {`package app

func payprovCond(vals []int, on bool, most int) int {
	sum := 0
	for _, v := range vals {
		g := v
		g += 2
		if on {
			g += 1
		}
		if g > most {
			g = most
		}
		sum += g
	}
	return sum
}
`, "Function payprovCond is a near copy (100% alike) of function CondAdd"},
		"addition moved before a check that multiplies": {`package app

func payprovCond(vals []int, on bool, most int) int {
	sum := 0
	for _, v := range vals {
		g := v
		g += 2
		if on {
			g *= 3
		}
		if g > most {
			g = most
		}
		sum -= g
	}
	return sum
}
`, ""},
		"addition moved before a check that reads what it adds to": {`package app

func payprovCond(vals []int, on bool, k, most int) int {
	sum := 0
	for _, v := range vals {
		g := v
		k += 2
		if on {
			g += k
			k++
		}
		if g > most {
			g = most
		}
		sum += g * k
	}
	return sum
}
`, ""},
		"addition moved before a check of the value": {`package app

func payprovCond(vals []int, most int) int {
	sum := 0
	for _, v := range vals {
		g := v
		g += 2
		if g > 3 {
			g += 1
		}
		if g > most {
			g = most
		}
		sum ^= g
	}
	return sum
}
`, ""},
		"addition moved before a loop that adds": {`package app

func payprovLoop(n, k, most int) int {
	g := k
	g += 2
	for j := 0; j < n; j++ {
		if j*k > most {
			break
		}
		g += j
	}
	if g > most {
		g = most
	}
	return g * 3
}
`, "Function payprovLoop is a near copy (100% alike) of function LoopAdd"},
		"sum moved past a switch a break leaves": {`package app

func payprovClasses(vals []int, most int) (int, int) {
	x, y := 0, 0
	for _, v := range vals {
		switch v % 3 {
		case 1:
			if v > most {
				break
			}
			x++
		}
		y += v
	}
	return x, y
}
`, "Function payprovClasses is a near copy (100% alike) of function Classes"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, libraryLostSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// An assignment updates an integer when it reads it only to add to it, or
// to multiply it, or to set, clear or flip bits of it, with the operator of
// the assignment or as m = m + k; another assignment, one that reads the
// value again, and one of a float update nothing.
func TestGoNearBodyUpdates(t *testing.T) {
	bodies := goNearBodiesOf(t, `package app

func payprovUpdates(xs [4]int, m, k int, f float64) (int, float64) {
	m += k
	m -= k
	m++
	m = m + k
	m = k + m
	m = m - k
	m = m * k
	m = m | k
	m = m & k
	m = m ^ k
	m *= k
	m = k - m
	m = m + m
	m += m
	m = m &^ k
	m = k
	xs[xs[0]] += 1
	xs[k] += 1
	f += 1
	return m + xs[0], f
}
`)
	var kinds []string
	for _, role := range bodies["payprovUpdates"].Roles {
		if len(role.Writes) > 0 {
			kinds = append(kinds, role.Update)
		}
	}
	assert.Equal(t, []string{"+", "+", "+", "+", "+", "+", "*", "|", "&", "^", "*", "", "", "", "", "", "", "+", ""}, kinds)
}

// The TypeScript library counts in a do loop with a continue, counts in two
// loops with a continue to the outer one under a label named as a
// parameter, and sums in a switch of a callback made in a conditional.
const libraryLostTS = `export function doFrom(n: number, step: number, floor: number): number[] {
  let i = 0
  let c = 0
  do {
    i++
    if (i % step === 0) continue
    c += i
  } while (i < n)
  const k = step * floor
  return [c, k]
}

export function rows(n: number, m: number, limit: number): number[] {
  let c = 0
  let d = 0
  limit: for (let i = 0; i < n; i++) {
    for (let j = 0; j < m; j++) {
      if (i + j > n) continue limit
      c++
    }
    d++
  }
  return [c, d]
}

export function caseArrow(on: boolean, xs: number[], step: number): number {
  let total = 0
  const pick = on ? (v: number) => { switch (v % step) { case 0: { total = total + v } } } : null
  for (const x of xs) {
    if (pick) pick(x)
  }
  return total
}
`

// A continue in a do loop leaves the loop, so a statement after the loop
// may move before it, but not one in the loop past the continue; a jump to
// a label leaves the function, also when a variable is named as the label;
// a brace after the colon of a case in a callback the first branch of a
// conditional makes opens a block, whose names are variables.
func TestDuplicateFuncOfLibraryTypeScriptLostCopies(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"product moved before the do loop with a continue": {`function payprovDo(n: number, step: number, floor: number): number[] {
  const k = step * floor
  let i = 0
  let c = 0
  do {
    i++
    if (i % step === 0) continue
    c += i
  } while (i < n)
  return [c, k]
}
`, "Function payprovDo is a near copy (100% alike) of function doFrom"},
		"sum moved before the continue of the do loop": {`function payprovDo(n: number, step: number, floor: number): number[] {
  let i = 0
  let c = 0
  do {
    i++
    c += i
    if (i % step === 0) continue
  } while (i < n)
  const k = step * floor
  return [c, k]
}
`, ""},
		"count moved before the loop a continue to a label named as a parameter leaves": {`function payprovRows(n: number, m: number, limit: number): number[] {
  let c = 0
  let d = 0
  limit: for (let i = 0; i < n; i++) {
    d++
    for (let j = 0; j < m; j++) {
      if (i + j > n) continue limit
      c++
    }
  }
  return [c, d]
}
`, ""},
		"block of a case in a callback of a conditional, renamed": {`function payprovCase(flag: boolean, vals: number[], k: number): number {
  let sum = 0
  const pick = flag ? (v: number) => { switch (v % k) { case 0: { sum = sum + v } } } : null
  for (const x of vals) {
    if (pick) pick(x)
  }
  return sum
}
`, "Function payprovCase duplicates function caseArrow"},
	} {
		t.Run(name, func(t *testing.T) {
			violations := tsLibraryFilesFindings(t, map[string]string{
				"lib.go":       "package lib\n",
				"ts/lost.ts":   libraryLostTS,
				"package.json": `{"name": "@owner/lib"}`,
			}, "frontend/lost.ts", "backend", tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// A statement that holds others updates a variable with a kind only when
// it and every statement it holds that names the variable update it with
// that kind: if c { m += 1; m *= 2 } neither adds to m nor multiplies it,
// and neither does if m > 0 { m += 1 }, whose condition reads m, nor
// if c { k += m }, which reads m to add to k.
func TestUpdateKinds(t *testing.T) {
	for name, tc := range map[string]struct {
		roles []nearRole
		held  string
	}{
		"held sums":               {[]nearRole{{Parent: -1}, {Locals: []int{0}, Writes: []int{0}, Update: "+"}, {Locals: []int{0}, Writes: []int{0}, Update: "+"}}, "+"},
		"held sum and product":    {[]nearRole{{Parent: -1}, {Locals: []int{0}, Writes: []int{0}, Update: "+"}, {Locals: []int{0}, Writes: []int{0}, Update: "*"}}, ""},
		"held product and sum":    {[]nearRole{{Parent: -1}, {Locals: []int{0}, Writes: []int{0}, Update: "*"}, {Locals: []int{0}, Writes: []int{0}, Update: "+"}}, ""},
		"held sum under a read":   {[]nearRole{{Parent: -1, Locals: []int{0}}, {Locals: []int{0}, Writes: []int{0}, Update: "+"}}, ""},
		"held sum that reads one": {[]nearRole{{Parent: -1}, {Locals: []int{0, 1}, Writes: []int{1}, Update: "+"}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			for i := 1; i < len(tc.roles); i++ {
				tc.roles[i].Parent = 0
			}
			assert.Equal(t, tc.held, updateKinds(tc.roles)[0][0])
		})
	}
}
