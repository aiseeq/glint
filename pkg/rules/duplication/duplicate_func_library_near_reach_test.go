package duplication

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The library sets a field through one pointer and then reads a field of
// the other, also of a value the other holds, or reads it first, also in a
// counted loop; reads a field in a loop that sets it
// through the other pointer; adds to a named result before a loop that
// indexes an array, a check that divides or a division, under a deferred
// recover, and before a product that cannot panic; and adds a field of a
// value to another field of it before adding to that field again.
const libraryReachSource = `package lib

type Box struct{ N, M int }

type Outer struct{ In Box }

func InnerSet(a, b *Outer, top int) int {
	if top < 0 {
		top = 0
	}
	b.In.N = top
	v := a.In.N * 2
	if v > top {
		v = top
	}
	return v + b.In.N
}

func BumpSet(a, b *Box, top int) int {
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

func BumpRead(a, b *Box, top int) int {
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

func CountEach(a, b *Box, n, top int) int {
	t := 0
	for i := 0; i < n; i++ {
		v := a.N * 2
		b.N = i
		if v > top {
			v = top
		}
		t += v
	}
	return t * 3
}

func InitLoop(a, b *Box, top int) int {
	t := 0
	for t < 100 {
		t += a.N + 1
		b.N = top
	}
	if t > top {
		t = top
	}
	return t * 2
}

func SafeArray(xs [4]int, n, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += k
	for i := 0; i < n; i++ {
		m += xs[i]
	}
	if m > 1000 {
		m = 1000
	}
	return m
}

func SafeCheck(xs []int, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	for _, x := range xs {
		m += k
		if 10/x > 0 {
			m += 1
		}
	}
	return m * 3
}

func SafeFlat(x, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += k
	m += 100 / x
	if m > 1000 {
		m = 1000
	}
	return m
}

func SafeProduct(x, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += k
	m += 100 * x
	if m > 1000 {
		m = 1000
	}
	return m
}

func Tally(xs []int, k int) int {
	var s Box
	for _, x := range xs {
		s.M = x
		s.N += s.M
		s.N += k
		if s.N > 100 {
			s.N = 100
		}
	}
	return s.N
}

func TallyTwice(xs []int, k int) int {
	var s Box
	for _, x := range xs {
		s.M = x
		s.N += s.N
		s.N += k
		if s.N > 100 {
			s.N = 100
		}
	}
	return s.N
}
`

// A name copied from the name of a field, or from a field of it, reads the
// field where the copy is read, so a write through another pointer may not
// pass the last read of any copy; a name given in the head of a loop is read
// again on every turn, after what the turn writes, while a name given in its
// body is given anew. Under a deferred recover a statement that may
// panic without a call — an index of an array, a division — keeps its
// place against an update of a named result, which the deferred function
// sees as the panic left it; one that cannot panic does not. An update of a
// field of a value that reads another field of the value commutes with
// another update of its kind, one that reads the field itself does not.
func TestDuplicateFuncOfLibraryNearCopyReach(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject string }{
		"copy of a name read after the other pointer sets the field": {`package app

type Box struct{ N, M int }

func payprovChain(p, q *Box, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.N
	again := was
	q.N = limit
	r := again * 2
	if r > limit {
		r = limit
	}
	return r + q.N
}
`, ""},
		"copy of a name read before the other pointer sets the field": {`package app

type Box struct{ N, M int }

func payprovChain(p, q *Box, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.N
	again := was
	r := again * 2
	q.N = limit
	if r > limit {
		r = limit
	}
	return r + q.N
}
`, "Function payprovChain is a near copy (100% alike) of function BumpRead"},
		"field of a copied value read after the other pointer sets it": {`package app

type Box struct{ N, M int }

type Outer struct{ In Box }

func payprovInner(p, q *Outer, limit int) int {
	if limit < 0 {
		limit = 0
	}
	was := p.In
	again := was.N
	q.In.N = limit
	r := again * 2
	if r > limit {
		r = limit
	}
	return r + q.In.N
}
`, ""},
		"field named in a counted loop before the other pointer sets it after the read": {`package app

type Box struct{ N, M int }

func payprovCount(p, q *Box, count, limit int) int {
	sum := 0
	for j := 0; j < count; j++ {
		was := p.N
		r := was * 2
		q.N = j
		if r > limit {
			r = limit
		}
		sum += r
	}
	return sum * 3
}
`, "Function payprovCount is a near copy (100% alike) of function CountEach"},
		"name given in the head of a loop that sets the field": {`package app

type Box struct{ N, M int }

func payprovLoop(p, q *Box, limit int) int {
	t := 0
	for was := p.N; t < 100; {
		t += was + 1
		q.N = limit
	}
	if t > limit {
		t = limit
	}
	return t * 2
}
`, ""},
		"addition moved past a loop that indexes an array under a recover": {`package app

func payprovSafe(vals [4]int, n, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	for i := 0; i < n; i++ {
		m += vals[i]
	}
	m += step
	if m > 1000 {
		m = 1000
	}
	return m
}
`, ""},
		"addition moved past a check that divides under a recover": {`package app

func payprovSafe(vals []int, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	for _, x := range vals {
		if 10/x > 0 {
			m += 1
		}
		m += step
	}
	return m * 3
}
`, ""},
		"addition moved past a division under a recover": {`package app

func payprovSafe(x, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += 100 / x
	m += step
	if m > 1000 {
		m = 1000
	}
	return m
}
`, ""},
		"addition moved past a product under a recover": {`package app

func payprovSafe(x, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += 100 * x
	m += step
	if m > 1000 {
		m = 1000
	}
	return m
}
`, "Function payprovSafe is a near copy (100% alike) of function SafeProduct"},
		"additions to a field of a value swapped, one reads another field": {`package app

type Box struct{ N, M int }

func payprovTally(vals []int, step int) int {
	var s Box
	for _, x := range vals {
		s.M = x
		s.N += step
		s.N += s.M
		if s.N > 100 {
			s.N = 100
		}
	}
	return s.N
}
`, "Function payprovTally is a near copy (100% alike) of function Tally"},
		"addition to a field of a value swapped with a doubling of it": {`package app

type Box struct{ N, M int }

func payprovTally(vals []int, step int) int {
	var s Box
	for _, x := range vals {
		s.M = x
		s.N += step
		s.N += s.N
		if s.N > 100 {
			s.N = 100
		}
	}
	return s.N
}
`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			violations := nearLibraryFindings(t, libraryReachSource, tc.source)
			if tc.subject == "" {
				assert.Empty(t, violations)
				return
			}
			require.Len(t, violations, 1)
			assert.Contains(t, violations[0].Message, tc.subject)
		})
	}
}

// Under a deferred function that may recover — a literal that calls
// recover, or a function the body does not show — in a function with named
// results, a statement keeps its place when it may panic without a call:
// an index of an array that is not a constant, an index of a text, a
// division or a remainder of integers by what is not a constant, a shift
// by a signed count that is not one, a type assertion. A literal that
// recovers only in a literal of its own recovers nothing, and results
// without names return their zero values after a recover.
func TestGoNearBodyFixedUnderRecover(t *testing.T) {
	const recovers = "defer func() {\n\t\tif recover() != nil {\n\t\t\tm = -m\n\t\t}\n\t}()"
	for name, tc := range map[string]struct {
		deferred, results, update string
		fixed                     bool
	}{
		"index of an array":                  {recovers, "(m int)", "m += xs[k]", true},
		"constant index of an array":         {recovers, "(m int)", "m += xs[2]", false},
		"index of a text":                    {recovers, "(m int)", "m += int(text[k])", true},
		"division":                           {recovers, "(m int)", "m += x / k", true},
		"remainder":                          {recovers, "(m int)", "m += x % k", true},
		"division by a constant":             {recovers, "(m int)", "m += x / 4", false},
		"division of floats":                 {recovers, "(m int)", "m += int(f / g)", false},
		"shift by a signed count":            {recovers, "(m int)", "m += x << k", true},
		"shift by an unsigned count":         {recovers, "(m int)", "m += x << u", false},
		"type assertion":                     {recovers, "(m int)", "m += v.(int)", true},
		"division in place":                  {recovers, "(m int)", "m /= k", true},
		"shift in place":                     {recovers, "(m int)", "m <<= k", true},
		"division in place by a constant":    {recovers, "(m int)", "m /= 4", false},
		"sum":                                {recovers, "(m int)", "m += x * k", false},
		"function deferred":                  {"defer settle()", "(m int)", "m += x / k", true},
		"literal that does not recover":      {"defer func() { m = -m }()", "(m int)", "m += x / k", false},
		"literal that calls another builtin": {"defer func() { println(m) }()", "(m int)", "m += x / k", false},
		"recover in a literal of its own":    {"defer func() {\n\t\tf := func() { recover() }\n\t\tf()\n\t}()", "(m int)", "m += x / k", false},
		"results without names":              {"defer func() { recover() }()", "int", "m += x / k", false},
	} {
		t.Run(name, func(t *testing.T) {
			source := "package app\n\nfunc settle() {}\n\nfunc subject(xs [4]int, text string, x, k int, u uint, f, g float64, v any) " + tc.results + " {\n\tm := 0\n\t" + tc.deferred + "\n\t" + tc.update + "\n\treturn m\n}\n"
			if tc.results != "int" {
				source = strings.Replace(source, "\tm := 0\n", "", 1)
			}
			roles := goNearBodiesOf(t, source)["subject"].Roles
			assert.Equal(t, tc.fixed, roles[len(roles)-2].Fixed)
		})
	}
}

// Two fields of one variable are apart when their paths part and neither
// passes a pointer after the variable or a promoted field; a field is not
// apart from the value that holds it, nor from a method value.
func TestGoFieldsApart(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b  string
		apart bool
	}{
		"two fields":                     {"s.N", "s.M", true},
		"one field":                      {"s.N", "s.N", false},
		"the value and its field":        {"s", "s.N", false},
		"two fields of a field":          {"s.In.N", "s.In.M", true},
		"a field and the field it holds": {"s.In", "s.In.N", false},
		"fields of two fields":           {"s.In.N", "s.N", true},
		"a field past a pointer":         {"s.P.N", "s.N", false},
		"two fields through a pointer":   {"p.N", "p.M", true},
		"a promoted field":               {"s.E", "s.Emb.E", false},
		"a method value":                 {"s.Len", "s.N", false},
		"a field in parentheses":         {"(s.N)", "s.M", true},
	} {
		t.Run(name, func(t *testing.T) {
			source := "package app\n\ntype In struct{ N, M int }\n\ntype Emb struct{ E int }\n\ntype Box struct {\n\tN, M int\n\tIn   In\n\tP    *Box\n\tEmb\n}\n\nfunc (Box) Len() int { return 0 }\n\nfunc f(s Box, p *Box) {\n\t_, _ = " + tc.a + ", " + tc.b + "\n}\n"
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "app.go", source, 0)
			require.NoError(t, err)
			info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
			_, err = (&types.Config{}).Check("app", fset, []*ast.File{file}, info)
			require.NoError(t, err)
			fd := file.Decls[len(file.Decls)-1].(*ast.FuncDecl)
			assign := fd.Body.List[0].(*ast.AssignStmt)
			assert.Equal(t, tc.apart, goFieldsApart(info, assign.Rhs[0], assign.Rhs[1]))
			assert.Equal(t, tc.apart, goFieldsApart(info, assign.Rhs[1], assign.Rhs[0]))
		})
	}
}
