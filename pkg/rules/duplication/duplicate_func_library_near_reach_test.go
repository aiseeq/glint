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
// recover, before a product, a loop that converts a slice to a slice or
// one that compares interfaces, sets locals with a division and then the
// result, and adds a field of a value, also to an element of an array
// field, to another field of it before adding to that field again.
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

type Holder struct {
	In Box
	K  int
}

func NestedTally(xs []int, k int) int {
	t := 0
	for _, x := range xs {
		var s Holder
		s.In.M = x
		s.In.N += k
		s.In.M += s.In.N
		if s.In.M > 100 {
			s.In.M = 100
		}
		t += s.In.M
	}
	return t
}

func NestedOther(xs []int, k int) int {
	t := 0
	for _, x := range xs {
		var s Holder
		s.K = x
		s.In.N += k
		s.In.N += s.K
		if s.In.N > 100 {
			s.In.N = 100
		}
		t += s.In.N
	}
	return t
}

func SafeConvert(xs []int, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += k
	if len(xs) > 0 {
		a := [4]int(xs)
		m += a[0] + a[3]
	}
	if m > 1000 {
		m = 1000
	}
	return m
}

func SafeLength(xs []int, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += k
	for i := 0; i < 2; i++ {
		ys := []int(xs)
		m += len(ys)
	}
	if m > 1000 {
		m = 1000
	}
	return m
}

func SafeShare(x, y, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += k
	d := x / y
	m += d
	if m > 1000 {
		m = 1000
	}
	return m
}

func SafeEqual(a, b any, n, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	m += k
	for i := 0; i < n; i++ {
		if a == b {
			m += 1
		}
	}
	if m > 1000 {
		m = 1000
	}
	return m
}

func SafeLocal(x, k int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	a := x * 2
	b := 100 / k
	if a > b {
		a = b
	}
	m = a + b
	return m * 2
}

type Slots struct {
	Arr [2]int
	K   int
}

func SlotTally(xs []int, k int) int {
	t := 0
	for _, x := range xs {
		var s Slots
		s.K = x
		s.Arr[0] += s.K
		s.Arr[0] += k
		if s.Arr[0] < 0 {
			s.Arr[0] = -s.Arr[0]
		}
		t -= s.Arr[0] * 5
	}
	return t
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
// panic without a call — an index of an array, a division, a comparison of
// interfaces — keeps its order against a statement that sets a named
// result, which the deferred function sees as the panic left it, but not
// against one that sets no result; one that cannot panic keeps no order.
// An update of a field of a value, or of an element of an array field,
// that reads another field of the value commutes with another update of
// its kind, one that reads the field itself does not, nor one of a field
// of a field that reads another field of that field, which the comparison
// sees as one value.
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
		"addition moved past a comparison of interfaces under a recover": {`package app

func payprovSafe(p, q any, n, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	for i := 0; i < n; i++ {
		if p == q {
			m += 1
		}
	}
	m += step
	if m > 1000 {
		m = 1000
	}
	return m
}
`, ""},
		"addition moved past a division that sets no result under a recover": {`package app

func payprovSafe(p, q, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	d := p / q
	m += step
	m += d
	if m > 1000 {
		m = 1000
	}
	return m
}
`, ""},
		"addition moved past a loop that cannot panic under a recover": {`package app

func payprovSafe(vals []int, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	for i := 0; i < 2; i++ {
		ys := []int(vals)
		m += len(ys)
	}
	m += step
	if m > 1000 {
		m = 1000
	}
	return m
}
`, "Function payprovSafe is a near copy (100% alike) of function SafeLength"},
		"statements that set no result swapped under a recover": {`package app

func payprovSafe(x, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	b := 100 / step
	a := x * 2
	if a > b {
		a = b
	}
	m = a + b
	return m * 2
}
`, "Function payprovSafe is a near copy (100% alike) of function SafeLocal"},
		"additions to an element of an array field swapped, one reads another field": {`package app

type Slots struct {
	Arr [2]int
	K   int
}

func payprovSlots(vals []int, step int) int {
	t := 0
	for _, x := range vals {
		var s Slots
		s.K = x
		s.Arr[0] += step
		s.Arr[0] += s.K
		if s.Arr[0] < 0 {
			s.Arr[0] = -s.Arr[0]
		}
		t -= s.Arr[0] * 5
	}
	return t
}
`, "Function payprovSlots is a near copy (100% alike) of function SlotTally"},
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
		"additions to two fields of a field swapped, one reads the other": {`package app

type Box struct{ N, M int }

type Holder struct {
	In Box
	K  int
}

func payprovNested(vals []int, step int) int {
	t := 0
	for _, x := range vals {
		var s Holder
		s.In.M = x
		s.In.M += s.In.N
		s.In.N += step
		if s.In.M > 100 {
			s.In.M = 100
		}
		t += s.In.M
	}
	return t
}
`, ""},
		"additions to a field of a field swapped, one reads a field of the value": {`package app

type Box struct{ N, M int }

type Holder struct {
	In Box
	K  int
}

func payprovNested(vals []int, step int) int {
	t := 0
	for _, x := range vals {
		var s Holder
		s.K = x
		s.In.N += s.K
		s.In.N += step
		if s.In.N > 100 {
			s.In.N = 100
		}
		t += s.In.N
	}
	return t
}
`, "Function payprovNested is a near copy (100% alike) of function NestedOther"},
		"addition moved past a conversion to an array under a recover": {`package app

func payprovSafe(vals []int, step int) (m int) {
	defer func() {
		if recover() != nil {
			m = -m
		}
	}()
	if len(vals) > 0 {
		a := [4]int(vals)
		m += a[0] + a[3]
	}
	m += step
	if m > 1000 {
		m = 1000
	}
	return m
}
`, ""},
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
// results, a statement shows the results unless nothing in it can panic,
// since the deferred function sees them as the panic left them: a
// division or a remainder of integers by what is not a constant, a shift
// by a signed count, an index of a text or of an array at an index that is
// not a constant, a comparison of two interfaces or of values that hold
// one, a switch on one with a case of one, a type assertion, a call, a conversion of a slice to a longer array, a
// method of an interface may; arithmetic, a comparison of numbers or of an
// interface with a number or nil, len and cap and another conversion may
// not. A
// literal that recovers only in a literal of its own recovers nothing, and
// results without names return their zero values after a recover.
func TestGoNearBodyShowsUnderRecover(t *testing.T) {
	const recovers = "defer func() {\n\t\tif recover() != nil {\n\t\t\tm = -m\n\t\t}\n\t}()"
	for name, tc := range map[string]struct {
		deferred, results, update string
		shows                     bool
	}{
		"sum":                                          {recovers, "(m int)", "m += x * k", false},
		"negation":                                     {recovers, "(m int)", "m += -x", false},
		"receive":                                      {recovers, "(m int)", "_ = <-ch", true},
		"field of a value":                             {recovers, "(m int)", "_ = st.A", false},
		"constant call":                                {recovers, "(m int)", "m += min(3, 4)", false},
		"shift by a constant":                          {recovers, "(m int)", "m += x << 2", false},
		"comparison of channels":                       {recovers, "(m int)", "_ = ch == ch", false},
		"comparison of structs of numbers":             {recovers, "(m int)", "_ = pt == pt", false},
		"remainder in place":                           {recovers, "(m int)", "m %= k", true},
		"shift to the right in place":                  {recovers, "(m int)", "m >>= k", true},
		"division":                                     {recovers, "(m int)", "m += x / k", true},
		"remainder":                                    {recovers, "(m int)", "m += x % k", true},
		"division by a constant":                       {recovers, "(m int)", "m += x / 4", false},
		"division of floats":                           {recovers, "(m int)", "m += int(f / g)", false},
		"shift by a signed count":                      {recovers, "(m int)", "m += x << k", true},
		"shift by an unsigned count":                   {recovers, "(m int)", "m += x << u", false},
		"division in place":                            {recovers, "(m int)", "m /= k", true},
		"shift in place":                               {recovers, "(m int)", "m <<= k", true},
		"division in place by a constant":              {recovers, "(m int)", "m /= 4", false},
		"index of an array":                            {recovers, "(m int)", "m += xs[k]", true},
		"constant index of an array":                   {recovers, "(m int)", "m += xs[2]", false},
		"index of a text":                              {recovers, "(m int)", "m += int(text[k])", true},
		"constant index of a text":                     {recovers, "(m int)", "m += int(text[2])", true},
		"comparison of interfaces":                     {recovers, "(m int)", "_ = v == v", true},
		"comparison of values that hold an interface":  {recovers, "(m int)", "_ = st == st", true},
		"comparison of numbers":                        {recovers, "(m int)", "_ = x != k", false},
		"switch on an interface with a case of one":    {recovers, "(m int)", "switch v {\n\tcase 1, e:\n\t\tm++\n\t}", true},
		"switch on an interface with cases of numbers": {recovers, "(m int)", "switch v {\n\tcase 1, 2:\n\t\tm++\n\t}", false},
		"switch without a value":                       {recovers, "(m int)", "switch {\n\tcase x > k:\n\t\tm++\n\t}", false},
		"comparison of an interface with a number":     {recovers, "(m int)", "_ = v == 1", false},
		"comparison of a number with an interface":     {recovers, "(m int)", "_ = 1 != v", false},
		"comparison of an interface with nil":          {recovers, "(m int)", "_ = e == nil", false},
		"comparison of values that hold an array of interfaces": {recovers, "(m int)", "_ = arr == arr", true},
		"comparison of arrays of numbers":                       {recovers, "(m int)", "_ = xs == xs", false},
		"comparison of pointers":                                {recovers, "(m int)", "_ = bp == bp", false},
		"call of a function":                                    {recovers, "(m int)", "settle()", true},
		"capacity":                                              {recovers, "(m int)", "m += cap(sl)", false},
		"append":                                                {recovers, "(m int)", "sl = append(sl, x)", true},
		"switch on a number":                                    {recovers, "(m int)", "switch x {\n\tcase 1:\n\t\tm++\n\t}", false},
		"type assertion":                                        {recovers, "(m int)", "m += v.(int)", true},
		"method of an interface":                                {recovers, "(m int)", "_ = e.Error", true},
		"conversion of a slice to an array":                     {recovers, "(m int)", "_ = [4]int(sl)", true},
		"conversion of a slice to a pointer to an array":        {recovers, "(m int)", "_ = (*[4]int)(sl)", true},
		"conversion of a slice to an empty array":               {recovers, "(m int)", "_ = [0]int(sl)", false},
		"conversion of a slice to a pointer to an empty array":  {recovers, "(m int)", "_ = (*[0]int)(sl)", false},
		"conversion of a pointer":                               {recovers, "(m int)", "_ = (*int)(bp)", false},
		"conversion of a slice to a slice":                      {recovers, "(m int)", "_ = ints(sl)", false},
		"conversion of an array":                                {recovers, "(m int)", "_ = [4]int(xs)", false},
		"conversion of a text to a slice":                       {recovers, "(m int)", "_ = []byte(text)", false},
		"conversion of an integer":                              {recovers, "(m int)", "_ = int64(x)", false},
		"length":                                                {recovers, "(m int)", "m += len(sl)", false},
		"function deferred":                                     {"defer settle()", "(m int)", "m += x / k", true},
		"literal that does not recover":                         {"defer func() { m = -m }()", "(m int)", "m += x / k", false},
		"literal that calls another builtin":                    {"defer func() { println(m) }()", "(m int)", "m += x / k", false},
		"recover in a literal of its own":                       {"defer func() {\n\t\tf := func() { recover() }\n\t\tf()\n\t}()", "(m int)", "m += x / k", false},
		"results without names":                                 {"defer func() { recover() }()", "int", "m += x / k", false},
	} {
		t.Run(name, func(t *testing.T) {
			source := func(update string) string {
				out := "package app\n\ntype ints []int\n\nfunc settle() {}\n\nfunc subject(xs [4]int, text string, x, k int, u uint, f, g float64, v any, st struct{ A any }, e error, sl []int, bp *int, arr [2]any, ch chan int, pt struct{ N, M int }) " + tc.results + " {\n\tm := 0\n\t" + tc.deferred + "\n\t" + update + "\n\treturn m\n}\n"
				if tc.results != "int" {
					out = strings.Replace(out, "\tm := 0\n", "", 1)
				}
				return out
			}
			before := len(goNearBodiesOf(t, source("k = x"))["subject"].Roles) - 2
			roles := goNearBodiesOf(t, source(tc.update))["subject"].Roles
			shows := false
			for _, role := range roles[before : len(roles)-1] {
				shows = shows || len(role.Shows) > 0
			}
			assert.Equal(t, tc.shows, shows)
		})
	}
}

// A statement that may panic shows the named results the body names, not
// one it never names, which it does not number.
func TestGoNearBodyShowsNamedResults(t *testing.T) {
	roles := goNearBodiesOf(t, "package app\n\nfunc settle() {}\n\nfunc subject(x, y int) (m, n int) {\n\tdefer settle()\n\tk := x / y\n\tm = k\n\treturn\n}\n")["subject"].Roles
	require.Len(t, roles, 4)
	assert.Equal(t, []int{roles[2].Writes[0]}, roles[1].Shows)
}

// Two fields of one variable are apart when they are two fields of the
// variable itself, or lie in two, and neither passes a pointer after the
// variable or a promoted field, an index of an array field stands for the
// field, of a slice, a map or a pointer for none: the near comparison numbers a field of a
// variable, not a field of a field, so s.In.N and s.In.M are one value for
// it. A field is not apart from the value that holds it, nor from a method
// value of the variable; a method value of a field stands for the field.
func TestGoFieldsApart(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b  string
		apart bool
	}{
		"two fields":                     {"s.N", "s.M", true},
		"one field":                      {"s.N", "s.N", false},
		"the value and its field":        {"s", "s.N", false},
		"two fields of a field":          {"s.In.N", "s.In.M", false},
		"a field and the field it holds": {"s.In", "s.In.N", false},
		"fields of two fields":           {"s.In.N", "s.N", true},
		"a field past a pointer":         {"s.P.N", "s.N", false},
		"two fields through a pointer":   {"p.N", "p.M", true},
		"a promoted field":               {"s.E", "s.Emb.E", false},
		"a method value":                 {"s.Len", "s.N", false},
		"a method value of a field":      {"s.In.Sum", "s.N", true},
		"a method value of the field":    {"s.In.Sum", "s.In.N", false},
		"an element of an array field":   {"s.Arr[0]", "s.N", true},
		"two elements of an array field": {"s.Arr[0]", "s.Arr[1]", false},
		"an element of a slice field":    {"s.Sl[0]", "s.N", false},
		"an element through a pointer":   {"s.PA[0]", "s.N", false},
		"an element of a map field":      {"s.Ms[0]", "s.N", false},
		"a field in parentheses":         {"(s.N)", "s.M", true},
	} {
		t.Run(name, func(t *testing.T) {
			source := "package app\n\ntype In struct{ N, M int }\n\nfunc (In) Sum() int { return 0 }\n\ntype Emb struct{ E int }\n\ntype Box struct {\n\tN, M int\n\tIn   In\n\tP    *Box\n\tArr  [2]int\n\tSl   []int\n\tPA   *[2]int\n\tMs   map[int]int\n\tEmb\n}\n\nfunc (Box) Len() int { return 0 }\n\nfunc f(s Box, p *Box) {\n\t_, _ = " + tc.a + ", " + tc.b + "\n}\n"
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
