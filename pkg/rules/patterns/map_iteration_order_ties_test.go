package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mapOrderLines(t *testing.T, source string) []int {
	t.Helper()
	var got []int
	for _, v := range analyzeMapOrder(t, source) {
		got = append(got, v.Line)
	}
	return got
}

// Repro from a real project: the nearest worker was picked by walking a map
// with a strict comparison of distances. Two workers at the same distance won
// by turns, depending on the walk, and two runs of one seed diverged.
func TestMapIterationOrderReportsArgminWithoutTieBreak(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Point struct{ X, Y float64 }

func (p Point) Dist2(q Point) float64 { return (p.X-q.X)*(p.X-q.X) + (p.Y-q.Y)*(p.Y-q.Y) }

type Worker struct {
	Tag uint64
	Pos Point
}

func Nearest(free map[uint64]*Worker, target Point) *Worker {
	var best *Worker
	bestD := 0.0
	for _, w := range free {
		d := w.Pos.Dist2(target)
		if best == nil || d < bestD {
			best, bestD = w, d
		}
	}
	return best
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line)
	assert.Contains(t, violations[0].Message, "best")
	assert.Equal(t, "map_iteration_tie", violations[0].Context["pattern"])
}

// Repro from a real project: the cheapest unit of each producer was kept in a
// map, and two units of equal price swapped places from run to run.
func TestMapIterationOrderReportsArgminStoredInMap(t *testing.T) {
	assert.Equal(t, []int{19}, mapOrderLines(t, `package order

type Kind struct {
	ID     uint32
	Price  int
	Gas    int
}

type Catalog struct {
	producer map[uint32]uint32
	kinds    map[uint32]*Kind
	cheapest map[uint32]*Kind
}

func (c *Catalog) Build() {
	c.cheapest = map[uint32]*Kind{}
	for unit, prod := range c.producer {
		t := c.kinds[unit]
		if best := c.cheapest[prod]; best == nil || t.Price+t.Gas < best.Price+best.Gas {
			c.cheapest[prod] = t
		}
	}
}
`))
}

// A second comparison on equal keys decides every tie, so the walk no longer
// does.
func TestMapIterationOrderAcceptsArgminWithTieBreak(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

type Worker struct {
	Tag  uint64
	Dist float64
}

func Nearest(free map[uint64]*Worker) *Worker {
	var best *Worker
	for _, w := range free {
		if best == nil || w.Dist < best.Dist || (w.Dist == best.Dist && w.Tag < best.Tag) {
			best = w
		}
	}
	return best
}
`))
}

// Comparing the key itself cannot tie: a map holds each key once.
func TestMapIterationOrderAcceptsArgminOverKey(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

func First(names map[string]int) (string, int) {
	bestName, bestCount := "", 0
	for name, count := range names {
		if bestName == "" || name < bestName {
			bestName, bestCount = name, count
		}
	}
	return bestName, bestCount
}
`))
}

// Each entry of the result is written once per key of the walked map: there is
// no choice between entries.
func TestMapIterationOrderAcceptsPerKeyMinimum(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

func Lowest(prices map[string][]int) map[string]int {
	out := map[string]int{}
	for name, list := range prices {
		for _, p := range list {
			if cur, ok := out[name]; !ok || p < cur {
				out[name] = p
			}
		}
	}
	return out
}
`))
}

// Repro from a real project: a float sum over a map changes in the last digit
// with the walk, and a golden report printed it with full precision.
func TestMapIterationOrderReportsFloatSum(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

func SumOf(m map[string]float64) float64 {
	n := 0.0
	for _, v := range m {
		n += v
	}
	return n
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Equal(t, "map_iteration_float_sum", violations[0].Context["pattern"])
}

// Repro from a real project: a meter added a float damage into a field while
// walking the units of a window.
func TestMapIterationOrderReportsFloatSumIntoField(t *testing.T) {
	assert.Equal(t, []int{14}, mapOrderLines(t, `package order

type hit struct{ start, low float64 }

type Meter struct {
	hits   map[uint64]*hit
	damage float64
	byKind map[string]float64
	kinds  map[uint64]string
	total  map[uint64]float64
}

func (m *Meter) Close() {
	for tag, h := range m.hits {
		m.damage += h.start - h.low
		m.total[tag] += h.start
	}
}
`))
}

// Integer sums do not depend on the order of the terms.
func TestMapIterationOrderAcceptsIntSum(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

func Total(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
`))
}

// A float sum that stays inside the function and is only compared does not
// reach any output.
func TestMapIterationOrderAcceptsFloatSumThatStays(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

func Heavy(m map[string]float64) bool {
	n := 0.0
	for _, v := range m {
		n += v
	}
	return n > 100
}
`))
}

// Repro from a real project: rows collected from a map were sorted by seconds
// alone, so types with equal seconds came out in walk order.
func TestMapIterationOrderReportsSortWithoutTieBreak(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

import (
	"fmt"
	"sort"
	"strings"
)

func Report(m map[string]float64) string {
	type row struct {
		name string
		secs float64
	}
	var rows []row
	for n, v := range m {
		rows = append(rows, row{n, v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].secs > rows[j].secs })
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, fmt.Sprintf("%s=%.0f", r.name, r.secs))
	}
	return strings.Join(parts, " ")
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 18, violations[0].Line)
	assert.Equal(t, "map_iteration_sort_tie", violations[0].Context["pattern"])
	assert.Contains(t, violations[0].Message, "rows")
}

// Repro from a real project: values of a map sorted by a method result; a
// stable sort keeps the walk order of the equal ones just the same.
func TestMapIterationOrderReportsStableSortOfValues(t *testing.T) {
	assert.Equal(t, []int{17}, mapOrderLines(t, `package order

import "sort"

type seen struct {
	tag   uint64
	since uint32
}

func (s *seen) idle(loop uint32) uint32 { return loop - s.since }

func Worst(all map[uint64]*seen, loop uint32) []*seen {
	var out []*seen
	for _, rec := range all {
		out = append(out, rec)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].idle(loop) > out[j].idle(loop) })
	return out
}
`))
}

// The second key decides every tie, or the key of the map is the sort key.
func TestMapIterationOrderAcceptsSortWithTieBreak(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

import (
	"cmp"
	"slices"
	"sort"
)

type row struct {
	name string
	secs float64
}

func A(m map[string]float64) []row {
	var rows []row
	for n, v := range m {
		rows = append(rows, row{n, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].secs > rows[j].secs || rows[i].secs == rows[j].secs && rows[i].name < rows[j].name
	})
	return rows
}

func B(m map[string]float64) []row {
	var rows []row
	for n, v := range m {
		rows = append(rows, row{name: n, secs: v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	return rows
}

func C(m map[string]float64) []row {
	var rows []row
	for n, v := range m {
		rows = append(rows, row{n, v})
	}
	slices.SortFunc(rows, func(a, b row) int { return cmp.Or(cmp.Compare(a.secs, b.secs), cmp.Compare(a.name, b.name)) })
	return rows
}

type item struct {
	ID   int
	Size int
}

func D(m map[string]*item) []*item {
	var out []*item
	for _, it := range m {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func E(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
`))
}

// Repro from a real project: two flashes near one death; the walk decided
// which one the death consumed, deleting it and stopping.
func TestMapIterationOrderReportsDeleteAndBreak(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Point struct{ X, Y float64 }

func (p Point) Near(q Point) bool { return (p.X-q.X)*(p.X-q.X)+(p.Y-q.Y)*(p.Y-q.Y) < 4 }

type Tracker struct {
	flashes map[uint64]Point
	matched int
}

func (t *Tracker) Death(pos Point) {
	for tag, at := range t.flashes {
		if !pos.Near(at) {
			continue
		}
		t.matched++
		delete(t.flashes, tag)
		break
	}
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 13, violations[0].Line)
	assert.Equal(t, "map_iteration_first_match", violations[0].Context["pattern"])
}

// Deleting every matching entry without stopping is a cleanup, not a choice.
func TestMapIterationOrderAcceptsDeleteWithoutBreak(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

func Expire(seen map[string]int, now int) {
	for k, at := range seen {
		if now-at > 10 {
			delete(seen, k)
		}
	}
}
`))
}

// Repro from a real project: the users of each requirement were collected by
// walking the catalog map, and the first useful one named a different type on
// every run.
func TestMapIterationOrderReportsAppendIntoMapOfSlices(t *testing.T) {
	violations := analyzeMapOrder(t, `package order

type Kind struct {
	ID  uint32
	Req uint32
}

type Stats struct {
	techOf map[uint32][]uint32
}

func (s *Stats) Init(units map[uint32]*Kind) {
	s.techOf = map[uint32][]uint32{}
	for _, t := range units {
		if t.Req != 0 {
			s.techOf[t.Req] = append(s.techOf[t.Req], t.ID)
		}
	}
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 16, violations[0].Line)
	assert.Equal(t, "map_iteration_grouped", violations[0].Context["pattern"])
	assert.Contains(t, violations[0].Message, "s.techOf")
}

// The groups are sorted after the walk, or they never leave the function.
func TestMapIterationOrderAcceptsSortedGroups(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

import "slices"

type Kind struct {
	ID  uint32
	Req uint32
}

type Stats struct {
	techOf map[uint32][]uint32
}

func (s *Stats) Init(units map[uint32]*Kind) {
	s.techOf = map[uint32][]uint32{}
	for _, t := range units {
		s.techOf[t.Req] = append(s.techOf[t.Req], t.ID)
	}
	for _, ids := range s.techOf {
		slices.Sort(ids)
	}
}

func Count(units map[uint32]*Kind) int {
	by := map[uint32][]uint32{}
	for _, t := range units {
		by[t.Req] = append(by[t.Req], t.ID)
	}
	return len(by)
}
`))
}

// False positives from a real project: a filter against a constant keeps every
// entry above it, which is no choice between entries; a sort by a field of the
// map key's type sorts by the key itself, copied into the element.
func TestMapIterationOrderAcceptsFilterAndKeyTypedSort(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

import (
	"cmp"
	"slices"
	"sort"
)

const grace = 10

type seen struct{ since uint32 }

func (s *seen) idle(loop uint32) uint32 { return loop - s.since }

func Idle(all map[uint64]*seen, loop uint32) []*seen {
	var out []*seen
	for _, rec := range all {
		if rec.idle(loop) > grace {
			out = append(out, rec)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].since < out[j].since && false })
	return out
}

type building struct {
	Tag  uint64
	Seen uint32
}

func Known(buildings map[uint64]*building) []*building {
	var out []*building
	for _, b := range buildings {
		out = append(out, &building{Tag: b.Tag, Seen: b.Seen})
	}
	slices.SortFunc(out, func(a, b *building) int { return cmp.Compare(a.Tag, b.Tag) })
	return out
}
`))
}

// False positives from real projects: matching prefixes of one path of equal
// length are the same string; a comparison on an identity field cannot tie; a
// sort key filled from the map key through a conversion or read through a key
// method is unique; a sort on a name or on a rank of the element itself is a
// defined order; a float added into the row of the loop's own key gets one
// term per walk; groups returned to a caller are not stored state.
func TestMapIterationOrderAcceptsUniqueKeys(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

import (
	"slices"
	"sort"
	"strings"
)

func Page(path string, rules map[string]string) string {
	page, longest := "", 0
	for prefix, name := range rules {
		if len(prefix) > longest && strings.HasPrefix(path, prefix) {
			page, longest = name, len(prefix)
		}
	}
	return page
}

type Unit struct {
	ID   uint32
	Name string
}

func Fold(units map[uint32]*Unit, name string) *Unit {
	var best *Unit
	for _, u := range units {
		if strings.EqualFold(u.Name, name) && (best == nil || u.ID < best.ID) {
			best = u
		}
	}
	return best
}

type Kind string

type row struct {
	Kind string
	On   bool
}

func Rows(wanted map[Kind]bool) []row {
	rows := make([]row, 0, len(wanted))
	for k := range wanted {
		rows = append(rows, row{Kind: string(k), On: true})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Kind < rows[j].Kind })
	return rows
}

type holding struct{ coin, chain string }

func (h *holding) key() string { return h.coin + "/" + h.chain }

func Holdings(by map[string]*holding) []*holding {
	out := make([]*holding, 0, len(by))
	for _, h := range by {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

type cond struct{ doc struct{ at string } }

func Conds(by map[string]*cond) []*cond {
	out := make([]*cond, 0, len(by))
	for _, c := range by {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b *cond) int { return strings.Compare(a.doc.at, b.doc.at) })
	return out
}

var rank = []string{"tag", "rule", "type"}

func Signs(seen map[string][]string) []string {
	var signs []string
	for _, s := range seen {
		for _, x := range s {
			if !slices.Contains(signs, x) {
				signs = append(signs, x)
			}
		}
	}
	slices.SortFunc(signs, func(a, b string) int { return slices.Index(rank, a) - slices.Index(rank, b) })
	return signs
}

type stat struct{ lost float64 }

func rowOf(rows map[string]*stat, k string) *stat { return rows[k] }

func Lost(rows map[string]*stat, lost map[string]float64) {
	for k, v := range lost {
		rowOf(rows, k).lost += v
	}
}

type cand struct{ key string }

func Loose(existing map[string]int) map[string][]cand {
	groups := map[string][]cand{}
	for key := range existing {
		groups[strings.ToLower(key)] = append(groups[strings.ToLower(key)], cand{key: key})
	}
	return groups
}
`))
}

// False positives from glint itself: the longest suffix of one path is one
// directory; a Name() method tells entries apart; source positions of
// distinct nodes do not repeat.
func TestMapIterationOrderAcceptsSuffixNameAndPosition(t *testing.T) {
	assert.Empty(t, mapOrderLines(t, `package order

import (
	"cmp"
	"go/token"
	"slices"
	"strings"
)

func DirOf(dirs map[string]bool, importPath string) string {
	best := ""
	for dir := range dirs {
		if strings.HasSuffix("/"+importPath, "/"+dir) && len(dir) > len(best) {
			best = dir
		}
	}
	return best
}

type Var struct{ name string }

func (v *Var) Name() string { return v.name }

func First(vars map[string]*Var) *Var {
	var found *Var
	for _, v := range vars {
		if found == nil || v.Name() < found.Name() {
			found = v
		}
	}
	return found
}

type node struct{ pos token.Pos }

func (n node) Pos() token.Pos { return n.pos }

type finding struct{ node node }

func Sorted(by map[string]finding) []finding {
	var out []finding
	for _, f := range by {
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b finding) int { return cmp.Compare(a.node.Pos(), b.node.Pos()) })
	return out
}
`))
}
