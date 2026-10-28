package concurrencyrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hotAllocationSource is a step function its author marked hot: it runs every
// tick, and every allocation in it is garbage the collector sweeps every tick.
// The same code in an unmarked function is ordinary code.
const hotAllocationSource = `package physics

import "slices"

type Pair struct{ A, B int }

type Ints []int

type State struct {
	buf   []int
	pairs []Pair
}

var shared []int

//glint:hot
func (s *State) Step(in []int, out []int) []int {
	cp := slices.Clone(in) // want allocation-in-hot-function
	tmp := make([]int, len(in)) // want allocation-in-hot-function
	seen := map[int]bool{} // want allocation-in-hot-function
	lit := []int{1, 2} // want allocation-in-hot-function
	named := Ints{3} // want allocation-in-hot-function
	var acc []int
	for _, v := range in {
		acc = append(acc, v) // want allocation-in-hot-function
	}
	fresh := []int(nil)
	fresh = append(fresh, 1) // want allocation-in-hot-function
	grown := append([]int(nil), in...) // want allocation-in-hot-function
	p := new(Pair) // want allocation-in-hot-function
	q := &Pair{A: 1} // want allocation-in-hot-function
	f := func() []int { return make([]int, 1) } // want allocation-in-hot-function

	s.buf = append(s.buf[:0], in...)
	s.pairs = append(s.pairs, Pair{A: 1})
	out = append(out[:0], in...)
	shared = append(shared[:0], 1)
	local := s.buf[:0]
	local = append(local, 1)
	reused := make([]int, 0, 8) // allocation-in-hot-function: safe — sized once per step for the batch below
	reused = append(reused, 1)
	arr := [4]int{1, 2, 3, 4}
	pair := Pair{A: 1, B: 2}
	_, _, _, _, _, _, _, _, _, _, _, _, _ = cp, tmp, seen, lit, named, grown, p, q, f, local, reused, arr, pair
	return out
}

// Collect gathers values; the doc text comes before the directive.
//
//glint:hot
func collect(in []int) (res []int) {
	for _, v := range in {
		res = append(res, v) // want allocation-in-hot-function
	}
	return res
}

// Cold is the same work without the directive.
func (s *State) Cold(in []int) []int {
	cp := slices.Clone(in)
	var acc []int
	acc = append(acc, cp...)
	return append(acc, make([]int, 1)...)
}
`

// hotGuardedSource allocates only when a check of the same target says the
// old value is missing or too small: a get-or-create keeps the new value for
// the next tick, a buffer grows once and is refilled in place after that.
// Neither leaves garbage every tick. An allocation under a check of something
// else, or into a local the function starts empty, still does.
const hotGuardedSource = `package physics

type Walker struct{ path []int }

type World struct {
	walkers map[uint64]*Walker
	verts   []int
	orders  []int
	cur     *Walker
}

//glint:hot
func (w *World) Tick(tag uint64, n int, buf *[]int) {
	wk := w.walkers[tag]
	if wk == nil {
		wk = &Walker{}
		w.walkers[tag] = wk
	}
	if cap(w.verts) < n {
		w.verts = make([]int, 0, n)
	}
	if len(w.orders) == cap(w.orders) {
		w.orders = make([]int, 0, 256)
	}
	if cap(*buf)-len(*buf) < n {
		*buf = make([]int, 0, n)
	}
	if w.cur == nil || len(w.cur.path) != n {
		w.cur = &Walker{path: make([]int, n)}
	}
	if n > 4 {
		w.verts = make([]int, n) // want allocation-in-hot-function
	}
	var local []int
	if local == nil {
		local = make([]int, n) // want allocation-in-hot-function
	}
	fresh := &Walker{} // want allocation-in-hot-function
	if fresh == nil {
		fresh = &Walker{} // want allocation-in-hot-function
	}
	_, _ = local, fresh
}
`

func TestAllocationInHotFunction(t *testing.T) {
	files := map[string]string{"physics/world.go": hotAllocationSource, "physics/guarded.go": hotGuardedSource}
	violations, err := NewAllocationInHotFunctionRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "allocation-in-hot-function"), patterntest.FoundLines(violations))
}

// hotTransitiveSource marks only the root of the tick; the garbage is made by
// what it calls. A call through an interface or a func value is not
// followed, nor a call on a cold branch that carries the rule's suppression.
const hotTransitiveSource = `package solver

import "fmt"

type Unit struct{ X, Y int }

type Frame struct{ Units []Unit }

type Sink interface{ Put(u Unit) }

type Solver struct {
	scratch []Unit
	sink    Sink
	hook    func(Unit)
}

//glint:hot
func (s *Solver) Tick(f *Frame) {
	for i := range f.Units {
		_ = s.neighbors(f, i)
		_ = s.neighborsInPlace(f, i)
		s.sink.Put(f.Units[i])
		s.hook(f.Units[i])
	}
	if len(f.Units) == 0 {
		s.reset() // allocation-in-hot-function: safe — the first frame only
	}
}

func (s *Solver) neighbors(f *Frame, i int) []Unit {
	var out []Unit
	for _, u := range f.Units {
		if u.X == f.Units[i].X {
			out = append(out, u) // want allocation-in-hot-function
		}
	}
	return outline(out)
}

func outline(us []Unit) []Unit {
	return append([]Unit(nil), us...) // want allocation-in-hot-function
}

func (s *Solver) neighborsInPlace(f *Frame, i int) []Unit {
	s.scratch = append(s.scratch[:0], f.Units[i])
	return s.scratch
}

func (s *Solver) reset() { s.scratch = make([]Unit, 0, 64) }

type logSink struct{}

func (logSink) Put(u Unit) { _ = []Unit{u} }

func cold() []Unit { return make([]Unit, 8) }

// Check fails once per bad frame: the branch that returns the error or
// panics is not run every tick, nor is what it calls.
//
//glint:hot
func (s *Solver) Check(f *Frame) error {
	if len(f.Units) > 1000 {
		return tooMany(len(f.Units))
	}
	if f.Units == nil {
		panic(fmt.Sprint("no units", []int{len(f.Units)}))
	}
	if len(f.Units) == 1 {
		_ = []int{1} // want allocation-in-hot-function
	}
	return nil
}

func tooMany(n int) error { return fmt.Errorf("%d units: %v", n, []int{n}) }
`

func TestAllocationInHotFunctionTransitive(t *testing.T) {
	files := map[string]string{"solver/solver.go": hotTransitiveSource}
	project := rulestest.Project(t, files)

	direct, err := NewAllocationInHotFunctionRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []string{"solver/solver.go:69"}, patterntest.FoundLines(direct), "without transitive only the marked bodies are checked")

	rule := NewAllocationInHotFunctionRule()
	require.NoError(t, rule.Configure(map[string]any{"transitive": true}))
	violations, err := rule.AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "allocation-in-hot-function"), patterntest.FoundLines(violations))
	require.NotEmpty(t, violations)
	assert.Contains(t, violations[0].Message, "Solver.Tick → Solver.neighbors")

	require.Error(t, NewAllocationInHotFunctionRule().Configure(map[string]any{"transitive": "yes"}))
}

// hotEscapeSource allocates where the syntax does not show it: a variable
// whose address is kept moves to the heap, a value boxed into an interface
// for a log call is allocated on every call, a closure kept on the receiver
// escapes. A small make that never leaves the function stays on the stack;
// a constant or a zero-size value in an interface costs nothing; what the
// inlined slog.Debug does inside is not a line of this function.
const hotEscapeSource = `package engine

import (
	"fmt"
	"log/slog"
)

type Shot struct{ A [64]int }

type Empty struct{}

type Engine struct {
	keep *Shot
	hook func() int
	sink any
}

func (e *Engine) retain(s *Shot) { e.keep = s }

func (e *Engine) capture() Shot { return Shot{} }

//glint:hot
func (e *Engine) Apply(loop int) int {
	before := e.capture() // want allocation-in-hot-function
	e.retain(&before)
	slog.Debug("apply", "loop", loop) // want allocation-in-hot-function
	tmp := make([]int, 8)
	tmp[0] = loop
	if loop < 0 {
		panic(fmt.Sprintf("loop %d", loop))
	}
	e.hook = func() int { return loop } // want allocation-in-hot-function
	e.sink = Empty{}
	e.sink = "const"
	grown := make([]int, loop) // want allocation-in-hot-function
	return tmp[0] + len(grown)
}
`

func TestAllocationInHotFunctionEscape(t *testing.T) {
	files := map[string]string{"engine/engine.go": hotEscapeSource}
	project := rulestest.Project(t, files)

	syntax, err := NewAllocationInHotFunctionRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []string{"engine/engine.go:27", "engine/engine.go:35"}, patterntest.FoundLines(syntax), "the syntax sees both makes and nothing else")

	rule := NewAllocationInHotFunctionRule()
	require.NoError(t, rule.Configure(map[string]any{"escape": true}))
	violations, err := rule.AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "allocation-in-hot-function"), patterntest.FoundLines(violations))

	require.Error(t, NewReflectInHotFunctionRule().Configure(map[string]any{"escape": true}))
}

func TestParseEscapeLine(t *testing.T) {
	file, note, ok, err := parseEscapeLine("p/p.go:20:2: moved to heap: before")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "p/p.go", file)
	assert.Equal(t, escapeNote{line: 20, col: 2, expr: "before", heap: true, moved: true}, note)

	file, _, ok, err = parseEscapeLine(`C:\src\p\p.go:20:2: moved to heap: before`)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, `C:\src\p\p.go`, file)

	_, note, ok, _ = parseEscapeLine("p/p.go:23:13: make([]int, 8) does not escape")
	require.True(t, ok)
	assert.Equal(t, escapeNote{line: 23, col: 13, expr: "make([]int, 8)"}, note)

	_, note, ok, _ = parseEscapeLine(`p/q.go:10:42: []int{...} escapes to heap`)
	require.True(t, ok)
	assert.Equal(t, escapeNote{line: 10, col: 42, expr: "[]int{...}", heap: true}, note)

	_, _, _, err = parseEscapeLine("p/p.go:99999999999999999999:1: moved to heap: x")
	require.Error(t, err)

	for _, skipped := range []string{"# example.com/esc/p", "p/p.go:16:6: can inline (*E).retain", "p/p.go:16:26: leaking param: s", "p/p.go:21:16: inlining call to (*E).retain"} {
		_, _, ok, err = parseEscapeLine(skipped)
		require.NoError(t, err)
		assert.False(t, ok, skipped)
	}
}
