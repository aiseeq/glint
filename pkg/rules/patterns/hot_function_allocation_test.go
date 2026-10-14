package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
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

func TestAllocationInHotFunction(t *testing.T) {
	files := map[string]string{"physics/world.go": hotAllocationSource}
	violations, err := NewAllocationInHotFunctionRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "allocation-in-hot-function"), foundLines(violations))
}
