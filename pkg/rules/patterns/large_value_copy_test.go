package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// largeValueCopySource is a physics step over a slice of 256-byte records:
// every by-value comparator call and every range value copies the whole
// record, and in a hot loop the copies take more time than the work itself.
const largeValueCopySource = `package physics

import (
	"cmp"
	"iter"
	"slices"
	"sort"
)

// Body is 256 bytes on a 64-bit platform.
type Body struct {
	ID    uint64
	Pos   [2]float64
	Mass  float64
	Trail [28]float64
}

// Bodies is a named slice of large records.
type Bodies []Body

// Spot is 16 bytes.
type Spot struct {
	ID   uint64
	Heat float64
}

func find(bodies []Body, id uint64) (int, bool) {
	return slices.BinarySearchFunc(bodies, id, func(b Body, id uint64) int { // want large-value-copied-per-element
		return cmp.Compare(b.ID, id)
	})
}

func prune(bodies Bodies) Bodies {
	return slices.DeleteFunc(bodies, func(b Body) bool { return b.Mass == 0 }) // want large-value-copied-per-element
}

func order(bodies []Body) {
	slices.SortFunc(bodies, func(a, b Body) int { return cmp.Compare(a.ID, b.ID) }) // want large-value-copied-per-element
}

func byID(a, b Body) int { return cmp.Compare(a.ID, b.ID) }

func orderNamed(bodies []Body) {
	slices.SortFunc(bodies, byID) // want large-value-copied-per-element
}

func keep[T any](xs []T, ok func(T) bool) []T {
	var out []T
	for i := range xs {
		if ok(xs[i]) {
			out = append(out, xs[i])
		}
	}
	return out
}

func heavy(bodies []Body) []Body {
	return keep(bodies, func(b Body) bool { return b.Mass > 1 }) // want large-value-copied-per-element
}

func (bs Bodies) Any(ok func(Body) bool) bool {
	for i := range bs {
		if ok(bs[i]) {
			return true
		}
	}
	return false
}

func anyHeavy(bodies Bodies) bool {
	return bodies.Any(func(b Body) bool { return b.Mass > 1 }) // want large-value-copied-per-element
}

// A small record by value is cheap.
func findSpot(spots []Spot, id uint64) int {
	return slices.IndexFunc(spots, func(s Spot) bool { return s.ID == id })
}

// Pointers to large records copy a word.
func hasHeavy(bodies []*Body) bool {
	return slices.ContainsFunc(bodies, func(b *Body) bool { return b.Mass > 1 })
}

// An index comparator copies nothing.
func orderByIndex(bodies []Body) {
	sort.Slice(bodies, func(i, j int) bool { return bodies[i].ID < bodies[j].ID })
}

// A callback called once with a value that is not an element of anything.
func with(b Body, f func(Body)) { f(b) }

func once(b Body) {
	with(b, func(v Body) { _ = v.Mass })
}

func total(bodies []Body, named Bodies, arr [4]Body, byKey map[uint64]Body, spots map[uint64]Spot, ptrs []*Body, seq iter.Seq[Body]) float64 {
	sum := 0.0
	for _, b := range bodies { // want large-value-copied-per-element
		sum += b.Mass
	}
	for _, b := range named { // want large-value-copied-per-element
		sum += b.Mass
	}
	for _, b := range arr { // want large-value-copied-per-element
		sum += b.Mass
	}
	for _, b := range byKey { // want large-value-copied-per-element
		sum += b.Mass
	}
	var last Body
	for _, last = range bodies { // want large-value-copied-per-element
	}
	sum += last.Mass
	for i := range bodies {
		sum += bodies[i].Mass
	}
	for id := range byKey {
		sum += float64(id)
	}
	for _, s := range spots {
		sum += s.Heat
	}
	for _, p := range ptrs {
		sum += p.Mass
	}
	for b := range seq {
		sum += b.Mass
	}
	return sum
}
`

func TestLargeValueCopiedPerElement(t *testing.T) {
	files := map[string]string{"physics/world.go": largeValueCopySource}
	violations, err := NewLargeValueCopiedPerElementRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "large-value-copied-per-element"), foundLines(violations))
}

// The threshold is an option: a project of 512-byte records sets it to what
// it counts as large.
func TestLargeValueCopiedPerElementThreshold(t *testing.T) {
	rule := NewLargeValueCopiedPerElementRule()
	require.NoError(t, rule.Configure(map[string]any{"max_bytes": 256}))
	files := map[string]string{"physics/world.go": largeValueCopySource}
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations, "a 256-byte record is not over a 256-byte limit")
}

func TestLargeValueCopiedPerElementMessage(t *testing.T) {
	files := map[string]string{"physics/world.go": largeValueCopySource}
	violations, err := NewLargeValueCopiedPerElementRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.NotEmpty(t, violations)
	assert.Contains(t, violations[0].Message, "physics.Body (256 bytes)")
}
