package duplication

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func renamedBlockFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewRenamedDuplicateBlockRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var found []string
	for _, v := range violations {
		found = append(found, v.File+":"+strconv.Itoa(v.Line)+" -> "+
			v.Context["original_file"].(string)+":"+strconv.Itoa(v.Context["original_line"].(int)))
	}
	return found
}

const renamedBlockGeo = `package geo

import "math"

type Point struct{ X, Y float64 }

func (p Point) Dist(q Point) float64 { return math.Hypot(p.X-q.X, p.Y-q.Y) }

func (p Point) DistSq(q Point) float64 { return (p.X-q.X)*(p.X-q.X) + (p.Y-q.Y)*(p.Y-q.Y) }

type Unit struct {
	Tag  uint64
	Kind string
	Pos  Point
}
`

// The marking of the posts with a rival nearby, with hysteresis: a method of
// zone.Marks, and the same loop written again inside a method of another
// package — other names, a field of the receiver for the marks, constants for
// the radii and make for the map. cross-file-duplicate compares the text and
// finds no line in common; a fix of the hysteresis lands in one of them.
const renamedBlockZone = `package zone

import (
	"math"

	"example.com/rulestest/geo"
)

type Marks map[uint64]bool

func (m Marks) Next(posts, rivals []*geo.Unit, in, out float64) Marks {
	marked := Marks{}
	for _, p := range posts {
		d := math.Inf(1)
		for _, r := range rivals {
			d = min(d, r.Pos.Dist(p.Pos))
		}
		if d <= in || (m[p.Tag] && d <= out) {
			marked[p.Tag] = true
		}
	}
	return marked
}
`

const renamedBlockWatchCopy = `package watch

import (
	"math"

	"example.com/rulestest/geo"
)

const (
	enterRange = 15.0
	leaveRange = 24.0
)

type Input struct {
	Posts  []*geo.Unit
	Rivals []*geo.Unit
}

type Tracker struct {
	rivalAtPost map[uint64]bool
	ticks       int
}

func (s *Tracker) step(in Input) {
	s.ticks++
	marked := make(map[uint64]bool)
	for _, post := range in.Posts {
		best := math.Inf(1)
		for _, rival := range in.Rivals {
			best = min(best, rival.Pos.Dist(post.Pos))
		}
		if best <= enterRange || s.rivalAtPost[post.Tag] && best <= leaveRange {
			marked[post.Tag] = true
		}
	}
	s.rivalAtPost = marked
}
`

func TestRenamedDuplicateBlock(t *testing.T) {
	files := map[string]string{
		"geo/geo.go":     renamedBlockGeo,
		"zone/zone.go":   renamedBlockZone,
		"watch/watch.go": renamedBlockWatchCopy,
	}
	assert.Equal(t, []string{"watch/watch.go:27 -> zone/zone.go:13"}, renamedBlockFindings(t, files))
}

// The copy is reported against the occurrence that makes up most of its
// function — the helper to call — whichever file sorts first.
func TestRenamedDuplicateBlockOriginalIsTheHelper(t *testing.T) {
	files := map[string]string{
		"geo/geo.go":  renamedBlockGeo,
		"zz/zone.go":  `package zz` + renamedBlockZone[len("package zone"):],
		"aa/watch.go": `package aa` + renamedBlockWatchCopy[len("package watch"):],
	}
	assert.Equal(t, []string{"aa/watch.go:27 -> zz/zone.go:13"}, renamedBlockFindings(t, files))
}

// The same loop shape over another method (DistSq) or with another comparison
// (< for <=) is another computation, not a copy.
func TestRenamedDuplicateBlockOtherComputation(t *testing.T) {
	otherMethod := `package watch

import (
	"math"

	"example.com/rulestest/geo"
)

func mark(prev map[uint64]bool, posts, rivals []*geo.Unit, in, out float64) map[uint64]bool {
	marked := map[uint64]bool{}
	for _, post := range posts {
		best := math.Inf(1)
		for _, rival := range rivals {
			best = min(best, rival.Pos.DistSq(post.Pos))
		}
		if best <= in || prev[post.Tag] && best <= out {
			marked[post.Tag] = true
		}
	}
	return marked
}
`
	otherCompare := `package scout

import (
	"math"

	"example.com/rulestest/geo"
)

func mark(prev map[uint64]bool, posts, rivals []*geo.Unit, in, out float64) map[uint64]bool {
	marked := map[uint64]bool{}
	for _, post := range posts {
		best := math.Inf(1)
		for _, rival := range rivals {
			best = min(best, rival.Pos.Dist(post.Pos))
		}
		if best < in || prev[post.Tag] && best < out {
			marked[post.Tag] = true
		}
	}
	return marked
}
`
	files := map[string]string{
		"geo/geo.go":     renamedBlockGeo,
		"zone/zone.go":   renamedBlockZone,
		"watch/watch.go": otherMethod,
		"scout/scout.go": otherCompare,
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}

// Idioms every package writes its own way are not copies of one another: a
// lookup in a slice, grouping into a map, summing a field, a filter, an error
// guard that logs and returns.
func TestRenamedDuplicateBlockIdioms(t *testing.T) {
	idioms := func(pkg, item string) string {
		return `package ` + pkg + `

import "example.com/rulestest/geo"

func find(units []*geo.Unit, tag uint64) *geo.Unit {
	for _, ` + item + ` := range units {
		if ` + item + `.Tag == tag {
			return ` + item + `
		}
	}
	return nil
}

func group(units []*geo.Unit) map[string][]*geo.Unit {
	out := make(map[string][]*geo.Unit)
	for _, ` + item + ` := range units {
		if ` + item + `.Kind == "" {
			continue
		}
		out[` + item + `.Kind] = append(out[` + item + `.Kind], ` + item + `)
	}
	return out
}

func sum(units []*geo.Unit) float64 {
	total := 0.0
	for _, ` + item + ` := range units {
		if ` + item + `.Pos.X > 0 {
			total += ` + item + `.Pos.X
		}
	}
	return total
}

func near(units []*geo.Unit, at geo.Point, r float64) []*geo.Unit {
	var out []*geo.Unit
	for _, ` + item + ` := range units {
		if ` + item + `.Pos.Dist(at) <= r {
			out = append(out, ` + item + `)
		}
	}
	return out
}

func load(units []*geo.Unit, check func([]*geo.Unit) error, log func(string, ...any), fail func(error)) error {
	if err := check(units); err != nil {
		log("check failed", "units", len(units), "error", err)
		fail(err)
		return err
	}
	return nil
}
`
	}
	files := map[string]string{
		"geo/geo.go": renamedBlockGeo,
		"alpha/a.go": idioms("alpha", "u"),
		"beta/b.go":  idioms("beta", "unit"),
		"gamma/g.go": idioms("gamma", "x"),
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}

// A copy kept in a mock package stands in for the real one in tests.
func TestRenamedDuplicateBlockTestDouble(t *testing.T) {
	files := map[string]string{
		"geo/geo.go":           renamedBlockGeo,
		"zone/zone.go":         renamedBlockZone,
		"watch/mocks/watch.go": `package mocks` + renamedBlockWatchCopy[len("package watch"):],
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}

// Within one package the copy in another function is a copy too; the
// message names the function to call.
func TestRenamedDuplicateBlockSamePackage(t *testing.T) {
	files := map[string]string{
		"geo/geo.go":      renamedBlockGeo,
		"zone/zone.go":    renamedBlockZone,
		"zone/refresh.go": `package zone` + renamedBlockWatchCopy[len("package watch"):],
	}
	violations, err := NewRenamedDuplicateBlockRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "zone/refresh.go", violations[0].File)
	assert.Equal(t, 27, violations[0].Line)
	assert.Contains(t, violations[0].Message, "zone/zone.go:13 (in Marks.Next)")
}

// Two passes over two lists in one function are the textual rules' concern:
// the rule compares functions with each other.
func TestRenamedDuplicateBlockSameFunction(t *testing.T) {
	files := map[string]string{
		"geo/geo.go": renamedBlockGeo,
		"zone/zone.go": `package zone

import (
	"math"

	"example.com/rulestest/geo"
)

func both(posts, depots, rivals []*geo.Unit, prev map[uint64]bool, in, out float64) map[uint64]bool {
	marked := map[uint64]bool{}
	for _, p := range posts {
		d := math.Inf(1)
		for _, r := range rivals {
			d = min(d, r.Pos.Dist(p.Pos))
		}
		if d <= in || (prev[p.Tag] && d <= out) {
			marked[p.Tag] = true
		}
	}
	for _, depot := range depots {
		best := math.Inf(1)
		for _, rival := range rivals {
			best = min(best, rival.Pos.Dist(depot.Pos))
		}
		if best <= in || prev[depot.Tag] && best <= out {
			marked[depot.Tag] = true
		}
	}
	return marked
}
`,
	}
	assert.Empty(t, renamedBlockFindings(t, files))
}
