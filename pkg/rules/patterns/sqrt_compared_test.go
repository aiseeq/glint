package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// sqrtComparedSource takes a root only to compare it, in a loop or a hot
// function: comparing squares gives the same answer without the root. The
// minimum of roots is the root of the minimum of squares. A root kept in a
// variable is used beyond the comparison (a normalization, an output), and a
// comparison outside a loop runs once.
const sqrtComparedSource = `package geom

import "math"

type P struct{ X, Y float64 }

func Near(ps []P, a P, r float64) int {
	n := 0
	for _, p := range ps {
		if math.Hypot(p.X-a.X, p.Y-a.Y) <= r { // want sqrt-compared-to-threshold
			n++
		}
		if math.Sqrt(p.X*p.X+p.Y*p.Y) > math.Hypot(a.X, a.Y) { // want sqrt-compared-to-threshold
			n++
		}
		if d := math.Hypot(p.X, p.Y); d > 0 {
			p.X /= d
		}
		if math.Hypot(p.X, p.Y)/2-r <= 1 {
			n++
		}
	}
	return n
}

func Closest(ps []P, a P) float64 {
	best := math.Inf(1)
	for _, p := range ps {
		best = math.Min(best, math.Hypot(p.X-a.X, p.Y-a.Y)) // want sqrt-compared-to-threshold
		best = min(best, math.Sqrt(p.X)) // want sqrt-compared-to-threshold
	}
	return best
}

//glint:hot
func Inside(p, a P, r float64) bool {
	return math.Hypot(p.X-a.X, p.Y-a.Y) < r // want sqrt-compared-to-threshold
}

func Once(p, a P, r float64) bool {
	return math.Hypot(p.X-a.X, p.Y-a.Y) < r
}
`

func TestSqrtComparedToThreshold(t *testing.T) {
	files := map[string]string{"geom/geom.go": sqrtComparedSource}
	violations, err := NewSqrtComparedToThresholdRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "sqrt-compared-to-threshold"), foundLines(violations))
}
