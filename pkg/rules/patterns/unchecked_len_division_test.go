package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeLenDivision(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return NewUncheckedLenDivisionRule().AnalyzeFile(rulestest.GoFile(t, "geometry.go", source))
}

// Repro from a real project: the centre of a group of units was averaged over
// len(us) with no emptiness check. An empty group produced NaN coordinates, the
// move order went to a point that does not exist, and every comparison with NaN
// is false — so nothing ever reported the failure.
func TestUncheckedLenDivisionReportsAverageThroughLenVariable(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

type Point struct{ X, Y float64 }

func centerOf(us []Point) Point {
	var x, y float64
	for i := range us {
		x += us[i].X
		y += us[i].Y
	}
	n := float64(len(us))
	return Point{X: x / n, Y: y / n}
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 12, violations[0].Line)
	assert.Contains(t, violations[0].Message, "us")
}

func TestUncheckedLenDivisionReportsDirectDivision(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func mean(values []float64) float64 {
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 8, violations[0].Line)
}

func TestUncheckedLenDivisionReportsIntegerDivision(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func share(total int, parts []int) int {
	return total / len(parts)
}
`)

	require.Len(t, violations, 1)
}

// An early return on the empty case is the fix, and the rule must see it.
func TestUncheckedLenDivisionAcceptsEarlyReturn(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

type Point struct{ X, Y float64 }

func centerOf(us []Point) (Point, bool) {
	if len(us) == 0 {
		return Point{}, false
	}
	var x float64
	for i := range us {
		x += us[i].X
	}
	return Point{X: x / float64(len(us))}, true
}
`)

	assert.Empty(t, violations)
}

func TestUncheckedLenDivisionAcceptsPositiveGuard(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func mean(values []float64) float64 {
	var sum float64
	for _, v := range values {
		sum += v
	}
	if len(values) > 0 {
		return sum / float64(len(values))
	}
	return 0
}
`)

	assert.Empty(t, violations)
}

// A minimum-size guard covers the emptiness too.
func TestUncheckedLenDivisionAcceptsMinimumSizeGuard(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func spread(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	return values[len(values)-1] / float64(len(values))
}
`)

	assert.Empty(t, violations)
}

// Inside the loop body the collection cannot be empty: the body would not run.
func TestUncheckedLenDivisionAcceptsDivisionInsideRangeBody(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func weights(values []float64) []float64 {
	out := make([]float64, 0, len(values))
	for _, v := range values {
		out = append(out, v/float64(len(values)))
	}
	return out
}
`)

	assert.Empty(t, violations)
}

func TestUncheckedLenDivisionAcceptsDivisionInsideCountedLoop(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func weights(values []float64) []float64 {
	var out []float64
	for i := 0; i < len(values); i++ {
		out = append(out, values[i]/float64(len(values)))
	}
	return out
}
`)

	assert.Empty(t, violations)
}

// False positive from a real project: picking an element out of a static table
// by a hash remainder. The remainder is not an average, and its empty case
// panics where it happens instead of spreading a NaN.
func TestUncheckedLenDivisionAcceptsRemainderPick(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

var cities = []string{"a", "b"}

func pick(hash uint64) string {
	return cities[hash%uint64(len(cities))]
}
`)

	assert.Empty(t, violations)
}

// A divisor that is not a length is another rule's business.
func TestUncheckedLenDivisionAcceptsOtherDivisors(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func rate(total float64, seconds float64) float64 {
	return total / seconds
}
`)

	assert.Empty(t, violations)
}

// The guard belongs to the collection that is divided by, not to any other.
func TestUncheckedLenDivisionReportsGuardOfAnotherCollection(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func mean(values []float64, weights []float64) float64 {
	if len(weights) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "values")
}
