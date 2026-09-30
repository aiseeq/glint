package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A guard on the variable that holds the length guards the collection.
func TestUncheckedLenDivisionAcceptsGuardThroughLenVariable(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func avg(xs []int, total int) int {
	n := len(xs)
	if n == 0 {
		return 0
	}
	return total / n
}
`)
	assert.Empty(t, violations)
}

func TestUncheckedLenDivisionAcceptsConvertedGuardedLenVariable(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func avg(xs []float64, sum float64) float64 {
	n := len(xs)
	if n < 1 {
		return 0
	}
	return sum / float64(n)
}
`)
	assert.Empty(t, violations)
}

// A conversion around the variable holding the length is still that length.
func TestUncheckedLenDivisionReportsConvertedLenVariable(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func avg(xs []float64, sum float64) float64 {
	n := len(xs)
	return sum / float64(n)
}
`)
	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Equal(t, "xs", violations[0].Context["collection"])
}

// append with at least one element leaves the collection non-empty.
func TestUncheckedLenDivisionAcceptsDivisionAfterAppend(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func avg(a, b float64) float64 {
	var vals []float64
	vals = append(vals, a, b)
	return (a + b) / float64(len(vals))
}
`)
	assert.Empty(t, violations)
}

// Spreading another slice into append proves nothing: it may be empty.
func TestUncheckedLenDivisionReportsDivisionAfterSpreadAppend(t *testing.T) {
	violations := analyzeLenDivision(t, `package geometry

func avg(extra []float64, sum float64) float64 {
	var vals []float64
	vals = append(vals, extra...)
	return sum / float64(len(vals))
}
`)
	require.Len(t, violations, 1)
}

// The length of an array is a constant: it cannot be zero by surprise.
func TestUncheckedLenDivisionAcceptsArrayLength(t *testing.T) {
	violations := runRuleOnFiles(t, NewUncheckedLenDivisionRule(), map[string]string{
		"weights.go": `package geometry

var weights = [3]float64{0.2, 0.3, 0.5}

func wavg(total float64) float64 {
	return total / float64(len(weights))
}
`,
	})
	assert.Empty(t, violations)
}

// The typed path still reports a slice.
func TestUncheckedLenDivisionTypedReportsSlice(t *testing.T) {
	violations := runRuleOnFiles(t, NewUncheckedLenDivisionRule(), map[string]string{
		"weights.go": `package geometry

var weights = []float64{0.2, 0.3, 0.5}

func wavg(total float64) float64 {
	return total / float64(len(weights))
}
`,
	})
	require.Len(t, violations, 1)
	assert.Equal(t, "weights.go", violations[0].File)
}

// A guard that stops the process — log.Fatal, os.Exit — ends the empty path
// just as a return does.
func TestUncheckedLenDivisionTypedAcceptsNoReturnGuard(t *testing.T) {
	violations := runRuleOnFiles(t, NewUncheckedLenDivisionRule(), map[string]string{
		"avg.go": `package geometry

import (
	"log"
	"os"
)

func avg(xs []int, total int) int {
	if len(xs) == 0 {
		log.Fatal("no samples")
	}
	return total / len(xs)
}

func mean(xs []float64, sum float64) float64 {
	if len(xs) == 0 {
		os.Exit(2)
	}
	return sum / float64(len(xs))
}
`,
	})
	assert.Empty(t, violations)
}
