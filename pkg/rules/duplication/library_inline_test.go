package duplication

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDuplicateFuncOfLibraryInlineFieldFlow(t *testing.T) {
	ctx := duplicateLibraryTestProject(t, "github.com/projecta/libkit", "github.com/projecta/app", inlineFieldApp, map[string]string{"pressure/limits.go": inlineFieldLibrary}, true, "")
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	found := map[string]int{}
	for _, v := range violations {
		switch {
		case v.Line >= 18 && v.Line <= 24:
			require.Contains(t, v.Message, "RunnableLimit")
			found["P1"]++
		case v.Line >= 27 && v.Line <= 33:
			require.Contains(t, v.Message, "RunnableLimit")
			found["P2"]++
		case v.Line >= 77 && v.Line <= 88:
			require.Contains(t, v.Message, "Share")
			found["C1"]++
		default:
			t.Errorf("unexpected violation at %d: %s", v.Line, v.Message)
		}
	}
	require.Equal(t, map[string]int{"P1": 1, "P2": 1, "C1": 1}, found)
}

func TestDuplicateFuncOfLibraryInlineAndCallInSameBlock(t *testing.T) {
	const source = `package app
import "github.com/projecta/libkit/pressure"
func compare(l pressure.Limits, m pressure.Load) bool {
	limit := l.Runnable
	if limit <= 0 {
		limit = float64(m.Threads)
	}
	return limit == l.RunnableLimit(m)
}`
	ctx := duplicateLibraryTestProject(t, "github.com/projecta/libkit", "github.com/projecta/app", source, map[string]string{"pressure/limits.go": inlineFieldLibrary}, true, "")
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Empty(t, violations, "the method is called in the same block")
}

const inlineFieldLibrary = `// Package pressure holds machine load limits.
package pressure

import "fmt"

// Load is one measure of the machine.
type Load struct {
	Threads int
	Avg1    float64
}

// Limits are the configured ceilings.
type Limits struct {
	Runnable float64
	MaxAvg   float64
	Name     string
}

// RunnableLimit is the ceiling of runnable tasks: the configured one, or the
// machine's threads when none is set.
func (l Limits) RunnableLimit(m Load) float64 {
	runnable := l.Runnable
	if runnable <= 0 {
		runnable = float64(m.Threads)
	}
	return runnable
}

// Over reports a load above the average ceiling.
func (l Limits) Over(m Load) bool {
	return l.MaxAvg > 0 && m.Avg1 > l.MaxAvg
}

// Label names the limits.
func (l Limits) Label() string {
	return l.Name
}

// Share prints a used share of a total.
func Share(used, total float64, name string) string {
	if total <= 0 {
		return name + ": n/a"
	}
	pct := used * 100 / total
	if pct > 100 {
		pct = 100
	}
	return fmt.Sprintf("%s: %.0f%%", name, pct)
}
`

const inlineFieldApp = `// Package queue admits heavy tasks.
package queue

import (
	"fmt"

	"github.com/projecta/libkit/pressure"
)

// Gate admits tasks under a limit.
type Gate struct {
	limits        pressure.Limits
	runnableLimit float64
	name          string
}

// Measure takes a new load. P1: the body of Limits.RunnableLimit inline, its condition turned around.
func (g *Gate) Measure(v pressure.Load) {
	g.runnableLimit = float64(v.Threads)
	if g.limits.Runnable > 0 {
		g.runnableLimit = g.limits.Runnable
	}
	g.name = "gate"
}

// Ceiling is P2: the same copy into a local variable, as written in the library.
func Ceiling(l pressure.Limits, m pressure.Load) int {
	limit := l.Runnable
	if limit <= 0 {
		limit = float64(m.Threads)
	}
	return int(limit) + 1
}

// Called is N1: the method is called.
func (g *Gate) Called(v pressure.Load) {
	g.runnableLimit = g.limits.RunnableLimit(v)
}

// Logged is N2: the same fields read, but only printed.
func Logged(l pressure.Limits, m pressure.Load) {
	fmt.Println(l.Runnable, m.Threads)
}

// OwnDefault is N3: the idiom over fields of the project's own type.
type own struct {
	Runnable float64
	Threads  int
}

// OwnLimit is N3.
func OwnLimit(o own) float64 {
	limit := o.Runnable
	if limit <= 0 {
		limit = float64(o.Threads)
	}
	return limit
}

// OneField is N4: one field of the library type, a getter's worth (Limits.Label reads one field).
func OneField(l pressure.Limits) string {
	name := l.Name
	if name == "" {
		name = "default"
	}
	return name
}

// Mixed is N5: the two fields go to different variables.
func Mixed(l pressure.Limits, m pressure.Load) (float64, int) {
	limit := l.Runnable
	threads := m.Threads
	return limit, threads
}

// shareCopy is C1: a whole copy of pressure.Share, which the rule finds today.
func shareCopy(used, total float64, name string) string {
	if total <= 0 {
		return name + ": n/a"
	}
	pct := used * 100 / total
	if pct > 100 {
		pct = 100
	}
	return fmt.Sprintf("%s: %.0f%%", name, pct)
}

var _ = shareCopy

func separated(l pressure.Limits, m pressure.Load) float64 {
    limit := l.Runnable
    fmt.Println("unrelated")
    if limit <= 0 {
        limit = float64(m.Threads)
    }
    return limit
}

func overwritten(l pressure.Limits, m pressure.Load) float64 {
    limit := l.Runnable
    limit = float64(m.Threads)
    return limit
}
`
