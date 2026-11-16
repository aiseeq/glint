package concurrencyrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hotAllocGuardSource marks functions hot; a test measures the allocations
// of some of them. Only a checked AllocsPerRun result guards a hot function.
const hotAllocGuardSource = `package engine

type Stage interface{ Step() }

type mover struct{ buf []int }

//glint:hot
func (m *mover) Step() { m.buf = m.buf[:0] }

type Engine struct{ stages []Stage }

//glint:hot
func (e *Engine) Step() {
	for _, s := range e.stages {
		s.Step()
	}
	e.apply()
}

//glint:hot
func (e *Engine) apply() {}

//glint:hot
func Decode(b []byte) int { return len(b) } // want hot-function-without-alloc-guard

//glint:hot
func Render(n int) int { return n } // want hot-function-without-alloc-guard

//glint:hot
func Compare(a, b int) bool { return a == b } // want hot-function-without-alloc-guard

//glint:hot
func Logged() {} // want hot-function-without-alloc-guard

//glint:hot
func Discarded() {} // want hot-function-without-alloc-guard

//glint:hot
func Assigned() {}

//glint:hot
func ComparedElsewhere() {} // want hot-function-without-alloc-guard

//glint:hot
func Returned() {}

//glint:hot
func PassedToCheck() {}

func check(any) {}
`

const hotAllocGuardTest = `package engine

import "testing"

func TestStepAllocs(t *testing.T) {
	e := &Engine{stages: []Stage{&mover{}}}
	if got := testing.AllocsPerRun(10, func() { e.Step() }); got > 0 {
		t.Errorf("allocs %.1f", got)
	}
}

func TestOtherAllocs(t *testing.T) {
	_ = testing.AllocsPerRun(10, func() { Logged() })
	t.Log(testing.AllocsPerRun(10, func() { Logged() }))
	testing.AllocsPerRun(10, func() { Discarded() })
	assigned := testing.AllocsPerRun(10, func() { Assigned() })
	if assigned > 2 {
		t.Fatal(assigned)
	}
	elsewhere := testing.AllocsPerRun(10, func() { ComparedElsewhere() })
	check(elsewhere)
	compareElsewhere(elsewhere)
	if n := testing.AllocsPerRun(10, func() { Returned() }) / float64(2); n != 0 {
		t.Fatal(n)
	}
	check(testing.AllocsPerRun(10, func() { PassedToCheck() }))
}

func compareElsewhere(value float64) {
	if value > 2 {
		panic(value)
	}
}

func allocationResult() float64 {
	return testing.AllocsPerRun(10, func() { Returned() })
}

func BenchmarkDecode(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Decode(nil)
	}
}

func BenchmarkCompare(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Compare(1, 2)
	}
}
`

func TestHotFunctionWithoutAllocGuard(t *testing.T) {
	files := map[string]string{"engine/engine.go": hotAllocGuardSource, "engine/engine_test.go": hotAllocGuardTest}
	violations, err := NewHotFunctionWithoutAllocGuardRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "hot-function-without-alloc-guard"), patterntest.FoundLines(violations))
}
