package concurrencyrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hotAllocGuardSource marks functions hot; a test measures the allocations
// of some of them. A hot function no AllocsPerRun closure and no benchmark
// with ReportAllocs reaches is a declaration nobody checks: its allocations
// grow unnoticed.
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
func Decode(b []byte) int { return len(b) }

//glint:hot
func Render(n int) int { return n } // want hot-function-without-alloc-guard

//glint:hot
func Compare(a, b int) bool { return a == b } // want hot-function-without-alloc-guard
`

const hotAllocGuardTest = `package engine

import "testing"

func TestStepAllocs(t *testing.T) {
	e := &Engine{stages: []Stage{&mover{}}}
	if got := testing.AllocsPerRun(10, func() { e.Step() }); got > 0 {
		t.Errorf("allocs %.1f", got)
	}
}

func BenchmarkDecode(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Decode(nil)
	}
}

func BenchmarkCompare(b *testing.B) {
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
