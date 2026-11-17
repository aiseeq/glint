package concurrencyrules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runtimeGCTuningSource tunes the collector from code: the frame loop leaves
// garbage every tick, and instead of removing it the program makes the
// collector run less often, paying with memory. Forcing a collection to take
// an up-to-date heap profile or memory reading is measurement, not tuning.
const runtimeGCTuningSource = `package prof

import (
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"runtime/pprof"
)

const gogcVar = "GOGC"

func GC() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(400) // want runtime-gc-tuning
	}
}

func limit() {
	debug.SetMemoryLimit(512 << 20) // want runtime-gc-tuning
	_ = os.Setenv(gogcVar, "off") // want runtime-gc-tuning
	_ = os.Setenv("GOMEMLIMIT", "1GiB") // want runtime-gc-tuning
	_ = os.Setenv("GOMAXPROCS", "4")
	_ = os.Getenv("GOGC")
}

func compact() {
	runtime.GC() // want runtime-gc-tuning
	debug.FreeOSMemory() // want runtime-gc-tuning
}

func containerLimit() {
	debug.SetMemoryLimit(900 << 20) // runtime-gc-tuning: safe — the container is capped at 1 GiB, RSS measured at 700 MiB
}

func writeHeap(f *os.File) error {
	runtime.GC() // get up-to-date statistics
	return pprof.WriteHeapProfile(f)
}

func heapInUse() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func liveHeap() uint64 {
	runtime.GC()
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(sample)
	return sample[0].Value.Uint64()
}
`

// runtimeGCTuningTest is the same tuning in a test: a benchmark or a test
// that measures memory sets the collector up on purpose.
const runtimeGCTuningTest = `package prof

import (
	"runtime/debug"
	"testing"
)

func TestHeap(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
}
`

func TestRuntimeGCTuning(t *testing.T) {
	files := map[string]string{"prof/prof.go": runtimeGCTuningSource, "prof/prof_test.go": runtimeGCTuningTest}
	violations, err := NewRuntimeGCTuningRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "runtime-gc-tuning"), patterntest.FoundLines(violations))
}

func TestRuntimeGCTuningOutsideGo(t *testing.T) {
	cases := []struct {
		name, source string
		want         []int
	}{
		{"scripts/run.sh", "#!/bin/sh\nexport GOGC=50\nGOMEMLIMIT=1GiB ./app\n", []int{2, 3}},
		{"Makefile", "run:\n\tGOGC=50 ./app\n", []int{2}},
		{"Dockerfile", "FROM alpine\nENV GOMEMLIMIT=1GiB\n", []int{2}},
		{"compose.yaml", "services:\n  app:\n    image: app\n    environment:\n      GOGC: 50\n  worker:\n    image: app\n    environment:\n      - GOMEMLIMIT=1200MiB\n  capped:\n    image: app\n    environment:\n      - GOMEMLIMIT=1200MiB #nolint:runtime-gc-tuning hard memory cap\n", []int{5, 9}},
		{"scripts/bench.sh", "#!/bin/sh\nGOGC=off go test -run xxx -bench . ./...\n", nil},
		{".graft.yaml", "tasks:\n  test:\n    env:\n      GOGC: off\n", nil},
	}
	rule := NewRuntimeGCTuningRule()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := core.NewFileContext("/project/"+tc.name, "/project", []byte(tc.source), nil)
			found := rule.AnalyzeFile(ctx)
			var lines []int
			for _, v := range found {
				lines = append(lines, v.Line)
				assert.Equal(t, core.SeverityMedium, v.Severity)
			}
			assert.Equal(t, tc.want, lines)
		})
	}
	assert.Contains(t, rule.Description(), ".graft.yaml")
	assert.Contains(t, strings.ToLower(rule.Description()), "bench")
}
