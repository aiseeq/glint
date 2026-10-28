package concurrencyrules

import (
	"testing"

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
