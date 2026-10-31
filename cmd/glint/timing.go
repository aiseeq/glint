package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/pprof"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aiseeq/glint/pkg/output"
)

// timingCollector accumulates rule durations for the run journal, and keeps
// detailed phase and per-file data when --timing is enabled. A nil collector
// is the disabled state: every method is a no-op, so call sites never check
// the flag. In-flight runs localize hangs in detailed mode.
type timingCollector struct {
	// now is replaceable in tests; measuring real durations otherwise.
	now func() time.Time
	// detailed keeps the lock-based data needed by --timing reports. The
	// lightweight path only accumulates per-rule totals for the run journal.
	detailed bool

	mu       sync.Mutex
	phases   []phaseTiming
	rules    map[string]*ruleTiming
	inFlight map[uint64]inFlightRun
	nextID   uint64
	quick    sync.Map // map[string]*atomic.Int64, nanoseconds
}

type phaseTiming struct {
	name     string
	duration time.Duration
}

type ruleTiming struct {
	name    string
	total   time.Duration
	max     time.Duration
	maxFile string
}

type inFlightRun struct {
	rule    string
	file    string
	started time.Time
}

func newTimingCollector() *timingCollector {
	return newTimingCollectorMode(true)
}

func newTimingCollectorMode(detailed bool) *timingCollector {
	tc := &timingCollector{now: time.Now, detailed: detailed}
	if detailed {
		tc.rules = make(map[string]*ruleTiming)
		tc.inFlight = make(map[uint64]inFlightRun)
	}
	return tc
}

// track registers a (rule, file) run and returns the function that finishes
// it. The run stays visible as in-flight until finished, so a hang can be
// localized from the interrupt report.
func (tc *timingCollector) track(rule, file string) func() {
	if tc == nil {
		return func() {}
	}
	if !tc.detailed {
		started := tc.now()
		return func() {
			elapsed := tc.now().Sub(started)
			value, ok := tc.quick.Load(rule)
			if !ok {
				candidate := new(atomic.Int64)
				value, _ = tc.quick.LoadOrStore(rule, candidate)
			}
			value.(*atomic.Int64).Add(int64(elapsed))
		}
	}
	started := tc.now()
	tc.mu.Lock()
	tc.nextID++
	id := tc.nextID
	tc.inFlight[id] = inFlightRun{rule: rule, file: file, started: started}
	tc.mu.Unlock()

	return func() {
		elapsed := tc.now().Sub(started)
		tc.mu.Lock()
		defer tc.mu.Unlock()
		delete(tc.inFlight, id)
		timing := tc.rules[rule]
		if timing == nil {
			timing = &ruleTiming{name: rule}
			tc.rules[rule] = timing
		}
		timing.total += elapsed
		if elapsed >= timing.max {
			timing.max = elapsed
			timing.maxFile = file
		}
	}
}

// phase times a coarse stage (walk+parse+type-check, analysis). The stage is
// kept in-flight until finished for the same reason rules are: a hang inside
// go/packages loading must be visible on interrupt.
func (tc *timingCollector) phase(name string) func() {
	if tc == nil || !tc.detailed {
		return func() {}
	}
	started := tc.now()
	tc.mu.Lock()
	tc.nextID++
	id := tc.nextID
	tc.inFlight[id] = inFlightRun{rule: name, file: "(phase)", started: started}
	tc.mu.Unlock()

	return func() {
		elapsed := tc.now().Sub(started)
		tc.mu.Lock()
		defer tc.mu.Unlock()
		delete(tc.inFlight, id)
		tc.phases = append(tc.phases, phaseTiming{name: name, duration: elapsed})
	}
}

func (tc *timingCollector) ruleDurations() map[string]time.Duration {
	if tc == nil {
		return nil
	}
	if tc.detailed {
		tc.mu.Lock()
		defer tc.mu.Unlock()
		durations := make(map[string]time.Duration, len(tc.rules))
		for name, timing := range tc.rules {
			durations[name] = timing.total
		}
		return durations
	}
	durations := make(map[string]time.Duration)
	tc.quick.Range(func(key, value any) bool {
		durations[key.(string)] = time.Duration(value.(*atomic.Int64).Load())
		return true
	})
	return durations
}

func writeTimingReport() error {
	if !flagTiming {
		return nil
	}
	return timings.report(os.Stderr)
}

// report writes the collected timings. Rules are sorted by total time
// descending; sub-millisecond rules are folded into one summary line. Runs
// still in flight are listed with their age — after an interrupt that section
// points at the rule and file the analysis hung on.
func (tc *timingCollector) report(w io.Writer) error {
	if tc == nil {
		return nil
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()

	rw := output.NewReportWriter(w)
	rw.Line("TIMING")
	for _, phase := range tc.phases {
		rw.Printf("  %-52s %8s\n", phase.name, formatDuration(phase.duration))
	}
	if len(tc.phases) > 0 {
		rw.Line()
	}

	sorted := make([]*ruleTiming, 0, len(tc.rules))
	for _, timing := range tc.rules {
		sorted = append(sorted, timing)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].total != sorted[j].total {
			return sorted[i].total > sorted[j].total
		}
		return sorted[i].name < sorted[j].name
	})

	if len(sorted) > 0 {
		rw.Printf("  %-36s %8s %8s  %s\n", "RULE", "TOTAL", "MAX", "SLOWEST FILE")
	}
	folded := 0
	for _, timing := range sorted {
		if timing.total < time.Millisecond {
			folded++
			continue
		}
		rw.Printf("  %-36s %8s %8s  %s\n",
			timing.name, formatDuration(timing.total), formatDuration(timing.max), timing.maxFile)
	}
	if folded > 0 {
		rw.Printf("  (%d rules under 1ms)\n", folded)
	}

	if len(tc.inFlight) > 0 {
		stuck := make([]inFlightRun, 0, len(tc.inFlight))
		for _, run := range tc.inFlight {
			stuck = append(stuck, run)
		}
		sort.Slice(stuck, func(i, j int) bool { return stuck[i].started.Before(stuck[j].started) })
		rw.Line("\n  IN FLIGHT (not finished — a hang points here)")
		for _, run := range stuck {
			rw.Printf("  %-36s %8s  %s\n", run.rule, formatDuration(tc.now().Sub(run.started)), run.file)
		}
	}
	return rw.Err()
}

// exitInterrupted is the status of a process stopped by SIGINT, as a shell
// reports it: 128 + the signal number.
const exitInterrupted = 130

// reportTimingsOnInterrupt dumps the timings collected so far when the run is
// interrupted — the report a user sends the author when glint hangs on their
// project: completed rules plus the in-flight (rule, file) it was stuck on.
// Returns the function that uninstalls the handler.
func reportTimingsOnInterrupt(tc *timingCollector) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		if _, open := <-sigCh; !open {
			return // normal completion, handler uninstalled
		}
		fmt.Fprintln(os.Stderr, "\ninterrupted — timings collected so far:")
		_ = tc.report(os.Stderr) // ignored-error: safe — exiting; a stderr write failure has nowhere left to be reported

		os.Exit(exitInterrupted)
	}()
	return func() {
		signal.Stop(sigCh)
		close(sigCh)
	}
}

// formatDuration trims time.Duration noise: sub-second values in whole
// milliseconds, the rest in tenths of a second.
func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return "<1ms"
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

// startCPUProfile starts writing a CPU profile to path; the returned function
// stops it and closes the file.
func startCPUProfile(path string) (func(), error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("start CPU profile: %w", err)
	}
	return func() {
		pprof.StopCPUProfile()
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close CPU profile: %v\n", err)
		}
	}, nil
}
