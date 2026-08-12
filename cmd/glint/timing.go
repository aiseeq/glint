package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"sync"
	"time"

	"github.com/aiseeq/glint/pkg/output"
)

// timingCollector accumulates per-phase and per-rule durations under --timing.
// A nil collector is the disabled state: every method is a no-op, so call
// sites never check the flag. In-flight runs are kept so that an interrupted
// (hung) analysis can still report which rule is stuck on which file.
type timingCollector struct {
	// now is replaceable in tests; measuring real durations otherwise.
	now func() time.Time

	mu       sync.Mutex
	phases   []phaseTiming
	rules    map[string]*ruleTiming
	inFlight map[uint64]inFlightRun
	nextID   uint64
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
	return &timingCollector{
		now:      time.Now,
		rules:    make(map[string]*ruleTiming),
		inFlight: make(map[uint64]inFlightRun),
	}
}

// track registers a (rule, file) run and returns the function that finishes
// it. The run stays visible as in-flight until finished, so a hang can be
// localized from the interrupt report.
func (tc *timingCollector) track(rule, file string) func() {
	if tc == nil {
		return func() {}
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
	if tc == nil {
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

		os.Exit(130)
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
