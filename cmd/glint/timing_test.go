package main

import (
	"strings"
	"testing"
	"time"
)

// fakeClock returns a controllable now() and a function to advance it.
func fakeClock() (func() time.Time, func(d time.Duration)) {
	current := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return current },
		func(d time.Duration) { current = current.Add(d) }
}

func TestTimingCollectorAccumulatesPerRule(t *testing.T) {
	tc := newTimingCollector()
	now, advance := fakeClock()
	tc.now = now

	done := tc.track("slow-rule", "a.go")
	advance(30 * time.Millisecond)
	done()

	done = tc.track("slow-rule", "b.go")
	advance(70 * time.Millisecond)
	done()

	done = tc.track("fast-rule", "a.go")
	advance(5 * time.Millisecond)
	done()

	var out strings.Builder
	if err := tc.report(&out); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	slowIdx := strings.Index(got, "slow-rule")
	fastIdx := strings.Index(got, "fast-rule")
	if slowIdx == -1 || fastIdx == -1 {
		t.Fatalf("report must mention both rules, got:\n%s", got)
	}
	if slowIdx > fastIdx {
		t.Errorf("rules must be sorted by total time descending, got:\n%s", got)
	}
	if !strings.Contains(got, "100ms") {
		t.Errorf("slow-rule total must be 100ms, got:\n%s", got)
	}
	// The slowest single file is what gets sent to the author of the rule.
	if !strings.Contains(got, "b.go") {
		t.Errorf("report must name the slowest file b.go, got:\n%s", got)
	}
}

func TestTimingCollectorReportsInFlightRuns(t *testing.T) {
	tc := newTimingCollector()
	now, advance := fakeClock()
	tc.now = now

	tc.track("stuck-rule", "huge.go") // never finished — the hang case
	advance(42 * time.Second)

	var out strings.Builder
	if err := tc.report(&out); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	if !strings.Contains(got, "stuck-rule") || !strings.Contains(got, "huge.go") {
		t.Fatalf("report must name the in-flight rule and file, got:\n%s", got)
	}
	if !strings.Contains(got, "42s") {
		t.Errorf("report must show how long the run has been stuck, got:\n%s", got)
	}
}

func TestTimingCollectorFoldsSubMillisecondRules(t *testing.T) {
	tc := newTimingCollector()
	now, advance := fakeClock()
	tc.now = now

	done := tc.track("visible-rule", "a.go")
	advance(2 * time.Millisecond)
	done()

	for _, name := range []string{"noise-1", "noise-2"} {
		done := tc.track(name, "a.go")
		advance(10 * time.Microsecond)
		done()
	}

	var out strings.Builder
	if err := tc.report(&out); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	if strings.Contains(got, "noise-1") {
		t.Errorf("sub-millisecond rules must be folded into a summary line, got:\n%s", got)
	}
	if !strings.Contains(got, "2 rules under 1ms") {
		t.Errorf("folded rules must be counted, got:\n%s", got)
	}
}

func TestTimingCollectorRecordsPhases(t *testing.T) {
	tc := newTimingCollector()
	now, advance := fakeClock()
	tc.now = now

	done := tc.phase("load .")
	advance(1500 * time.Millisecond)
	done()

	var out strings.Builder
	if err := tc.report(&out); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	if !strings.Contains(got, "load .") || !strings.Contains(got, "1.5s") {
		t.Fatalf("report must show the phase with its duration, got:\n%s", got)
	}
}

// A hang inside go/packages loading must be visible on interrupt, the same
// way a stuck rule is.
func TestTimingCollectorReportsInFlightPhase(t *testing.T) {
	tc := newTimingCollector()
	now, advance := fakeClock()
	tc.now = now

	tc.phase("load /big/project") // never finished
	advance(90 * time.Second)

	var out strings.Builder
	if err := tc.report(&out); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	if !strings.Contains(got, "load /big/project") || !strings.Contains(got, "1m30s") {
		t.Fatalf("report must show the unfinished phase with its age, got:\n%s", got)
	}
}

// A nil collector is the disabled state: every call site relies on it being a
// no-op instead of checking a flag.
func TestNilTimingCollectorIsNoOp(t *testing.T) {
	var tc *timingCollector
	tc.track("rule", "file.go")()
	tc.phase("load")()
	var out strings.Builder
	if err := tc.report(&out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("nil collector must write nothing, got: %q", out.String())
	}
}
