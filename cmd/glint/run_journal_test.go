package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/rules"
)

func TestAppendRunJournalWritesJSONLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "runs.jsonl")
	t.Setenv("GLINT_RUN_LOG", path)
	entry := runJournalEntry{
		Time: "2026-10-31T04:00:00+01:00", Root: filepath.Dir(path), Version: "v1.2.3",
		WallMS: 123, Files: 4, CachedFiles: 2, RootCache: "stamp", ProjectCache: "rules", Findings: map[string]int{"rule-a": 3},
		RuleMS: map[string]int64{"rule-a": 6}, Exit: 1,
	}
	if err := appendRunJournal(entry); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "\n") || strings.Count(string(data), "\n") != 1 {
		t.Fatalf("journal must contain one newline terminated record: %q", data)
	}
	var got runJournalEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid journal JSON: %v", err)
	}
	if got.Time != entry.Time || got.Root != entry.Root || got.Version != entry.Version || got.WallMS != entry.WallMS || got.Files != entry.Files || got.CachedFiles != entry.CachedFiles || got.RootCache != entry.RootCache || got.ProjectCache != entry.ProjectCache || got.Exit != entry.Exit || got.Findings["rule-a"] != 3 || got.RuleMS["rule-a"] != 6 {
		t.Errorf("decoded entry does not preserve fields: %#v", got)
	}
	if _, err := time.Parse(time.RFC3339, got.Time); err != nil {
		t.Errorf("time is not RFC3339: %v", err)
	}
}

func TestJournalHasRuleTimeWithoutTimingFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.jsonl")
	t.Setenv("GLINT_RUN_LOG", path)
	timings := newTimingCollectorMode(false)
	now, advance := fakeClock()
	timings.now = now
	done := timings.track("slow-rule", "fixture.go")
	advance(6 * time.Millisecond)
	done()

	if err := appendRunJournal(runJournalEntry{RuleMS: ruleMilliseconds(timings)}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got runJournalEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.RuleMS["slow-rule"] != 6 {
		t.Fatalf("journal rule_ms = %#v, want slow-rule: 6", got.RuleMS)
	}
}

func TestAppendRunJournalOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.jsonl")
	t.Setenv("GLINT_RUN_LOG", "off")
	if err := appendRunJournal(runJournalEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("disabled journal unexpectedly exists: %v", err)
	}
}

func TestAppendRunJournalConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.jsonl")
	t.Setenv("GLINT_RUN_LOG", path)
	const writers = 16
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	for i := range writers {
		wg.Go(func() {
			errCh <- appendRunJournal(runJournalEntry{Version: fmt.Sprint(i)})
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		var entry runJournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("line %d is not complete JSON: %v", lines+1, err)
		}
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines != writers {
		t.Fatalf("got %d journal lines, want %d", lines, writers)
	}
}

func TestAppendRunJournalRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.jsonl")
	t.Setenv("GLINT_RUN_LOG", path)
	root := permanentTestRoot(t)
	previous, _ := json.Marshal(runJournalEntry{Time: time.Now().Format(time.RFC3339), Root: root, RuleMS: map[string]int64{"rule-a": 6}})
	if err := os.WriteFile(path, append(previous, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLimit := runLogLimit
	runLogLimit = 1
	t.Cleanup(func() { runLogLimit = oldLimit })
	if err := appendRunJournal(runJournalEntry{Version: "new"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("rotated source should be removed after fold: %v", err)
	}
	daily, err := os.ReadFile(filepath.Join(filepath.Dir(path), "runs-daily.jsonl"))
	if err != nil || !strings.Contains(string(daily), `"rule-a":6`) {
		t.Fatalf("daily journal = %q, %v", daily, err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry runJournalEntry
	if err := json.Unmarshal(current, &entry); err != nil || entry.Version != "new" {
		t.Fatalf("current journal = %q, parse err %v", current, err)
	}
}

func TestRunJournalSkipsRunWithoutRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.jsonl")
	t.Setenv("GLINT_RUN_LOG", path)
	appendRunJournalWarning(runJournalEntry{Version: "v1.2.3", Exit: 1})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("run without a root must not be journaled, stat err %v", err)
	}
}

func TestRunJournalWriteFailureDoesNotChangeExitCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GLINT_RUN_LOG", filepath.Join(path, "runs.jsonl"))
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := appendRunJournal(runJournalEntry{}); err == nil {
		t.Fatal("expected journal write error")
	}
	oldStderr := os.Stderr
	os.Stderr = write
	appendRunJournalWarning(runJournalEntry{Root: path})
	_ = write.Close()
	os.Stderr = oldStderr
	warning, err := io.ReadAll(read)
	_ = read.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(warning), "warning: run journal not written") {
		t.Fatalf("missing write warning: %q", warning)
	}
	if got := runExitCode(errFindingsReported); got != 1 {
		t.Fatalf("journal failure must not affect the existing check exit code, got %d", got)
	}
}

func TestFoldRotatedJournalMergesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	root := permanentTestRoot(t)
	path := filepath.Join(dir, "runs.jsonl")
	entry := runJournalEntry{Time: time.Now().Format(time.RFC3339), Root: root, WallMS: 12, Findings: map[string]int{"long-function": 2}, RuleMS: map[string]int64{"long-function": 7}}
	line, _ := json.Marshal(entry)
	if err := os.WriteFile(path+".1", append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := foldRotatedJournal(path); err != nil {
		t.Fatal(err)
	}
	if err := foldRotatedJournal(path); err != nil {
		t.Fatal(err)
	}
	data := make(map[string]*dailyRecord)
	header := dailyHeader{}
	if err := readDaily(filepath.Join(dir, "runs-daily.jsonl"), data, &header); err != nil {
		t.Fatal(err)
	}
	d := data[time.Now().Format("2006-01-02")]
	if d == nil || d.Runs != 1 || d.RuleMS["long-function"] != 7 || d.Roots[root].Findings["long-function"] != 2 {
		t.Fatalf("daily record was lost or counted twice: %#v", d)
	}
	if header.FirstSeen["long-function"] == "" {
		t.Fatal("first_seen was not recorded")
	}
	report, err := makeStatsReport(path, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Runs != 1 {
		t.Fatalf("stats counted a crash-left rotation twice: runs=%d", report.Runs)
	}
}

func TestPermanentRootClassification(t *testing.T) {
	root := permanentTestRoot(t)
	if !isPermanentRoot(root) {
		t.Fatal("git directory should be permanent")
	}
	if isPermanentRoot(filepath.Join(root, "missing")) {
		t.Fatal("root without .git should be temporary")
	}
	if isPermanentRoot(t.TempDir()) {
		t.Fatal("temporary directory should be temporary")
	}
}

func permanentTestRoot(t *testing.T) string {
	t.Helper()
	// The checkout itself may lie under TMPDIR (a merge gate's copy), where
	// every root counts as temporary; a temp directory of its own that is not
	// an ancestor of the checkout keeps the project root permanent.
	tmp, err := os.MkdirTemp("", "glint-run-stats-tmp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(tmp); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("TMPDIR", tmp)
	root, err := os.MkdirTemp(".", ".run-stats-project-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestStatsWindowReportsCoverageHoleAndFindings(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.Local)
	start := localDay(now).AddDate(0, 0, -2)
	data := make(map[string]*dailyRecord)
	root := permanentTestRoot(t)
	for _, offset := range []int{0, 2} {
		day := start.AddDate(0, 0, offset)
		d := newDaily(day.Format("2006-01-02"))
		d.Runs = 1
		d.Roots[root] = &dailyRoot{Runs: 1, Findings: map[string]int{"long-function": 1}}
		data[d.Day] = d
	}
	report, err := buildStats(data, dailyHeader{FirstSeen: map[string]string{"deep-nesting": start.AddDate(0, 0, 1).Format("2006-01-02")}}, 3, start, localDay(now))
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.DaysWithRuns != 2 || report.Coverage.DaysWithoutRuns != 1 || report.Coverage.Complete {
		t.Fatalf("coverage = %#v", report.Coverage)
	}
	if len(report.RulesWithFindings) != 1 || report.RulesWithFindings[0].Days != 2 {
		t.Fatalf("findings = %#v", report.RulesWithFindings)
	}
	if !strings.Contains(report.CPUNote, "lower estimate") {
		t.Fatalf("missing CPU qualification: %q", report.CPUNote)
	}
}

func TestStatsRulesWithoutFindingsOrderAndConsoleCPULimit(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.Local)
	start := localDay(now).AddDate(0, 0, -2)
	allRules := rules.All()
	if len(allRules) < 3 {
		t.Fatalf("need at least three rules, got %d", len(allRules))
	}
	names := make([]string, 0, len(allRules))
	firstSeen := make(map[string]string, len(allRules))
	for _, rule := range allRules {
		name := rule.Name()
		names = append(names, name)
		firstSeen[name] = now.Format("2006-01-02")
	}
	sort.Strings(names)
	firstSeen[names[0]] = start.Format("2006-01-02")
	firstSeen[names[1]] = start.Format("2006-01-02")
	firstSeen[names[2]] = start.AddDate(0, 0, 1).Format("2006-01-02")
	report, err := buildStats(nil, dailyHeader{FirstSeen: firstSeen}, 3, start, localDay(now))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range names[:3] {
		if got := report.RulesWithoutFindings[i].Rule; got != want {
			t.Fatalf("rule at position %d = %q, want %q", i, got, want)
		}
	}
	// Days run to the report's end day, whatever the wall clock says.
	if got := []int{report.RulesWithoutFindings[0].Days, report.RulesWithoutFindings[2].Days}; got[0] != 3 || got[1] != 2 {
		t.Fatalf("days since first seen = %v, want [3 2]", got)
	}
	if report.RulesWithoutFindings[0].Since != report.RulesWithoutFindings[1].Since {
		t.Fatalf("same-day rules have different since dates: %#v", report.RulesWithoutFindings[:2])
	}

	today := now.Format("2006-01-02")
	consoleReport := statsReport{
		Days:                 3,
		Coverage:             statsCoverage{From: today, To: today, DaysWithRuns: 1, DaysWithoutRuns: 2},
		RulesWithoutFindings: []statsRuleEmpty{{Rule: "deep-nesting", Since: today, Days: 1}},
		CPU:                  make([]statsCPU, 25),
		CPUNote:              "CPU is a lower estimate.",
	}
	for i := range consoleReport.CPU {
		consoleReport.CPU[i] = statsCPU{Rule: fmt.Sprintf("cpu-%02d", i), MS: int64(25 - i)}
	}
	var output bytes.Buffer
	if err := printStats(&output, consoleReport); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "Rules without findings:\n  deep-nesting  since "+today+" (1 days)") {
		t.Fatalf("English rule section missing: %s", text)
	}
	if !strings.Contains(text, "Rule CPU (lower estimate):") || !strings.Contains(text, "... 5 more rules: -o json") {
		t.Fatalf("CPU section or truncation notice missing: %s", text)
	}
	if strings.Contains(text, "cpu-20:") || !strings.Contains(text, "cpu-19:") {
		t.Fatalf("console CPU list was not limited to 20: %s", text)
	}
}

func TestFirstFoldDatesRulesFromTheirFirstDayInJournal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runs.jsonl")
	root := permanentTestRoot(t)
	earliest := time.Now().AddDate(0, 0, -5)
	middle := time.Now().AddDate(0, 0, -3)
	var lines []byte
	for _, entry := range []runJournalEntry{
		{Time: earliest.Format(time.RFC3339), Root: root, WallMS: 1, RuleMS: map[string]int64{"long-function": 7}},
		{Time: middle.Format(time.RFC3339), Root: root, WallMS: 1, Findings: map[string]int{"deep-nesting": 1}},
		{Time: middle.Format(time.RFC3339), Root: t.TempDir(), WallMS: 1, RuleMS: map[string]int64{"empty-go-file": 5}},
	} {
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(append(lines, line...), '\n')
	}
	if err := os.WriteFile(path+".1", lines, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := foldRotatedJournal(path); err != nil {
		t.Fatal(err)
	}
	header := dailyHeader{}
	if err := readDaily(filepath.Join(dir, "runs-daily.jsonl"), make(map[string]*dailyRecord), &header); err != nil {
		t.Fatal(err)
	}
	for rule, want := range map[string]string{
		"long-function": earliest.Format("2006-01-02"),
		"deep-nesting":  middle.Format("2006-01-02"),
		"empty-go-file": middle.Format("2006-01-02"),
		"magic-number":  time.Now().Format("2006-01-02"),
	} {
		if got := header.FirstSeen[rule]; got != want {
			t.Errorf("first fold: %s first_seen = %q, want %q", rule, got, want)
		}
	}
}

func TestCalendarDaysSinceCountsDatesAcrossDST(t *testing.T) {
	// Standard time at since, daylight time at today, as in a zone that moved
	// its clocks in between: the span is 37 days and 23 hours, the dates 38.
	since := time.Date(2026, 9, 26, 0, 0, 0, 0, time.FixedZone("NZST", 12*3600))
	today := time.Date(2026, 11, 2, 0, 0, 0, 0, time.FixedZone("NZDT", 13*3600))
	if got := calendarDaysSince(since, today); got != 38 {
		t.Fatalf("26 Sep through 2 Nov across the DST change: got %d days, want 38", got)
	}
}

func TestFoldKeepsExactlyRetentionDays(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runs.jsonl")
	root := permanentTestRoot(t)
	var lines []byte
	for _, ago := range []int{runJournalRetention - 1, runJournalRetention} {
		entry := runJournalEntry{Time: localDay(time.Now()).AddDate(0, 0, -ago).Add(12 * time.Hour).Format(time.RFC3339), Root: root, WallMS: 1}
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(append(lines, line...), '\n')
	}
	if err := os.WriteFile(path+".1", lines, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := foldRotatedJournal(path); err != nil {
		t.Fatal(err)
	}
	data := make(map[string]*dailyRecord)
	if err := readDaily(filepath.Join(dir, "runs-daily.jsonl"), data, &dailyHeader{}); err != nil {
		t.Fatal(err)
	}
	if len(data) != 1 {
		t.Fatalf("want only the day %d days ago kept, got %d days", runJournalRetention-1, len(data))
	}
}
