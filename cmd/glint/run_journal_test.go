package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppendRunJournalWritesJSONLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "runs.jsonl")
	t.Setenv("GLINT_RUN_LOG", path)
	entry := runJournalEntry{
		Time: "2026-10-31T04:00:00+01:00", Root: filepath.Dir(path), Version: "v1.2.3",
		WallMS: 123, Files: 4, CachedFiles: 2, Findings: map[string]int{"rule-a": 3},
		Suppressed: map[string]int{"rule-b": 1}, RuleMS: map[string]int64{"rule-a": 6}, Exit: 1,
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
	if got.Time != entry.Time || got.Root != entry.Root || got.Version != entry.Version || got.WallMS != entry.WallMS || got.Files != entry.Files || got.CachedFiles != entry.CachedFiles || got.Exit != entry.Exit || got.Findings["rule-a"] != 3 || got.Suppressed["rule-b"] != 1 || got.RuleMS["rule-a"] != 6 {
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
	defer file.Close()
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
	if err := os.WriteFile(path, []byte("previous record\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLimit := runLogLimit
	runLogLimit = 1
	t.Cleanup(func() { runLogLimit = oldLimit })
	if err := appendRunJournal(runJournalEntry{Version: "new"}); err != nil {
		t.Fatal(err)
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil || string(rotated) != "previous record\n" {
		t.Fatalf("rotated file = %q, %v", rotated, err)
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
	appendRunJournalWarning(runJournalEntry{})
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
