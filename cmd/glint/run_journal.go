package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aiseeq/glint/pkg/core"
)

const defaultRunLogLimit int64 = 64 << 20

var runLogLimit = defaultRunLogLimit

type runJournalEntry struct {
	Time        string           `json:"time"`
	Root        string           `json:"root"`
	Version     string           `json:"version"`
	WallMS      int64            `json:"wall_ms"`
	Files       int              `json:"files"`
	CachedFiles int              `json:"cached_files"`
	Findings    map[string]int   `json:"findings"`
	Suppressed  map[string]int   `json:"suppressed,omitempty"`
	RuleMS      map[string]int64 `json:"rule_ms"`
	Exit        int              `json:"exit"`
}

func runLogPath() (string, bool, error) {
	if path, ok := os.LookupEnv("GLINT_RUN_LOG"); ok {
		if path == "off" {
			return "", false, nil
		}
		if path == "" {
			return "", false, fmt.Errorf("GLINT_RUN_LOG is empty")
		}
		return path, true, nil
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false, fmt.Errorf("get home directory for run journal: %w", err)
		}
		state = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(state, "glint", "runs.jsonl"), true, nil
}

func appendRunJournal(entry runJournalEntry) (retErr error) {
	path, enabled, err := runLogPath()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	if !filepath.IsAbs(path) {
		path, err = filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve run journal path: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create run journal directory: %w", err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open run journal lock: %w", err)
	}
	defer func() {
		if err := lock.Close(); retErr == nil && err != nil {
			retErr = fmt.Errorf("close run journal lock: %w", err)
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock run journal: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open run journal: %w", err)
	}
	info, statErr := file.Stat()
	if statErr != nil {
		return fmt.Errorf("stat run journal: %w", statErr)
	}
	if info.Size() > runLogLimit {
		if err := file.Close(); err != nil {
			return fmt.Errorf("close run journal before rotation: %w", err)
		}
		if err := os.Remove(path + ".1"); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove previous run journal: %w", err)
		}
		if err := os.Rename(path, path+".1"); err != nil {
			return fmt.Errorf("rotate run journal: %w", err)
		}
		file, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("create rotated run journal: %w", err)
		}
	}
	defer func() {
		if err := file.Close(); retErr == nil && err != nil {
			retErr = fmt.Errorf("close run journal: %w", err)
		}
	}()
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode run journal entry: %w", err)
	}
	line = append(line, '\n')
	n, err := file.Write(line)
	if err != nil {
		return fmt.Errorf("write run journal: %w", err)
	}
	if n != len(line) {
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(line))
	}
	return nil
}

func runExitCode(err error) int {
	if err == nil {
		return 0
	}
	var usageErr usageError
	if errors.As(err, &usageErr) {
		return exitUsage
	}
	return 1
}

func ruleMilliseconds(tc *timingCollector) map[string]int64 {
	result := make(map[string]int64)
	if tc == nil {
		return result
	}
	for name, duration := range tc.ruleDurations() {
		ms := duration.Milliseconds()
		if ms >= 5 {
			result[name] = ms
		}
	}
	return result
}

func findingsByRule(list core.ViolationList) map[string]int {
	counts := make(map[string]int)
	for _, finding := range list {
		counts[finding.Rule]++
	}
	return counts
}

func appendRunJournalWarning(entry runJournalEntry) {
	if err := appendRunJournal(entry); err != nil {
		fmt.Fprintf(os.Stderr, "warning: run journal not written: %v\n", err)
	}
}

func runJournalTime(t time.Time) string { return t.Format(time.RFC3339) }

func journalRoot(roots []analysisRoot) string {
	if len(roots) == 0 {
		return ""
	}
	return roots[0].dir
}
