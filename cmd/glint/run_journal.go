package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/aiseeq/glint/pkg/core"
)

const defaultRunLogLimit int64 = 64 << 20

var runLogLimit = defaultRunLogLimit

// noteCacheMiss records why the cache of a root missed; with several roots
// the first miss of each kind stands.
func (e *runJournalEntry) noteCacheMiss(cache *resultCache) {
	if e.RootCache == "" {
		e.RootCache = cache.rootMiss
	}
	if e.ProjectCache == "" {
		e.ProjectCache = cache.projectMiss
	}
}

type runJournalEntry struct {
	Time         string         `json:"time"`
	Root         string         `json:"root"`
	Version      string         `json:"version"`
	WallMS       int64          `json:"wall_ms"`
	Files        int            `json:"files"`
	CachedFiles  int            `json:"cached_files"`
	RootCache    string         `json:"root_cache,omitempty"`
	ProjectCache string         `json:"project_cache,omitempty"`
	Findings     map[string]int `json:"findings"`

	RuleMS map[string]int64 `json:"rule_ms"`
	Exit   int              `json:"exit"`
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

func absoluteRunJournalPath(path, operation string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve run journal path for %s: %w", operation, err)
	}
	return abs, nil
}

func ensureRunJournalDirectory(path, operation string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("%s: create run journal directory: %w", operation, err)
	}
	return nil
}

func openRunJournalLock(path, operation string) (*os.File, error) {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%s: open run journal lock: %w", operation, err)
	}
	return lock, nil
}

func appendRunJournal(entry runJournalEntry) (retErr error) {
	path, enabled, err := runLogPath()
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	limit := runLogLimit
	if raw, ok := os.LookupEnv("GLINT_RUN_LOG_LIMIT"); ok {
		parsed, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || parsed < 1 {
			return fmt.Errorf("GLINT_RUN_LOG_LIMIT must be a positive byte count")
		}
		limit = parsed
	}
	path, err = absoluteRunJournalPath(path, "append")
	if err != nil {
		return err
	}
	if err := ensureRunJournalDirectory(path, "append"); err != nil {
		return err
	}
	lock, err := openRunJournalLock(path, "append")
	if err != nil {
		return err
	}
	locked := false
	defer func() {
		if locked {
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("unlock run journal: %w", err))
			}
		}
		if err := lock.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close run journal lock: %w", err))
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock run journal: %w", err)
	}
	locked = true

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open run journal: %w", err)
	}
	info, statErr := file.Stat()
	if statErr != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return errors.Join(fmt.Errorf("stat run journal: %w", statErr), fmt.Errorf("close run journal after stat failure: %w", closeErr))
		}
		return fmt.Errorf("stat run journal: %w", statErr)
	}
	if info.Size() > limit {
		if err := file.Close(); err != nil {
			return fmt.Errorf("close run journal before rotation: %w", err)
		}
		if err := rotateRunJournal(path); err != nil {
			return err
		}
		file, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open run journal after rotation: %w", err)
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

func rotateRunJournal(path string) error {
	rotated := path + ".1"
	if _, err := os.Stat(rotated); err == nil {
		if err := foldRotatedJournal(path); err != nil {
			fmt.Fprintf(os.Stderr, "warning: run journal fold failed: %v\n", err)
			return nil
		}
		if err := os.Remove(rotated); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove previous run journal: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat previous run journal: %w", err)
	}
	if err := os.Rename(path, rotated); err != nil {
		return fmt.Errorf("rotate run journal: %w", err)
	}
	if err := foldRotatedJournal(path); err != nil {
		fmt.Fprintf(os.Stderr, "warning: run journal fold failed: %v\n", err)
		return nil
	}
	if err := os.Remove(rotated); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "warning: remove folded run journal: %v\n", err)
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
	// A run that failed before resolving a project root has nothing to attribute.
	if entry.Root == "" {
		return
	}
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
