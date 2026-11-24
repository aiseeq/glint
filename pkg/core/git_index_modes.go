package core

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// runGitIndexModes lists the index entries under root that match pathspec,
// with their modes; a test replaces it to count the runs.
var runGitIndexModes = func(root, pathspec string) ([]byte, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-s", "-z", "--", pathspec)
	return cmd.Output()
}

// indexModesKey names one answer of GitIndexModes: the question and the
// state of the git index it was read from.
type indexModesKey struct {
	root       string
	pathspec   string
	indexSize  int64
	indexMtime int64
	hasIndex   bool
}

// indexModesCache keeps the answers for the process: every file of a run
// asks about the same index.
var indexModesCache = struct {
	sync.Mutex
	answers map[indexModesKey]map[string]string
}{answers: make(map[indexModesKey]map[string]string)}

// GitIndexModes returns the mode the git index records for each file under
// root that matches pathspec (100644, 100755, 120000 for a link), by its
// path relative to root with forward slashes — the mode every clone checks
// the file out with, whatever the disk of this one says. Git runs once per
// root, pathspec and state of the index in the process. Outside a
// repository, or without git, no file has a mode and there is no error.
func GitIndexModes(root, pathspec string) (map[string]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("make %s absolute: %w", root, err)
	}
	repo := findGitRepoRoot(abs)
	if inside, err := hasOwnGit(repo); err != nil || !inside {
		return map[string]string{}, err
	}
	key := indexModesKey{root: abs, pathspec: pathspec}
	// The state of the index joins the key: a mode changed between two runs
	// in one process changes the answer.
	if gitDir, gitDirErr := resolveGitDir(repo); gitDirErr == nil && gitDir != "" {
		if info, statErr := os.Stat(filepath.Join(gitDir, "index")); statErr == nil {
			key.hasIndex = true
			key.indexSize = info.Size()
			key.indexMtime = info.ModTime().UnixNano()
		}
	}
	indexModesCache.Lock()
	defer indexModesCache.Unlock()
	if answer, ok := indexModesCache.answers[key]; ok {
		return maps.Clone(answer), nil
	}
	output, err := runGitIndexModes(abs, pathspec)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return map[string]string{}, nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("list the index of %s: %w: %s", abs, err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("list the index of %s: %w", abs, err)
	}
	answer, err := parseIndexModes(output)
	if err != nil {
		return nil, fmt.Errorf("list the index of %s: %w", abs, err)
	}
	indexModesCache.answers[key] = answer
	return maps.Clone(answer), nil
}

// parseIndexModes reads `git ls-files -s -z`: entries of
// "<mode> <object> <stage>\t<path>" ended by NUL.
func parseIndexModes(output []byte) (map[string]string, error) {
	modes := make(map[string]string)
	for entry := range bytes.SplitSeq(output, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		// An entry without a tab has no path.
		head, path, _ := bytes.Cut(entry, []byte{'\t'})
		mode, _, spaced := bytes.Cut(head, []byte{' '})
		if !spaced || len(path) == 0 {
			return nil, fmt.Errorf("unexpected entry %q", entry)
		}
		modes[string(path)] = string(mode)
	}
	return modes, nil
}
