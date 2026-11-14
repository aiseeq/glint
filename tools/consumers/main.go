// Command consumers compares glint findings across configured project roots.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/output"
)

type config struct {
	roots []string
	skips map[string]bool
}

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("consumers", flag.ContinueOnError)
	fs.SetOutput(stderr)
	home, err := os.UserHomeDir()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: find home directory: %v\n", err)
		return 2
	}
	cfgPath := fs.String("config", filepath.Join(home, ".config", "glint", "consumers.txt"), "consumer roots config")
	oldPath := fs.String("old", filepath.Join(home, "bin", "glint"), "installed glint binary")
	newPath := fs.String("new", "bin/glint", "new glint binary")
	rules := fs.String("r", "", "comma-separated rules")
	jobs := fs.String("j", "", "glint parallelism")
	only := fs.String("only", "", "comma-separated project names")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: consumers [-config PATH] [-old PATH] [-new PATH] [-r rules] [-j N] [-only a,b]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: parse flags: %v\n", err)
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "consumers: unexpected arguments")
		return 2
	}
	oldAbs, err := filepath.Abs(*oldPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	newAbs, err := filepath.Abs(*newPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	cfg, err := readConfig(*cfgPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "consumers:", err)
		return 2
	}
	projects, err := findProjects(cfg)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "consumers:", err)
		return 2
	}
	selected := map[string]bool{}
	if *only != "" {
		for name := range strings.SplitSeq(*only, ",") {
			selected[strings.TrimSpace(name)] = true
		}
	}
	var targets []string
	for _, p := range projects {
		name := filepath.Base(p)
		if !cfg.skips[name] && (len(selected) == 0 || selected[name]) {
			targets = append(targets, p)
		}
	}
	sort.Strings(targets)
	if _, err := os.Stat(oldAbs); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: old binary %s: %v\n", oldAbs, err)
		return 2
	}
	if _, err := os.Stat(newAbs); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: new binary %s: %v\n", newAbs, err)
		return 2
	}

	userCache, err := os.UserCacheDir()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: find user cache directory: %v\n", err)
		return 2
	}
	// A glint run prunes the result caches of other builds, so the new build
	// runs in a directory of its own and leaves the installed glint's caches.
	newCache := filepath.Join(userCache, "glint", "consumers-new")
	oldRuns, err := newOldRunCache(filepath.Join(userCache, "glint", "consumers"), oldAbs)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: old binary %s: %v\n", oldAbs, err)
		return 2
	}
	checkArguments := checkArgs(*rules, *jobs)

	diffs, errs, cached, rerun := 0, 0, 0, 0
	for _, p := range targets {
		name := filepath.Base(p)
		oldIssues, fromCache, oldErr := oldRuns.check(p, checkArguments, true, stderr)
		if oldErr != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %s\n", name, oldErr)
			errs++
			continue
		}
		newIssues, newErr := check(newAbs, p, checkArguments, newCache)
		if newErr != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %s\n", name, newErr)
			errs++
			continue
		}
		added, removed := difference(oldIssues, newIssues)
		if fromCache && len(added)+len(removed) > 0 {
			// glint reads more than the key covers (a list outside the
			// project, a go.work module, an ignored file): a difference from
			// a cached run holds only once the installed glint differs again.
			rerun++
			fromCache = false
			if oldIssues, _, oldErr = oldRuns.check(p, checkArguments, false, stderr); oldErr != nil {
				_, _ = fmt.Fprintf(stderr, "%s: %s\n", name, oldErr)
				errs++
				continue
			}
			added, removed = difference(oldIssues, newIssues)
		}
		if fromCache {
			cached++
		}
		if len(added)+len(removed) == 0 {
			continue
		}
		diffs++
		_, _ = fmt.Fprintf(stdout, "== %s: +%d -%d\n", p, len(added), len(removed))
		for i := range added {
			printIssue(stdout, "+", added[i])
		}
		for i := range removed {
			printIssue(stdout, "-", removed[i])
		}
	}
	skipped := slices.Sorted(maps.Keys(cfg.skips))
	_, _ = fmt.Fprintf(stdout, "old glint: %d of %d projects from cache", cached, len(targets))
	if rerun > 0 {
		_, _ = fmt.Fprintf(stdout, ", %d run again on a difference", rerun)
	}
	_, _ = fmt.Fprintln(stdout)
	_, _ = fmt.Fprintf(stdout, "%d projects, %d with differences, %d errors, skipped: %s\n", len(targets), diffs, errs, strings.Join(skipped, ", "))
	if errs > 0 {
		return 2
	}
	if diffs > 0 {
		return 1
	}
	return 0
}

func readConfig(path string) (config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	c := config{skips: map[string]bool{}}
	b, err := io.ReadAll(f)
	if err != nil {
		return config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value, ok := strings.Cut(line, " ")
		if !ok || strings.TrimSpace(value) == "" {
			return config{}, fmt.Errorf("%s:%d: expected 'root <dir>' or 'skip <name>'", path, n+1)
		}
		value = strings.TrimSpace(value)
		switch kind {
		case "root":
			if strings.HasPrefix(value, "~/") {
				home, err := os.UserHomeDir()
				if err != nil {
					return config{}, fmt.Errorf("find home directory: %w", err)
				}
				value = filepath.Join(home, value[2:])
			}
			abs, e := filepath.Abs(value)
			if e != nil {
				return config{}, e
			}
			c.roots = append(c.roots, abs)
		case "skip":
			c.skips[value] = true
		default:
			return config{}, fmt.Errorf("%s:%d: unknown directive %q", path, n+1, kind)
		}
	}
	if len(c.roots) == 0 {
		return config{}, errors.New("config has no root entries")
	}
	return c, nil
}

// findProjects returns the directories holding a .glint.yaml up to three
// levels below each root. A directory it cannot read is passed over: one
// unreadable folder must not hide every other consumer. A linked worktree
// (its .git is a file) is a checkout of another repository's branch and
// would repeat that repository's findings, so it is no consumer.
func findProjects(c config) ([]string, error) {
	found := map[string]bool{}
	for _, root := range c.roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return skipUnreadable(path, root, err)
			}
			if !d.IsDir() || path == root {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			if linkedWorktree(path) {
				return filepath.SkipDir
			}
			if _, e := os.Stat(filepath.Join(path, ".glint.yaml")); e == nil {
				found[path] = true
			}
			if len(strings.Split(rel, string(filepath.Separator))) >= 3 {
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", root, err)
		}
	}
	return slices.Sorted(maps.Keys(found)), nil
}

// linkedWorktree reports whether dir is a linked git worktree: git writes its
// .git as a file pointing at the main repository.
func linkedWorktree(dir string) bool {
	info, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil && info.Mode().IsRegular()
}

// skipUnreadable passes over a directory below the root that cannot be read,
// so one closed folder does not hide the other consumers; the root itself
// failing stops the scan.
func skipUnreadable(path, root string, err error) error {
	if path == root {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "consumers: skip %s: %v\n", path, err)
	return filepath.SkipDir
}

// errUnknownRule is a run refused because the binary does not know a rule
// given with -r.
var errUnknownRule = errors.New("unknown rule")

// checkArgs returns the arguments of a glint run over a project.
func checkArgs(rules, jobs string) []string {
	args := []string{"check", "-o", "json", "--no-color"}
	if rules != "" {
		args = append(args, "-r", rules)
	}
	if jobs != "" {
		args = append(args, "-j", jobs)
	}
	return append(args, "./...")
}

// check runs glint with args over dir; a non-empty cacheDir becomes its GLINT_CACHE_DIR.
func check(bin, dir string, args []string, cacheDir string) ([]output.JSONIssue, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	if cacheDir != "" {
		cmd.Env = append(os.Environ(), "GLINT_CACHE_DIR="+cacheDir)
	}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	var report output.JSONReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		if strings.Contains(stderr.String(), `unknown rule "`) {
			return nil, fmt.Errorf("%w: %s", errUnknownRule, strings.TrimSpace(stderr.String()))
		}
		lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
		if len(lines) > 3 {
			lines = lines[:3]
		}
		return nil, fmt.Errorf("no valid JSON: %w; stderr: %s", e, strings.Join(lines, " | "))
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, fmt.Errorf("run glint: %w", err)
		}
		// A rule panic still prints the findings of the other rules: the
		// report lacks that rule's findings, so the run is an error.
		if panics := panicLines(stderr.String()); panics != "" {
			return nil, fmt.Errorf("rule panic: %s", panics)
		}
	}
	return report.Issues, nil
}

// oldRunCache keeps the findings of the installed glint, one entry per
// project: the same binary over the same tree with the same arguments finds
// the same, and the old runs are about half of what a consumers run costs.
type oldRunCache struct {
	dir, bin, binHash string
}

// oldRunEntry is the cached old run of a project and the key it holds for.
type oldRunEntry struct {
	Key    string             `json:"key"`
	Issues []output.JSONIssue `json:"issues"`
}

func newOldRunCache(dir, bin string) (*oldRunCache, error) {
	h, err := fileHash(bin)
	if err != nil {
		return nil, err
	}
	return &oldRunCache{dir: dir, bin: bin, binHash: h}, nil
}

// errNoWorkTree is a project outside a git work tree: git cannot tell its state.
var errNoWorkTree = errors.New("not in a git work tree")

// check returns the old glint's findings over dir, from the cache when lookup
// is set and the binary, the tree and the arguments are those of the cached
// run; the run it makes replaces the entry. A project
// outside git has no tree state to compare, so its run is not cached; a cache
// that cannot be read or written is reported and the run goes on without it.
func (c *oldRunCache) check(dir string, args []string, lookup bool, stderr io.Writer) (issues []output.JSONIssue, fromCache bool, err error) {
	name := filepath.Base(dir)
	path := filepath.Join(c.dir, cacheFileName(dir))
	key, keyErr := c.key(dir, args)
	if keyErr != nil && !errors.Is(keyErr, errNoWorkTree) {
		_, _ = fmt.Fprintf(stderr, "consumers: %s: old run not cached: %v\n", name, keyErr)
	}
	if keyErr == nil && lookup {
		storedIssues, hit, loadErr := loadOldRun(path, key)
		if loadErr != nil {
			_, _ = fmt.Fprintf(stderr, "consumers: %s: %v\n", name, loadErr)
		}
		if hit {
			return storedIssues, true, nil
		}
	}
	issues, err = check(c.bin, dir, args, "")
	if errors.Is(err, errUnknownRule) {
		// A rule the new build adds: the installed glint has no findings of it.
		issues, err = nil, nil
	}
	if err != nil || keyErr != nil {
		return issues, false, err
	}
	// A tree that changed while glint ran may not be the tree it read.
	after, afterErr := c.key(dir, args)
	if afterErr != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: %s: old run not cached: %v\n", name, afterErr)
	}
	if after == key {
		if storeErr := storeOldRun(path, oldRunEntry{Key: key, Issues: issues}); storeErr != nil {
			_, _ = fmt.Fprintf(stderr, "consumers: %s: %v\n", name, storeErr)
		}
	}
	return issues, false, nil
}

// key is the hash of the old binary, the arguments and the tree state of dir.
func (c *oldRunCache) key(dir string, args []string) (string, error) {
	state, err := treeState(dir)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "glint %s\nargs %q\n%s", c.binHash, args, state))
	return hex.EncodeToString(sum[:]), nil
}

// cacheFileName names the cache entry of a project by its directory.
func cacheFileName(dir string) string {
	sum := sha256.Sum256([]byte(dir))
	return filepath.Base(dir) + "-" + hex.EncodeToString(sum[:8]) + ".json"
}

// loadOldRun returns the cached findings when the entry at path holds for
// key; a project not run before has no entry.
func loadOldRun(path, key string) (issues []output.JSONIssue, hit bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read the old run cache: %w", err)
	}
	var entry oldRunEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false, fmt.Errorf("decode the old run cache %s: %w", path, err)
	}
	return entry.Issues, entry.Key == key, nil
}

// storeOldRun writes the entry through a temporary file and a rename, so a
// reader sees the old entry or the new one, never a part.
func storeOldRun(path string, entry oldRunEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode the old run cache: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create the old run cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("create the old run cache file: %w", err)
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write the old run cache: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("replace the old run cache: %w", err)
	}
	return nil
}

// treeState describes the work tree of dir: HEAD, the status with every
// untracked file, and the content of each changed or untracked file, since
// the status line of a file edited again stays the same. Outside a git work
// tree it returns errNoWorkTree.
func treeState(dir string) (string, error) {
	top, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNoWorkTree, err)
	}
	top = strings.TrimSpace(top)
	head, err := git(dir, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	status, err := git(dir, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "head %s\nstatus %q\n", strings.TrimSpace(head), status)
	entries := strings.Split(status, "\x00")
	for i := 0; i < len(entries); i++ {
		entry := entries[i]
		if len(entry) < 4 {
			continue
		}
		xy, rel := entry[:2], entry[3:]
		if strings.ContainsAny(xy, "RC") {
			i++ // the original path of a rename or copy follows
		}
		h, err := pathHash(filepath.Join(top, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprintf(&b, "file %q %s\n", rel, h)
	}
	return b.String(), nil
}

// git runs git in dir without the optional index lock, so a consumers run
// does not race the project's own git.
func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"--no-optional-locks"}, args...)...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// pathHash describes a changed path: the hash of a file, the target of a
// link, a mark for a directory (a submodule) or for a deleted path.
func pathHash(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "", fmt.Errorf("stat a changed file: %w", err)
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		return "link " + target, err
	case info.IsDir():
		return "dir", nil
	}
	return fileHash(path)
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s to hash: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// panicLines returns the stderr lines of glint that name a rule panic, without
// the stacks, joined for one error line.
func panicLines(stderr string) string {
	var named []string
	for line := range strings.SplitSeq(stderr, "\n") {
		// The closing summary repeats the lines of each panic.
		if strings.Contains(line, `" panicked on `) && !strings.Contains(line, " rule panic(s), ") {
			named = append(named, strings.TrimSpace(line))
		}
	}
	return strings.Join(named, " | ")
}

type issueKey struct {
	rule, file string
	line       int
	message    string
}

func key(i output.JSONIssue) issueKey { return issueKey{i.Rule, i.File, i.Line, i.Message} }
func difference(old, new []output.JSONIssue) (added, removed []output.JSONIssue) {
	counts := map[issueKey]int{}
	for n := range old {
		counts[key(old[n])]++
	}
	for n := range new {
		k := key(new[n])
		if counts[k] > 0 {
			counts[k]--
		} else {
			added = append(added, new[n])
		}
	}
	for n := range old {
		k := key(old[n])
		if counts[k] > 0 {
			removed = append(removed, old[n])
			counts[k]--
		}
	}
	sortIssues(added)
	sortIssues(removed)
	return
}
func sortIssues(a []output.JSONIssue) {
	sort.Slice(a, func(i, j int) bool {
		x, y := a[i], a[j]
		return strings.Join([]string{x.File, fmt.Sprintf("%09d", x.Line), x.Rule, x.Severity, x.Message}, "\x00") < strings.Join([]string{y.File, fmt.Sprintf("%09d", y.Line), y.Rule, y.Severity, y.Message}, "\x00")
	})
}
func printIssue(w io.Writer, sign string, i output.JSONIssue) {
	s := []rune(fmt.Sprintf("%s %s:%d %s %s %s", sign, i.File, i.Line, i.Rule, i.Severity, i.Message))
	if len(s) > 220 {
		s = append(s[:217], '.', '.', '.')
	}
	_, _ = fmt.Fprintln(w, string(s))
}
