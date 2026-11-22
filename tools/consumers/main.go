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
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

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
	remindOnly := fs.Bool("remind", false, "remind whether consumers were compared for this commit")
	hostPathsFile := fs.String("host-paths", "", "write the paths the comparison reads outside this tree to FILE, for worker pc (WORKER_PC_TREES), and compare nothing")
	noMark := fs.Bool("no-mark", false, "write no run marker; print the result line a -via run marks by")
	selfPathsFile := fs.String("self-paths", "", "write the paths glint on this tree reads outside it (the tree with its .git, the user config, tickets_dir) to FILE, for worker pc (WORKER_PC_TREES), and compare nothing")
	via := fs.String("via", "", "run the comparison as graft task TASK, which may go to remote_heavy's host, and mark this commit when it ran on it; with -host-paths, write its paths first")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: consumers [-config PATH] [-old PATH] [-new PATH] [-r rules] [-j N] [-only a,b] [-remind | -host-paths FILE | -self-paths FILE | -via TASK | -no-mark]")
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
	if *remindOnly {
		cwd, err := os.Getwd()
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "no consumers comparison for this commit (current directory unknown: %v); run graft consumers before the install\n", err)
		} else {
			remind(cwd, stdout)
		}
		return 0
	}
	if *selfPathsFile != "" {
		return writeSelfPaths(*selfPathsFile, stderr)
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
	targets, err := selectTargets(cfg, *only)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "consumers:", err)
		return 2
	}
	if *hostPathsFile != "" {
		if code := writeConsumerHostPaths(*hostPathsFile, targets, *cfgPath, oldAbs, newAbs, stderr); code != 0 || *via == "" {
			return code
		}
	}
	if _, err := os.Stat(oldAbs); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: old binary %s: %v\n", oldAbs, err)
		return 2
	}
	if _, err := os.Stat(newAbs); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: new binary %s: %v\n", newAbs, err)
		return 2
	}
	markerState := "full"
	if *rules != "" || *only != "" {
		markerState = "partial"
	}
	if *via != "" {
		return runVia(*via, passedFlags(fs), newAbs, stdout, stderr)
	}
	return compareAll(cfg, targets, oldAbs, newAbs, *rules, *jobs, markerState, *noMark, stdout, stderr)
}

// writeConsumerHostPaths writes the host paths of a comparison of targets with
// these binaries and config, run from the tree in the current directory.
func writeConsumerHostPaths(file string, targets []string, cfgPath, oldAbs, newAbs string, stderr io.Writer) int {
	cwd, err := os.Getwd()
	var paths []string
	if err == nil {
		paths, err = hostPaths(targets, cfgPath, oldAbs, newAbs, gitToplevel(cwd))
	}
	if err == nil {
		err = writeHostPaths(file, "the consumers comparison", paths)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "consumers:", err)
		return 2
	}
	if home, err := os.UserHomeDir(); err == nil {
		warnConfigDir(home, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "consumers: %d host paths in %s\n", len(paths), file)
	return 0
}

// selectTargets are the consumers below the roots of cfg but the skipped
// ones, only those named in only when it is set.
func selectTargets(cfg config, only string) ([]string, error) {
	projects, err := findProjects(cfg)
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	if only != "" {
		for name := range strings.SplitSeq(only, ",") {
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
	// No consumer to compare is no evidence that nothing changed: a host
	// without the consumer copies, or a name in -only that is not there,
	// would otherwise pass as "no differences".
	for _, name := range slices.Sorted(maps.Keys(selected)) {
		if !slices.ContainsFunc(targets, func(p string) bool { return filepath.Base(p) == name }) {
			return nil, fmt.Errorf("-only %s: no such consumer below the roots", name)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no consumer projects below the roots %s", strings.Join(cfg.roots, ", "))
	}
	return targets, nil
}

// compareAll compares the old and the new glint on every target and either
// marks the commit (when HEAD, the tree and the new glint did not move) or,
// with noMark, ends with the result line a -via run marks by.
func compareAll(cfg config, targets []string, oldAbs, newAbs, rules, jobs, markerState string, noMark bool, stdout, stderr io.Writer) int {
	newSum, err := fileSHA256(newAbs)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: new binary: %v\n", err)
		return 2
	}
	var sent runSnapshot
	if !noMark {
		sent = snapshotHere(newAbs)
	}
	oldRuleNames, oldRulesErr := listRuleNames(oldAbs)

	userCache, err := os.UserCacheDir()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: find user cache directory: %v\n", err)
		return 2
	}
	// A glint run prunes the result caches of other builds, so the new build
	// runs in a directory of its own and leaves the installed glint's caches;
	// the old one fills a fresh directory per project for the cached run.
	cacheBase := filepath.Join(userCache, "glint")
	newCache := filepath.Join(cacheBase, "consumers-new")

	diffs, errs, slowerByProject, newestRule := compareTargets(targets, oldAbs, newAbs, rules, jobs, newCache, cacheBase, oldRuleNames, stdout, stderr)
	printTimingComparison(stdout, slowerByProject, newestRule, oldRulesErr)
	skipped := slices.Sorted(maps.Keys(cfg.skips))
	_, _ = fmt.Fprintf(stdout, "%d projects, %d with differences, %d errors, skipped: %s\n", len(targets), diffs, errs, strings.Join(skipped, ", "))
	if errs > 0 {
		return 2
	}
	if noMark {
		_, _ = fmt.Fprintf(stdout, "%s%s %s\n", resultPrefix, markerState, newSum)
	} else {
		sent.mark(newAbs, markerState, newSum, stderr)
	}
	if diffs > 0 {
		return 1
	}
	return 0
}

func compareTargets(targets []string, oldAbs, newAbs, rules, jobs, newCache, cacheBase string, oldRuleNames map[string]bool, stdout, stderr io.Writer) (int, int, []projectTimings, slowRule) {
	diffs, errs := 0, 0
	var slowerByProject []projectTimings
	var newestRule slowRule
	for _, p := range targets {
		name := filepath.Base(p)
		oldIssues, oldTimes, newIssues, newTimes, cacheErrs, err := compareProject(p, oldAbs, newAbs, rules, jobs, newCache, cacheBase, stdout, stderr)
		errs += cacheErrs
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %s\n", name, err)
			errs++
			continue
		}
		slower, slowestNew := compareRuleTimings(oldTimes, oldRuleNames, newTimes)
		if len(slower) > 0 {
			ruleNames := make([]string, 0, len(slower))
			for _, rule := range slower {
				ruleNames = append(ruleNames, rule.name)
			}
			sort.Strings(ruleNames)
			confirmationRules := strings.Join(ruleNames, ",")
			_, confirmationNewTimes, confirmationNewErr := check(newAbs, p, confirmationRules, jobs, newCache)
			_, confirmationOldTimes, confirmationOldErr := check(oldAbs, p, confirmationRules, jobs, "")
			if confirmationNewErr != nil {
				_, _ = fmt.Fprintf(stderr, "%s (confirmation new): %s\n", name, confirmationNewErr)
				errs++
			} else if confirmationOldErr != nil {
				_, _ = fmt.Fprintf(stderr, "%s (confirmation old): %s\n", name, confirmationOldErr)
				errs++
			} else {
				confirmed, _ := compareRuleTimings(confirmationOldTimes, oldRuleNames, confirmationNewTimes)
				confirmedByName := make(map[string]slowRule, len(confirmed))
				for _, rule := range confirmed {
					confirmedByName[rule.name] = rule
				}
				var reported []slowRule
				for _, rule := range slower {
					if confirmation, ok := confirmedByName[rule.name]; ok {
						rule.confirmationPrevious = confirmation.previous
						rule.confirmationDuration = confirmation.duration
						reported = append(reported, rule)
					}
				}
				if len(reported) > 0 {
					slowerByProject = append(slowerByProject, projectTimings{project: name, rules: reported})
				}
			}
		}
		if slowestNew.duration > newestRule.duration || slowestNew.duration == newestRule.duration && slowestNew.name < newestRule.name {
			slowestNew.project = name
			newestRule = slowestNew
		}
		added, removed := difference(oldIssues, newIssues)
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
	return diffs, errs, slowerByProject, newestRule
}

// compareProject runs the old glint on the project with a fresh result cache
// of its own, the new one without a cache, and the new one again on the old
// one's cache: the cache a release finds is the old version's, and a key that
// misses an input shows as findings that differ from the run without it. The
// old run fills an empty cache, so its findings are those of a run without
// one; the cache is made here, so the cached run never depends on what this
// machine's own cache holds. cacheErrs counts the cached run's failures.
func compareProject(p, oldAbs, newAbs, rules, jobs, newCache, cacheBase string, stdout, stderr io.Writer) (oldIssues []output.JSONIssue, oldTimes map[string]time.Duration, newIssues []output.JSONIssue, newTimes map[string]time.Duration, cacheErrs int, err error) {
	name := filepath.Base(p)
	if err := os.MkdirAll(cacheBase, 0o700); err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("create result cache directory: %w", err)
	}
	// Beside the user cache, on its disk: /tmp is memory, and a consumer
	// cache runs to hundreds of megabytes.
	oldCache, err := os.MkdirTemp(cacheBase, "consumers-old-")
	if err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("create the old glint's result cache: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(oldCache); removeErr != nil {
			_, _ = fmt.Fprintf(stderr, "%s (cache cleanup): %s\n", name, removeErr)
			cacheErrs++
		}
	}()
	oldIssues, oldTimes, oldErr := checkWithCache(oldAbs, p, rules, jobs, oldCache, true)
	oldKnowsRules := true
	if errors.Is(oldErr, errUnknownRule) {
		// A rule the new build adds: the installed glint has no findings of it.
		oldIssues, oldErr, oldKnowsRules = nil, nil, false
	}
	if oldErr != nil {
		return nil, nil, nil, nil, 0, oldErr
	}
	newIssues, newTimes, newErr := check(newAbs, p, rules, jobs, newCache)
	if newErr != nil {
		return nil, nil, nil, nil, 0, newErr
	}
	if !oldKnowsRules {
		_, _ = fmt.Fprintf(stdout, "%s: cached run skipped (the old glint does not know the rules)\n", name)
		return oldIssues, oldTimes, newIssues, newTimes, 0, nil
	}
	cacheFiles, err := countFiles(oldCache)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s (cached new): %s\n", name, err)
		return oldIssues, oldTimes, newIssues, newTimes, 1, nil
	}
	if cacheFiles == 0 {
		_, _ = fmt.Fprintf(stderr, "%s (cached new): the old glint wrote no result cache, so a cached run would analyze everything\n", name)
		return oldIssues, oldTimes, newIssues, newTimes, 1, nil
	}
	fromCache, cachedReport, cachedErr := runGlint(newAbs, p, rules, jobs, oldCache, true)
	if cachedErr != nil {
		_, _ = fmt.Fprintf(stderr, "%s (cached new): %s\n", name, cachedErr)
		return oldIssues, oldTimes, newIssues, newTimes, 1, nil
	}
	reuse, err := parseCacheReuse(cachedReport)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s (cached new): %s\n", name, err)
		return oldIssues, oldTimes, newIssues, newTimes, 1, nil
	}
	printCacheReuse(stdout, name, reuse)
	added, removed := difference(newIssues, fromCache)
	if len(added)+len(removed) > 0 {
		_, _ = fmt.Fprintf(stdout, "== %s: cached findings differ (+%d -%d)\n", p, len(added), len(removed))
		for i := 0; i < min(3, len(added)); i++ {
			printIssue(stdout, "+", added[i])
		}
		for i := 0; i < min(3, len(removed)); i++ {
			printIssue(stdout, "-", removed[i])
		}
		cacheErrs++
	}
	return oldIssues, oldTimes, newIssues, newTimes, cacheErrs, nil
}

// cacheReuse is what a run took from the result cache, summed over the roots
// glint reports: its --timing says "result cache <root>: N of M files
// unchanged, project rules X cached, Y rerun" for each.
type cacheReuse struct {
	roots, files, analyzed, rulesCached, rulesRerun int
}

// reuseLine matches a reuse line of glint --timing; the root is a path, so
// the counts follow its last ": ".
var reuseLine = regexp.MustCompile(`^result cache .*: (\d+) of (\d+) files unchanged, project rules (\d+) cached, (\d+) rerun$`)

func parseCacheReuse(report string) (cacheReuse, error) {
	var r cacheReuse
	for line := range strings.SplitSeq(report, "\n") {
		m := reuseLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		var counts [4]int
		for i := range counts {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				return cacheReuse{}, fmt.Errorf("read %q: %w", line, err)
			}
			counts[i] = n
		}
		r.roots++
		r.files += counts[0]
		r.analyzed += counts[1]
		r.rulesCached += counts[2]
		r.rulesRerun += counts[3]
	}
	return r, nil
}

// printCacheReuse says what the cached run took from the old glint's cache.
// Nothing taken makes the comparison blind, as equal findings then prove
// nothing about the cache; that is a warning, not an error: a release that
// changes the core of the key misses the cache by design.
func printCacheReuse(w io.Writer, name string, r cacheReuse) {
	if r.roots == 0 {
		_, _ = fmt.Fprintf(w, "%s: cache comparison blind: the cached run reported no result cache\n", name)
		return
	}
	_, _ = fmt.Fprintf(w, "%s: cached run: %d of %d files unchanged, project rules %d cached, %d rerun\n", name, r.files, r.analyzed, r.rulesCached, r.rulesRerun)
	if r.files == 0 && r.rulesCached == 0 {
		_, _ = fmt.Fprintf(w, "%s: cache comparison blind: nothing reused\n", name)
	}
}

// countFiles counts the regular files in dir.
func countFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read result cache directory: %w", err)
	}
	n := 0
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			n++
		}
	}
	return n, nil
}

// resultPrefix starts the line a -no-mark comparison ends with when every
// project compared: the marker state and the SHA-256 of the new glint it ran.
// A -via run reads it from the comparison's output, which is all that comes
// back from remote_heavy's host.
const resultPrefix = "consumers-result: "

// runSnapshot is the commit and the new glint a comparison is sent with: the
// run marker is written for them only, and only when nothing of them moved
// while it ran.
type runSnapshot struct {
	dir, head, sum string
	clean          bool
	err            error
}

// snapshotHere takes the snapshot of the current directory and newBin.
func snapshotHere(newBin string) runSnapshot {
	dir, err := os.Getwd()
	if err != nil {
		return runSnapshot{err: fmt.Errorf("find current directory: %w", err)}
	}
	return takeSnapshot(dir, newBin)
}

func takeSnapshot(dir, newBin string) runSnapshot {
	s := runSnapshot{dir: dir}
	if s.head, s.err = consumerGitValue(dir, "HEAD"); s.err != nil {
		return s
	}
	status := exec.Command("git", "status", "--porcelain")
	status.Dir = dir
	out, err := status.Output()
	if err != nil {
		s.err = fmt.Errorf("check worktree: %w", err)
		return s
	}
	s.clean = len(out) == 0
	s.sum, s.err = fileSHA256(newBin)
	return s
}

// mark writes the run marker of the snapshot's commit when the comparison ran
// the new glint the snapshot holds (ranSum) and HEAD, the clean tree and that
// glint are the same now as when it was sent; otherwise it says why not.
func (s runSnapshot) mark(newBin, state, ranSum string, stderr io.Writer) {
	why := s.markRefusal(newBin, ranSum)
	if why != "" {
		_, _ = fmt.Fprintf(stderr, "consumers: no run marker: %s\n", why)
		return
	}
	if err := writeConsumerMarker(s.dir, state); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: write run marker: %v\n", err)
	}
}

func (s runSnapshot) markRefusal(newBin, ranSum string) string {
	if s.err != nil {
		return s.err.Error()
	}
	if !s.clean {
		return "the tree had changes when the comparison started"
	}
	if ranSum != s.sum {
		return fmt.Sprintf("the comparison ran glint %s, not %s %s", short(ranSum), newBin, short(s.sum))
	}
	now := takeSnapshot(s.dir, newBin)
	switch {
	case now.err != nil:
		return now.err.Error()
	case now.head != s.head:
		return fmt.Sprintf("HEAD moved from %s to %s during the comparison", short(s.head), short(now.head))
	case !now.clean:
		return "the tree changed during the comparison"
	case now.sum != s.sum:
		return fmt.Sprintf("%s changed during the comparison", newBin)
	}
	return ""
}

func short(id string) string { return id[:min(12, len(id))] }

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// passedFlags are the flags given to this run but -via, as -name=value, for
// the comparison task's {args}.
func passedFlags(fs *flag.FlagSet) []string {
	var args []string
	fs.Visit(func(f *flag.Flag) {
		if f.Name != "via" && f.Name != "host-paths" {
			args = append(args, "-"+f.Name+"="+f.Value.String())
		}
	})
	return args
}

// runVia runs graft task with args, the comparison with -no-mark, wherever
// graft places it, and marks this commit by the result line it prints: the
// host has no .git of this tree, so the marker is written here, for the
// commit and the new glint taken before it was sent. graft exits 1 for any
// failed step, so the exit status is read back from the result line: present,
// the comparison finished and a failure means differences (1); missing, it
// did not finish (2).
func runVia(task string, args []string, newBin string, stdout, stderr io.Writer) int {
	sent := snapshotHere(newBin)
	argv := []string{task}
	if len(args) > 0 {
		argv = append(append(argv, "--"), args...)
	}
	cmd := exec.Command("graft", argv...)
	var out bytes.Buffer
	cmd.Stdout = io.MultiWriter(stdout, &out)
	cmd.Stderr = stderr
	runErr := cmd.Run()
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		_, _ = fmt.Fprintf(stderr, "consumers: run graft %s: %v\n", task, runErr)
		return 2
	}
	state, ranSum, ok := resultLine(out.String())
	if !ok {
		_, _ = fmt.Fprintf(stderr, "consumers: graft %s printed no result line, so the comparison did not finish; no run marker\n", task)
		return 2
	}
	sent.mark(newBin, state, ranSum, stderr)
	if runErr == nil {
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "consumers: graft %s finished the comparison and failed (%v): the glints differ\n", task, runErr)
	return 1
}

// resultLine is the state and the glint hash of the last result line in out.
func resultLine(out string) (state, sum string, ok bool) {
	for line := range strings.SplitSeq(out, "\n") {
		rest, found := strings.CutPrefix(line, resultPrefix)
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 2 && (fields[0] == "full" || fields[0] == "partial") {
			state, sum, ok = fields[0], fields[1], true
		}
	}
	return state, sum, ok
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
		kind, value := "root", line
		if directive, argument, ok := strings.Cut(line, " "); directive == "root" || directive == "skip" {
			if !ok || strings.TrimSpace(argument) == "" {
				return config{}, fmt.Errorf("%s:%d: expected 'root <dir>' or 'skip <name>'", path, n+1)
			}
			kind, value = directive, strings.TrimSpace(argument)
		}
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

// check runs glint over dir; a non-empty cacheDir becomes its GLINT_CACHE_DIR.
func check(bin, dir, rules, jobs, cacheDir string) ([]output.JSONIssue, map[string]time.Duration, error) {
	return checkWithCache(bin, dir, rules, jobs, cacheDir, false)
}

func checkWithCache(bin, dir, rules, jobs, cacheDir string, useCache bool) ([]output.JSONIssue, map[string]time.Duration, error) {
	issues, report, err := runGlint(bin, dir, rules, jobs, cacheDir, useCache)
	if err != nil {
		return nil, nil, err
	}
	return issues, parseRuleTimings(report), nil
}

// runGlint runs glint check --timing over dir and returns its findings and its
// stderr, where the timing report is.
func runGlint(bin, dir, rules, jobs, cacheDir string, useCache bool) ([]output.JSONIssue, string, error) {
	args := []string{"check", "-o", "json", "--no-color", "--timing"}
	if !useCache {
		args = append(args, "--no-cache")
	}
	if rules != "" {
		args = append(args, "-r", rules)
	}
	if jobs != "" {
		args = append(args, "-j", jobs)
	}
	args = append(args, "./...")
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
			return nil, "", fmt.Errorf("%w: %s", errUnknownRule, strings.TrimSpace(stderr.String()))
		}
		lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
		if len(lines) > 3 {
			lines = lines[:3]
		}
		return nil, "", fmt.Errorf("no valid JSON: %w; stderr: %s", e, strings.Join(lines, " | "))
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, "", fmt.Errorf("run glint: %w", err)
		}
		// A rule panic still prints the findings of the other rules: the
		// report lacks that rule's findings, so the run is an error.
		if panics := panicLines(stderr.String()); panics != "" {
			return nil, "", fmt.Errorf("rule panic: %s", panics)
		}
	}
	return report.Issues, stderr.String(), nil
}

type slowRule struct {
	name                 string
	project              string
	duration             time.Duration
	previous             time.Duration
	delta                time.Duration
	confirmationDuration time.Duration
	confirmationPrevious time.Duration
}

type projectTimings struct {
	project string
	rules   []slowRule
}

func parseRuleTimings(report string) map[string]time.Duration {
	got := make(map[string]time.Duration)
	inRules := false
	for line := range strings.SplitSeq(report, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "RULE" && fields[1] == "TOTAL" {
			inRules = true
			continue
		}
		if !inRules {
			continue
		}
		if len(fields) < 2 || strings.HasPrefix(line, "  (") || strings.HasPrefix(line, "  IN FLIGHT") {
			if strings.HasPrefix(line, "  IN FLIGHT") {
				inRules = false
			}
			continue
		}
		duration, err := time.ParseDuration(fields[1])
		if err == nil {
			got[fields[0]] = duration
		}
	}
	return got
}

func listRuleNames(bin string) (map[string]bool, error) {
	cmd := exec.Command(bin, "rules")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run %s rules: %w", bin, err)
	}
	got, err := parseRuleNames(string(out))
	if err != nil {
		return nil, fmt.Errorf("%s rules: %w", bin, err)
	}
	return got, nil
}

func parseRuleNames(report string) (map[string]bool, error) {
	got := make(map[string]bool)
	for line := range strings.SplitSeq(report, "\n") {
		if len(line) == 0 || line[0] != ' ' && line[0] != '\t' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			got[fields[0]] = true
		}
	}
	if len(got) == 0 {
		return nil, errors.New("returned no rule names")
	}
	return got, nil
}

func compareRuleTimings(old map[string]time.Duration, oldRuleNames map[string]bool, current map[string]time.Duration) ([]slowRule, slowRule) {
	var slower []slowRule
	var slowestNew slowRule
	for name, duration := range current {
		if duration < time.Millisecond {
			continue
		}
		previous, exists := old[name]
		if !exists {
			if oldRuleNames != nil && !oldRuleNames[name] && (duration > slowestNew.duration || duration == slowestNew.duration && name < slowestNew.name) {
				slowestNew = slowRule{name: name, duration: duration}
			}
			continue
		}
		if previous < time.Millisecond {
			continue
		}
		delta := duration - previous
		if delta >= 300*time.Millisecond && delta*2 >= previous {
			slower = append(slower, slowRule{name: name, duration: duration, previous: previous, delta: delta})
		}
	}
	sort.Slice(slower, func(i, j int) bool {
		if slower[i].duration != slower[j].duration {
			return slower[i].duration > slower[j].duration
		}
		return slower[i].name < slower[j].name
	})
	return slower, slowestNew
}

func printTimingComparison(w io.Writer, projects []projectTimings, slowestNew slowRule, oldRulesErr error) {
	_, _ = fmt.Fprintln(w, "slower rules (≥50% and ≥300 ms)")
	for _, project := range projects {
		for _, rule := range project.rules {
			percent := rule.delta * 100 / rule.previous
			confirmationDelta := rule.confirmationDuration - rule.confirmationPrevious
			confirmationPercent := confirmationDelta * 100 / rule.confirmationPrevious
			_, _ = fmt.Fprintf(w, "  %s: %s — %s -> %s (+%s, +%d%%); confirm %s -> %s (+%s, +%d%%)\n", project.project, rule.name,
				rule.previous.Round(time.Millisecond), rule.duration.Round(time.Millisecond), rule.delta.Round(time.Millisecond), percent,
				rule.confirmationPrevious.Round(time.Millisecond), rule.confirmationDuration.Round(time.Millisecond), confirmationDelta.Round(time.Millisecond), confirmationPercent)
		}
	}
	if oldRulesErr != nil {
		_, _ = fmt.Fprintf(w, "slowest new rule: unavailable (could not get old rules: %v)\n", oldRulesErr)
		return
	}
	if slowestNew.name == "" {
		_, _ = fmt.Fprintln(w, "slowest new rule: none")
		return
	}
	_, _ = fmt.Fprintf(w, "slowest new rule: %s: %s — %s\n", slowestNew.project, slowestNew.name, slowestNew.duration.Round(time.Millisecond))
}

func consumerGitValue(dir, arg string) (string, error) {
	cmd := exec.Command("git", "rev-parse", arg)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse %s: %w", arg, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func consumerMarkerPath(dir string) (string, error) {
	tree, err := consumerGitValue(dir, "HEAD^{tree}")
	if err != nil {
		return "", fmt.Errorf("resolve HEAD tree: %w", err)
	}
	commonDir, err := consumerGitValue(dir, "--git-common-dir")
	if err != nil {
		return "", fmt.Errorf("resolve common git directory: %w", err)
	}
	if !filepath.IsAbs(commonDir) {
		commonDir = filepath.Join(dir, commonDir)
	}
	return filepath.Join(commonDir, "glint-consumers", tree), nil
}

func writeConsumerMarker(dir, state string) error {
	status := exec.Command("git", "status", "--porcelain")
	status.Dir = dir
	if out, err := status.Output(); err != nil {
		return fmt.Errorf("check worktree: %w", err)
	} else if len(out) != 0 {
		return nil
	}
	path, err := consumerMarkerPath(dir)
	if err != nil {
		return err
	}
	if state == "partial" {
		current, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(current)) == "full" {
			return nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read existing run marker: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create marker directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(state+"\n"), 0o600); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	return nil
}

func remind(dir string, w io.Writer) {
	path, err := consumerMarkerPath(dir)
	if err != nil {
		_, _ = fmt.Fprintf(w, "no consumers comparison for this commit (cannot check the mark: %v); run graft consumers before the install\n", err)
		return
	}
	state, err := os.ReadFile(path)
	if err != nil { //nolint:silent-error-handling // A missing marker is the normal state before a run; the reminder reports it.
		if errors.Is(err, os.ErrNotExist) {
			printNoComparison(w)
		} else {
			_, _ = fmt.Fprintf(w, "no consumers comparison for this commit (cannot read the mark: %v); run graft consumers before the install\n", err)
		}
		return
	}
	switch strings.TrimSpace(string(state)) {
	case "full":
	case "partial":
		_, _ = fmt.Fprintln(w, "the consumers comparison for this commit was partial (-r or -only); run graft consumers without them before the install")
	default:
		printNoComparison(w)
	}
}

func printNoComparison(w io.Writer) {
	_, _ = fmt.Fprintln(w, "no consumers comparison for this commit; run graft consumers before the install")
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
