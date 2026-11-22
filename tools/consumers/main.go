// Command consumers compares glint findings across configured project roots.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
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
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: consumers [-config PATH] [-old PATH] [-new PATH] [-r rules] [-j N] [-only a,b] [-remind]")
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
	// No consumer to compare is no evidence that nothing changed: a host
	// without the consumer copies, or a name in -only that is not there,
	// would otherwise pass as "no differences".
	for name := range selected {
		if !slices.ContainsFunc(targets, func(p string) bool { return filepath.Base(p) == name }) {
			_, _ = fmt.Fprintf(stderr, "consumers: -only %s: no such consumer below the roots\n", name)
			return 2
		}
	}
	if len(targets) == 0 {
		_, _ = fmt.Fprintf(stderr, "consumers: no consumer projects below the roots %s\n", strings.Join(cfg.roots, ", "))
		return 2
	}
	if _, err := os.Stat(oldAbs); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: old binary %s: %v\n", oldAbs, err)
		return 2
	}
	if _, err := os.Stat(newAbs); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: new binary %s: %v\n", newAbs, err)
		return 2
	}
	oldRuleNames, oldRulesErr := listRuleNames(oldAbs)

	userCache, err := os.UserCacheDir()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: find user cache directory: %v\n", err)
		return 2
	}
	// A glint run prunes the result caches of other builds, so the new build
	// runs in a directory of its own and leaves the installed glint's caches.
	newCache := filepath.Join(userCache, "glint", "consumers-new")

	diffs, errs, slowerByProject, newestRule := compareTargets(targets, oldAbs, newAbs, *rules, *jobs, newCache, oldRuleNames, stdout, stderr)
	printTimingComparison(stdout, slowerByProject, newestRule, oldRulesErr)
	skipped := slices.Sorted(maps.Keys(cfg.skips))
	_, _ = fmt.Fprintf(stdout, "%d projects, %d with differences, %d errors, skipped: %s\n", len(targets), diffs, errs, strings.Join(skipped, ", "))
	if errs > 0 {
		return 2
	}
	markerState := "full"
	if *rules != "" || *only != "" {
		markerState = "partial"
	}
	markCurrentRun(markerState, stderr)
	if diffs > 0 {
		return 1
	}
	return 0
}

func compareTargets(targets []string, oldAbs, newAbs, rules, jobs, newCache string, oldRuleNames map[string]bool, stdout, stderr io.Writer) (int, int, []projectTimings, slowRule) {
	diffs, errs := 0, 0
	var slowerByProject []projectTimings
	var newestRule slowRule
	for _, p := range targets {
		name := filepath.Base(p)
		oldIssues, oldTimes, oldErr := check(oldAbs, p, rules, jobs, "")
		if errors.Is(oldErr, errUnknownRule) {
			// A rule the new build adds: the installed glint has no findings of it.
			oldIssues, oldErr = nil, nil
		}
		if oldErr != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %s\n", name, oldErr)
			errs++
			continue
		}
		newIssues, newTimes, newErr := check(newAbs, p, rules, jobs, newCache)
		if newErr != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %s\n", name, newErr)
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

func markCurrentRun(state string, stderr io.Writer) {
	cwd, err := os.Getwd()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: find current directory for run marker: %v\n", err)
		return
	}
	if err := writeConsumerMarker(cwd, state); err != nil {
		_, _ = fmt.Fprintf(stderr, "consumers: write run marker: %v\n", err)
	}
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
	args := []string{"check", "-o", "json", "--no-color", "--timing", "--no-cache"}
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
			return nil, nil, fmt.Errorf("%w: %s", errUnknownRule, strings.TrimSpace(stderr.String()))
		}
		lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
		if len(lines) > 3 {
			lines = lines[:3]
		}
		return nil, nil, fmt.Errorf("no valid JSON: %w; stderr: %s", e, strings.Join(lines, " | "))
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, nil, fmt.Errorf("run glint: %w", err)
		}
		// A rule panic still prints the findings of the other rules: the
		// report lacks that rule's findings, so the run is an error.
		if panics := panicLines(stderr.String()); panics != "" {
			return nil, nil, fmt.Errorf("rule panic: %s", panics)
		}
	}
	return report.Issues, parseRuleTimings(stderr.String()), nil
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
