// Command consumers compares glint findings across configured project roots.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
		fmt.Fprintf(stderr, "consumers: find home directory: %v\n", err)
		return 2
	}
	cfgPath := fs.String("config", filepath.Join(home, ".config", "glint", "consumers.txt"), "consumer roots config")
	oldPath := fs.String("old", filepath.Join(home, "bin", "glint"), "installed glint binary")
	newPath := fs.String("new", "bin/glint", "new glint binary")
	rules := fs.String("r", "", "comma-separated rules")
	jobs := fs.String("j", "", "glint parallelism")
	only := fs.String("only", "", "comma-separated project names")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: consumers [-config PATH] [-old PATH] [-new PATH] [-r rules] [-j N] [-only a,b]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "consumers: parse flags: %v\n", err)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "consumers: unexpected arguments")
		return 2
	}
	oldAbs, err := filepath.Abs(*oldPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	newAbs, err := filepath.Abs(*newPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	cfg, err := readConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "consumers:", err)
		return 2
	}
	projects, err := findProjects(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "consumers:", err)
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
		fmt.Fprintf(stderr, "consumers: old binary %s: %v\n", oldAbs, err)
		return 2
	}
	if _, err := os.Stat(newAbs); err != nil {
		fmt.Fprintf(stderr, "consumers: new binary %s: %v\n", newAbs, err)
		return 2
	}

	diffs, errs := 0, 0
	for _, p := range targets {
		name := filepath.Base(p)
		oldIssues, oldErr := check(oldAbs, p, *rules, *jobs)
		if oldErr != nil {
			fmt.Fprintf(stderr, "%s: %s\n", name, oldErr)
			errs++
			continue
		}
		newIssues, newErr := check(newAbs, p, *rules, *jobs)
		if newErr != nil {
			fmt.Fprintf(stderr, "%s: %s\n", name, newErr)
			errs++
			continue
		}
		added, removed := difference(oldIssues, newIssues)
		if len(added)+len(removed) == 0 {
			continue
		}
		diffs++
		fmt.Fprintf(stdout, "== %s: +%d -%d\n", p, len(added), len(removed))
		for i := range added {
			printIssue(stdout, "+", added[i])
		}
		for i := range removed {
			printIssue(stdout, "-", removed[i])
		}
	}
	skipped := make([]string, 0, len(cfg.skips))
	for name := range cfg.skips {
		skipped = append(skipped, name)
	}
	sort.Strings(skipped)
	fmt.Fprintf(stdout, "%d projects, %d with differences, %d errors, skipped: %s\n", len(targets), diffs, errs, strings.Join(skipped, ", "))
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
	defer f.Close()
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
// unreadable folder must not hide every other consumer.
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
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// skipUnreadable passes over a directory below the root that cannot be read,
// so one closed folder does not hide the other consumers; the root itself
// failing stops the scan.
func skipUnreadable(path, root string, err error) error {
	if path == root {
		return err
	}
	fmt.Fprintf(os.Stderr, "consumers: skip %s: %v\n", path, err)
	return filepath.SkipDir
}

func check(bin, dir, rules, jobs string) ([]output.JSONIssue, error) {
	args := []string{"check", "-o", "json", "--no-color"}
	if rules != "" {
		args = append(args, "-r", rules)
	}
	if jobs != "" {
		args = append(args, "-j", jobs)
	}
	args = append(args, "./...")
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	var report output.JSONReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
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
	}
	return report.Issues, nil
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
	fmt.Fprintln(w, string(s))
}
