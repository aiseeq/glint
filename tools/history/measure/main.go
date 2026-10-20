// Command measure builds a quality curve over a repository's git history
// using glint.
//
// Method (one instrument for the whole history):
//   - take a slice every N days (default 14) from the first commit to HEAD,
//     following first-parent;
//   - for each slice: check out a detached worktree, remove the project
//     .glint.yaml (full default rule set, no project exclusions), run
//     glint check --tolerate-broken-packages -o json;
//   - count only findings in non-test .go files; normalize per 1000
//     non-test Go lines (vendor/ and node_modules/ excluded).
//
// If a rule hard-crashes on a historical slice (old trees can break
// type-dependent rules), it is disabled for that slice only and recorded
// in the output as disabled_rules.
//
// Output: JSONL, one record per slice with aggregate numbers only.
//
// Usage: measure REPO OUT.jsonl [--interval 14] [--glint PATH]
//
// Plot per_kloc_crit_high over date (tools/history/plot) to get the
// heavy-findings curve.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aiseeq/glint/pkg/output"
	"github.com/aiseeq/glint/tools/history/internal/hist"
)

var severities = []string{"critical", "high", "medium", "low"}

// ruleFailure finds the rule a crashed glint run names.
var ruleFailure = regexp.MustCompile(`rule "([a-z0-9-]+)"`)

// maxAttempts bounds the runs of one slice: each failed run disables the
// rule it names and tries again.
const maxAttempts = 6

func main() {
	fs := flag.NewFlagSet("measure", flag.ExitOnError)
	interval := fs.Int("interval", 14, "days between slices")
	glint := fs.String("glint", "glint", "glint binary")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: measure REPO OUT.jsonl [--interval 14] [--glint PATH]")
		fs.PrintDefaults()
	}
	args, err := hist.Parse(fs, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(args) != 2 || *interval <= 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := measure(args[0], args[1], *interval, *glint, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "measure:", err)
		os.Exit(1)
	}
}

func measure(repo, outPath string, interval int, glint string, progress io.Writer) error {
	slices, err := sliceCommits(repo, interval)
	if err != nil {
		return err
	}
	fmt.Fprintf(progress, "%d slices\n", len(slices))
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	for n, s := range slices {
		rec, err := analyzeSlice(repo, s.hash, glint)
		if err != nil {
			return fmt.Errorf("slice %s: %w", s.hash, err)
		}
		rec.Date = s.date.Format(time.DateOnly)
		if err := hist.WriteLine(out, rec); err != nil {
			return err
		}
		total, critHigh := "-", "-"
		if rec.metrics != nil {
			total = strconv.Itoa(rec.TotalGo)
			if rec.PerKlocCritHigh != nil {
				critHigh = strconv.FormatFloat(*rec.PerKlocCritHigh, 'f', -1, 64)
			}
		}
		fmt.Fprintf(progress, "[%d/%d] %s sloc=%d total=%s c+h/kloc=%s\n", n+1, len(slices), rec.Date, rec.Sloc, total, critHigh)
	}
	return out.Close()
}

type commit struct {
	hash string
	date time.Time
}

// sliceCommits returns the last first-parent commit before each slice
// date, one slice every interval days from the first commit, and HEAD.
func sliceCommits(repo string, interval int) ([]commit, error) {
	log, err := hist.Git(repo, "log", "--first-parent", "--format=%H %cI", "--reverse")
	if err != nil {
		return nil, err
	}
	var commits []commit
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		if line == "" {
			continue
		}
		hash, iso, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("git log line %q: no date", line)
		}
		date, err := time.Parse(time.RFC3339, iso)
		if err != nil {
			return nil, fmt.Errorf("git log line %q: %w", line, err)
		}
		commits = append(commits, commit{hash, date})
	}
	if len(commits) == 0 {
		return nil, fmt.Errorf("%s: no commits", repo)
	}
	step := time.Duration(interval) * 24 * time.Hour
	start, end := commits[0].date, commits[len(commits)-1].date
	var slices []commit
	for cur := start.Add(step); !cur.After(end.Add(step)); cur = cur.Add(step) {
		// The log is in the order of the history, and a commit date can
		// go back in it: the slice ends at the first commit after cur.
		best := commits[0]
		for _, c := range commits {
			if c.date.After(cur) {
				break
			}
			best = c
		}
		if len(slices) == 0 || slices[len(slices)-1].hash != best.hash {
			slices = append(slices, best)
		}
	}
	if head := commits[len(commits)-1]; len(slices) == 0 || slices[len(slices)-1].hash != head.hash {
		slices = append(slices, head)
	}
	return slices, nil
}

// record is the line of one slice. A slice glint failed on has no
// metrics; per-kloc values need Go lines.
type record struct {
	Commit        string   `json:"commit"`
	Sloc          int      `json:"sloc"`
	GoFiles       int      `json:"go_files"`
	GlintExit     int      `json:"glint_exit"`
	DisabledRules []string `json:"disabled_rules,omitempty"`
	Error         string   `json:"error,omitempty"`
	StderrTail    string   `json:"stderr_tail,omitempty"`
	*metrics
	Date string `json:"date"`
}

type metrics struct {
	TotalGo         int            `json:"total_go"`
	BySeverity      map[string]int `json:"by_severity"`
	ByCategory      map[string]int `json:"by_category"`
	TopRules        rankedCounts   `json:"top_rules"`
	PackagesSkipped int            `json:"packages_skipped"`
	RulesRun        int            `json:"rules_run"`
	PerKlocTotal    *float64       `json:"per_kloc_total,omitempty"`
	PerKlocCritHigh *float64       `json:"per_kloc_crit_high,omitempty"`
}

func analyzeSlice(repo, hash, glint string) (*record, error) {
	tmp, err := os.MkdirTemp("", "glint-slice-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	wt := filepath.Join(tmp, "wt")
	if _, err := hist.Git(repo, "worktree", "add", "--detach", wt, hash); err != nil {
		return nil, err
	}
	defer func() {
		if _, err := hist.Git(repo, "worktree", "remove", "--force", wt); err != nil {
			fmt.Fprintln(os.Stderr, "measure: warning:", err)
		}
	}()
	for _, name := range []string{".glint.yaml", ".glint.yml"} {
		if err := os.Remove(filepath.Join(wt, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	sloc, files, err := goSloc(wt)
	if err != nil {
		return nil, err
	}
	rec := &record{Commit: hash, Sloc: sloc, GoFiles: files}
	var check hist.Check
	var categories map[string]string
	for range maxAttempts {
		check, err = hist.RunCheck(glint, wt, "check", "--tolerate-broken-packages", "-o", "json", ".")
		if err != nil {
			return nil, err
		}
		rec.GlintExit = check.Exit
		if check.Report != nil {
			break
		}
		m := ruleFailure.FindStringSubmatch(check.Stdout + check.Stderr)
		if m == nil || slices.Contains(rec.DisabledRules, m[1]) {
			break
		}
		if categories == nil {
			if categories, err = ruleCategories(glint); err != nil {
				return nil, err
			}
		}
		rec.DisabledRules = append(rec.DisabledRules, m[1])
		if err := writeDisableConfig(wt, rec.DisabledRules, categories); err != nil {
			return nil, err
		}
	}
	if check.Report == nil {
		rec.Error = "json_parse_failed"
		rec.StderrTail = hist.Tail(check.Stdout+check.Stderr, 500)
		return rec, nil
	}
	rec.metrics = summarize(check.Report, sloc)
	return rec, nil
}

// summarize counts the findings of a report in non-test Go files.
func summarize(report *output.JSONReport, sloc int) *metrics {
	m := &metrics{
		BySeverity:      map[string]int{},
		ByCategory:      map[string]int{},
		PackagesSkipped: report.Stats.PackagesSkipped,
		RulesRun:        report.Stats.RulesRun,
	}
	for _, s := range severities {
		m.BySeverity[s] = 0
	}
	var byRule rankedCounts
	for i := range report.Issues {
		issue := &report.Issues[i]
		if !strings.HasSuffix(issue.File, ".go") || strings.HasSuffix(issue.File, "_test.go") {
			continue
		}
		m.TotalGo++
		m.BySeverity[issue.Severity]++
		m.ByCategory[issue.Category]++
		byRule = byRule.add(issue.Rule)
	}
	m.TopRules = byRule.top(15)
	if sloc > 0 {
		k := float64(sloc) / 1000
		m.PerKlocTotal = perKloc(m.TotalGo, k)
		m.PerKlocCritHigh = perKloc(m.BySeverity["critical"]+m.BySeverity["high"], k)
	}
	return m
}

// perKloc is n per kloc rounded to two decimals on its exact binary value
// (0.285 is stored as 0.28499... and rounds down).
func perKloc(n int, kloc float64) *float64 {
	v, err := strconv.ParseFloat(strconv.FormatFloat(float64(n)/kloc, 'f', 2, 64), 64)
	if err != nil {
		panic(err) // FormatFloat wrote a number
	}
	return &v
}

// rankedCounts counts rules in the order they first appear; its JSON is
// an object in that order.
type rankedCounts []ruleCount

type ruleCount struct {
	rule  string
	count int
}

func (r rankedCounts) add(rule string) rankedCounts {
	for i := range r {
		if r[i].rule == rule {
			r[i].count++
			return r
		}
	}
	return append(r, ruleCount{rule, 1})
}

// top keeps the n most frequent rules, most frequent first; a tie keeps
// the order of first appearance.
func (r rankedCounts) top(n int) rankedCounts {
	sorted := append(rankedCounts{}, r...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

func (r rankedCounts) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, c := range r {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(c.rule)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%s:%d", key, c.count)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// goSloc counts the lines and files of non-test Go sources under root,
// outside vendor, node_modules and .git.
func goSloc(root string) (lines, files int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		files++
		data, err := os.ReadFile(path)
		if err != nil {
			// A historical tree may hold a dangling symlink: the file
			// counts, its lines cannot.
			fmt.Fprintln(os.Stderr, "measure: warning:", err)
			return nil
		}
		lines += countLines(data)
		return nil
	})
	return lines, files, err
}

// countLines counts lines, the last one with or without its newline.
func countLines(data []byte) int {
	n := bytes.Count(data, []byte{'\n'})
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n
}

var (
	categoryLine = regexp.MustCompile(`^\[(\w+)\]`)
	ruleLine     = regexp.MustCompile(`^\s{2}([a-z0-9-]+)\s`)
)

// ruleCategories maps each rule to its category from glint rules.
func ruleCategories(glint string) (map[string]string, error) {
	check, err := hist.RunCheck(glint, ".", "rules")
	if err != nil {
		return nil, err
	}
	categories := map[string]string{}
	var category string
	scanner := bufio.NewScanner(strings.NewReader(check.Stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if m := categoryLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			category = m[1]
			continue
		}
		if m := ruleLine.FindStringSubmatch(line); m != nil && category != "" {
			categories[m[1]] = category
		}
	}
	return categories, scanner.Err()
}

// writeDisableConfig writes a .glint.yaml turning the disabled rules off.
func writeDisableConfig(wt string, disabled []string, categories map[string]string) error {
	var order []string
	byCategory := map[string][]string{}
	for _, rule := range disabled {
		category, ok := categories[rule]
		if !ok {
			return fmt.Errorf("rule %q crashed glint but glint rules does not list it", rule)
		}
		if _, seen := byCategory[category]; !seen {
			order = append(order, category)
		}
		byCategory[category] = append(byCategory[category], rule)
	}
	var b strings.Builder
	b.WriteString("version: 1\ncategories:\n")
	for _, category := range order {
		fmt.Fprintf(&b, "  %s:\n    rules:\n", category)
		for _, rule := range byCategory[category] {
			fmt.Fprintf(&b, "      %s:\n        enabled: false\n", rule)
		}
	}
	return os.WriteFile(filepath.Join(wt, ".glint.yaml"), []byte(b.String()), 0o644)
}
