// Command verify replays today's glint on the trees of fix commits.
//
// Usage: verify REPO CANDIDATES.jsonl|MANIFEST.tsv WORKDIR OUT.jsonl [--sibling NAME=REPO ...] [--glint PATH]
//
// For every candidate commit, runs glint (all rules, no project config) on
// the directories of the files the commit changed, on the tree the record
// is about: the parent for kind=defect (the code before the fix), the
// commit itself for kind=introduced (the code the fix left). Reports the
// rules that fire on the lines the commit removed (defect) or added
// (introduced), +-1. Only reads the repository: trees come from git archive.
//
// A module that reaches a sibling repository through a local replace in
// go.mod (replace example.com/lib => ../../lib/backend) or a use of go.work
// (use ../lib) does not type-check alone: --sibling lib=/path/to/lib
// extracts that repository, as it was at the date of the analyzed tree, to
// where the replace points. When packages still fail to type-check on the
// tree before a fix, the sibling as of the fix's date is tried too: that
// tree was often built against sibling changes committed later.
//
// A manifest (.tsv, `commit kind rule[,rule...] [@path:line] [whole-tree]`
// per line) is the acceptance of new rules: only the listed rules run,
// every line is checked afresh and on its own - lines of one commit and
// kind share a glint run, not a verdict - and the lines where none of its
// rules fired are printed as misses; the exit status is 1 when there is
// one. A rule that reports the defect on a line the commit did not change
// (a setter, a line the fix kept) is anchored with @path:line in the
// analyzed tree. A rule that compares files across the repository (a TS
// set against a Go type) is run with whole-tree: glint checks the whole
// tree from its top instead of each changed file's module.
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
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/output"
	"github.com/aiseeq/glint/tools/history/internal/hist"
)

// siblingFlag collects --sibling NAME=REPO.
type siblingFlag map[string]string

func (s siblingFlag) String() string { return fmt.Sprint(map[string]string(s)) }

func (s siblingFlag) Set(value string) error {
	name, repo, ok := strings.Cut(value, "=")
	if !ok || name == "" || repo == "" {
		return fmt.Errorf("%q: expected NAME=REPO", value)
	}
	if strings.HasPrefix(repo, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("expand the repository path: %w", err)
		}
		repo = filepath.Join(home, repo[2:])
	}
	s[name] = repo
	return nil
}

func main() {
	siblings := siblingFlag{}
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Var(siblings, "sibling", "NAME=REPO: a sibling repository a local replace or go.work use points to (repeatable)")
	glint := fs.String("glint", "glint", "glint binary")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: verify REPO CANDIDATES.jsonl|MANIFEST.tsv WORKDIR OUT.jsonl [--sibling NAME=REPO ...] [--glint PATH]")
		fs.PrintDefaults()
	}
	args, err := hist.Parse(fs, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(args) != 4 {
		fs.Usage()
		os.Exit(2)
	}
	r := &replay{repo: args[0], work: args[2], glint: *glint, siblings: siblings}
	misses, err := r.verify(args[1], args[3], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	if misses > 0 {
		os.Exit(1)
	}
}

type replay struct {
	repo, work, glint string
	siblings          map[string]string
}

type job struct {
	date, commit, kind string
}

// check is one manifest line: the rules any of which must fire, and the
// anchor they may fire on instead of a changed line.
type check struct {
	rules  []string
	anchor string
}

// manifest holds the acceptance lines by commit and kind.
type manifest struct {
	checks map[[2]string][]check
	whole  map[[2]string]bool
}

// result is the line of one commit and kind in OUT.
type result struct {
	Status string   `json:"status"`
	Errors []string `json:"errors,omitempty"`
	*treeRun
	Commit   string   `json:"commit"`
	Kind     string   `json:"kind"`
	Expected []string `json:"expected,omitempty"`
	Hit      *bool    `json:"hit,omitempty"`
}

// treeRun is what glint found on the analyzed roots of one tree.
type treeRun struct {
	Files         []string            `json:"files"`
	IssuesInRoots int                 `json:"issues_in_roots"`
	Skipped       int                 `json:"packages_skipped"`
	Fired         map[string][]string `json:"fired"`
	// Hits are where each rule fired: [rule, "changed"] on a changed
	// line, [rule, anchor] on an anchor.
	Hits [][2]string `json:"hits"`
}

// verify replays every job of the input and returns the number of
// manifest lines that missed.
func (r *replay) verify(input, outPath string, progress io.Writer) (int, error) {
	var m *manifest
	var jobs []job
	var err error
	if strings.HasSuffix(input, ".tsv") {
		if m, err = readManifest(input); err != nil {
			return 0, err
		}
		if jobs, err = r.manifestJobs(m); err != nil {
			return 0, err
		}
	} else if jobs, err = readCandidates(input); err != nil {
		return 0, err
	}
	// Oldest first: neighbouring trees share most files, and the result
	// cache serves them. A candidate run resumes where it stopped; a
	// manifest is checked afresh.
	done := map[[2]string]bool{}
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if m == nil {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if done, err = readDone(outPath); err != nil {
			return 0, err
		}
	}
	out, err := os.OpenFile(outPath, flags, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open the output: %w", err)
	}
	// The Close at the end reports a failed write; this one only frees
	// the file of a run that failed earlier.
	defer func() { _ = out.Close() }()
	var misses []string
	lines := 0
	for i, j := range jobs {
		key := [2]string{j.commit, j.kind}
		if done[key] {
			continue
		}
		side, tree := "new", j.commit
		if j.kind == "defect" {
			side, tree = "old", j.commit+"^"
		}
		var rules, anchors []string
		if m != nil {
			rules = m.rules(key)
			for _, c := range m.checks[key] {
				if c.anchor != "" {
					anchors = append(anchors, c.anchor)
				}
			}
		}
		res, err := r.run(j.commit, tree, side, rules, anchors, m != nil && m.whole[key])
		if err != nil {
			res = &result{Status: "error", Errors: []string{hist.Head(err.Error(), 300)}}
		}
		res.Commit, res.Kind = j.commit, j.kind
		verdict := ""
		if m != nil {
			hit := true
			for _, c := range m.checks[key] {
				lines++
				if res.hit(c) {
					continue
				}
				hit = false
				miss := j.commit + " " + j.kind + " " + strings.Join(c.rules, ",")
				if c.anchor != "" {
					miss += " @" + c.anchor
				}
				misses = append(misses, miss+" "+res.Status)
			}
			res.Expected, res.Hit = rules, &hit
			verdict = " hit=" + strconv.FormatBool(hit)
		}
		if err := hist.WriteLine(out, res); err != nil {
			return 0, err
		}
		if _, err := fmt.Fprintf(progress, "%d/%d %s %s %s%s\n", i+1, len(jobs), j.commit, j.kind, res.Status, verdict); err != nil {
			return 0, fmt.Errorf("report progress: %w", err)
		}
	}
	if err := out.Close(); err != nil {
		return 0, fmt.Errorf("write the output: %w", err)
	}
	if m != nil {
		var report strings.Builder
		fmt.Fprintf(&report, "misses: %d of %d\n", len(misses), lines)
		for _, miss := range misses {
			report.WriteString("  " + miss + "\n")
		}
		if _, err := io.WriteString(progress, report.String()); err != nil {
			return 0, fmt.Errorf("report the misses: %w", err)
		}
	}
	return len(misses), nil
}

// hit tells whether one of the line's own rules fired on a changed line or
// on its own anchor; another line's rule or anchor does not count.
func (res *result) hit(c check) bool {
	if res.treeRun == nil {
		return false
	}
	for _, h := range res.Hits {
		for _, rule := range c.rules {
			if h[0] == rule && (h[1] == "changed" || c.anchor != "" && h[1] == c.anchor) {
				return true
			}
		}
	}
	return false
}

func readManifest(input string) (*manifest, error) {
	f, err := os.Open(input)
	if err != nil {
		return nil, fmt.Errorf("read the manifest: %w", err)
	}
	defer func() { _ = f.Close() }() // read only
	m := &manifest{checks: map[[2]string][]check{}, whole: map[[2]string]bool{}}
	scanner := bufio.NewScanner(f)
	for n := 1; scanner.Scan(); n++ {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("%s:%d: expected commit kind rule[,rule...] [@path:line] [whole-tree]", input, n)
		}
		key := [2]string{fields[0], fields[1]}
		c := check{rules: strings.Split(fields[2], ",")}
		for _, token := range fields[3:] {
			switch {
			case token == "whole-tree":
				m.whole[key] = true
			case strings.HasPrefix(token, "@") && c.anchor == "":
				a, err := parseAnchor(token[1:])
				if err != nil {
					return nil, fmt.Errorf("%s:%d: %w", input, n, err)
				}
				c.anchor = a.text
			default:
				return nil, fmt.Errorf("%s:%d: %q: expected one @path:line and whole-tree", input, n, token)
			}
		}
		m.checks[key] = append(m.checks[key], c)
	}
	return m, scanner.Err()
}

// rules are the rules of every line of one commit and kind: they share a
// glint run.
func (m *manifest) rules(key [2]string) []string {
	set := map[string]bool{}
	for _, c := range m.checks[key] {
		for _, rule := range c.rules {
			set[rule] = true
		}
	}
	rules := make([]string, 0, len(set))
	for rule := range set {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	return rules
}

func (r *replay) manifestJobs(m *manifest) ([]job, error) {
	var jobs []job
	for key := range m.checks {
		date, err := hist.Git(r.repo, "log", "-1", "--format=%ad", "--date=short", key[0])
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job{strings.TrimSpace(date), key[0], key[1]})
	}
	sortJobs(jobs)
	return jobs, nil
}

func readCandidates(input string) ([]job, error) {
	f, err := os.Open(input)
	if err != nil {
		return nil, fmt.Errorf("read the candidates: %w", err)
	}
	defer func() { _ = f.Close() }() // read only
	seen := map[job]bool{}
	var jobs []job
	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, 16<<20)
	for n := 1; scanner.Scan(); n++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var rec struct{ Date, Commit, Kind string }
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", input, n, err)
		}
		if rec.Commit == "" || rec.Date == "" {
			return nil, fmt.Errorf("%s:%d: a record needs commit and date", input, n)
		}
		// A triage record without a kind is about a defect.
		if rec.Kind == "" {
			rec.Kind = "defect"
		}
		j := job{rec.Date, rec.Commit, rec.Kind}
		if !seen[j] {
			seen[j] = true
			jobs = append(jobs, j)
		}
	}
	sortJobs(jobs)
	return jobs, scanner.Err()
}

func sortJobs(jobs []job) {
	sort.Slice(jobs, func(i, j int) bool {
		a, b := jobs[i], jobs[j]
		if a.date != b.date {
			return a.date < b.date
		}
		if a.commit != b.commit {
			return a.commit < b.commit
		}
		return a.kind < b.kind
	})
}

// readDone returns the commits and kinds an earlier run already wrote.
func readDone(outPath string) (map[[2]string]bool, error) {
	done := map[[2]string]bool{}
	data, err := os.ReadFile(outPath)
	if errors.Is(err, fs.ErrNotExist) {
		return done, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the earlier output: %w", err)
	}
	for n, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var res struct{ Commit, Kind string }
		if err := json.Unmarshal(line, &res); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", outPath, n+1, err)
		}
		done[[2]string{res.Commit, res.Kind}] = true
	}
	return done, nil
}

// code are the files whose changed lines glint may report on.
var code = regexp.MustCompile(`\.(go|ts|tsx|js|jsx|mjs|sh|mk|dockerfile|html|tmpl|gohtml)$|(^|/)(GNUmakefile|[Mm]akefile|Dockerfile(\.[\w-]+)?|Containerfile|(docker-)?compose[\w.-]*\.ya?ml|bitbucket-pipelines\.yml|\.gitlab-ci\.yml|\.github/workflows/[^/]+\.ya?ml)$`)

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// changedLines returns, per code file, the lines the commit removed (side
// "old", numbered in the parent) or added (side "new").
func (r *replay) changedLines(commit, side string) (map[string]map[int]bool, error) {
	diff, err := hist.Git(r.repo, "-c", "core.quotePath=false", "show", "--format=", "-U0", "--no-renames", commit)
	if err != nil {
		return nil, err
	}
	return parseDiff(diff, side)
}

func parseDiff(diff, side string) (map[string]map[int]bool, error) {
	lines := map[string]map[int]bool{}
	var oldPath, file string
	inHunk := false
	for line := range strings.SplitSeq(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "diff "):
			inHunk, oldPath, file = false, "", ""
		case inHunk:
			// Hunk lines start with -, + or \; a removed "-- comment"
			// is not a header.
			if !strings.HasPrefix(line, "@@") {
				continue
			}
		case strings.HasPrefix(line, "--- "):
			p, err := diffPath(line[4:])
			if err != nil {
				return nil, err
			}
			oldPath = p
			continue
		case strings.HasPrefix(line, "+++ "):
			p, err := diffPath(line[4:])
			if err != nil {
				return nil, err
			}
			file = p
			if side == "old" {
				file = oldPath
			}
			continue
		}
		if !strings.HasPrefix(line, "@@") {
			continue
		}
		inHunk = true
		if file == "" || !code.MatchString(file) {
			continue
		}
		m := hunkHeader.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("hunk header %q", line)
		}
		start, count := m[1], m[2]
		if side == "new" {
			start, count = m[3], m[4]
		}
		first, err := strconv.Atoi(start)
		if err != nil {
			return nil, fmt.Errorf("read a hunk header: %w", err)
		}
		n := 1
		if count != "" {
			if n, err = strconv.Atoi(count); err != nil {
				return nil, fmt.Errorf("read a hunk header: %w", err)
			}
		}
		for l := first; l < first+n; l++ {
			if lines[file] == nil {
				lines[file] = map[int]bool{}
			}
			lines[file][l] = true
		}
	}
	return lines, nil
}

// diffPath returns the path of a ---/+++ header without its a/ or b/, or
// "" for /dev/null.
func diffPath(s string) (string, error) {
	if s == "/dev/null" {
		return "", nil
	}
	if strings.HasPrefix(s, `"`) {
		unquoted, err := strconv.Unquote(s)
		if err != nil {
			return "", fmt.Errorf("diff path %s: %w", s, err)
		}
		s = unquoted
	}
	if len(s) < 2 || s[1] != '/' {
		return "", fmt.Errorf("diff path %q: no a/ or b/ prefix", s)
	}
	return s[2:], nil
}

// anchor is a line of the analyzed tree a manifest line names, as
// path:line.
type anchor struct {
	text string
	file string
	line int
}

func parseAnchor(text string) (anchor, error) {
	i := strings.LastIndex(text, ":")
	if i < 0 {
		return anchor{}, fmt.Errorf("anchor %q: expected path:line", text)
	}
	line, err := strconv.Atoi(text[i+1:])
	if err != nil {
		return anchor{}, fmt.Errorf("anchor %q: expected path:line", text)
	}
	return anchor{text, text[:i], line}, nil
}

// moduleRoot is the top directory to extract for a file: its Go module or
// its own directory.
func moduleRoot(file string, treeFiles map[string]bool) string {
	parts := strings.Split(file, "/")
	for i := len(parts) - 1; i > 0; i-- {
		dir := strings.Join(parts[:i], "/")
		if treeFiles[dir+"/go.mod"] {
			return dir
		}
	}
	// A module at the top of the repository is the whole tree: its
	// packages import each other and type-check only together.
	if treeFiles["go.mod"] {
		return "."
	}
	return path.Dir(file)
}

var (
	localReplace = regexp.MustCompile(`=>\s*(\.\.?/\S+)`)
	// A go.work use of a directory: `use ../lib` or a line of a use ( ... ) block.
	workUse = regexp.MustCompile(`(?m)^\s*(?:use\s+)?(\.\.?/[^\s)]+)\s*$`)
)

// localSiblingPaths returns the relative paths target's go.mod replaces
// and its go.work uses point to.
func localSiblingPaths(target string) ([]string, error) {
	var rels []string
	for _, f := range []struct {
		name    string
		pattern *regexp.Regexp
	}{{"go.mod", localReplace}, {"go.work", workUse}} {
		data, err := os.ReadFile(filepath.Join(target, f.name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read the local siblings of %s: %w", target, err)
		}
		for _, m := range f.pattern.FindAllStringSubmatch(string(data), -1) {
			rels = append(rels, m[1])
		}
	}
	return rels, nil
}

// provideSiblings extracts the sibling repositories a local replace of
// target's go.mod or a use of its go.work points to, as they were at the
// date of commit at; a path already holding that revision is kept. It
// returns whether target has such a reference.
func (r *replay) provideSiblings(target, at string) (bool, error) {
	if len(r.siblings) == 0 {
		return false, nil
	}
	rels, err := localSiblingPaths(target)
	if err != nil || len(rels) == 0 {
		return false, err
	}
	date, err := hist.Git(r.repo, "log", "-1", "--format=%cI", at)
	if err != nil {
		return false, err
	}
	provided := false
	for _, rel := range rels {
		var parts []string
		for p := range strings.SplitSeq(rel, "/") {
			if p != "." && p != ".." {
				parts = append(parts, p)
			}
		}
		if len(parts) == 0 {
			continue
		}
		sibling, ok := r.siblings[parts[0]]
		if !ok {
			continue
		}
		provided = true
		sub := strings.Join(parts[1:], "/")
		dest := filepath.Join(target, rel)
		rev, err := hist.Git(sibling, "rev-list", "-1", "--before="+strings.TrimSpace(date), "HEAD")
		if err != nil {
			return false, err
		}
		rev = strings.TrimSpace(rev)
		if rev == "" {
			return false, fmt.Errorf("%s: no commit before %s", sibling, strings.TrimSpace(date))
		}
		marker := dest + ".rev"
		if held, err := os.ReadFile(marker); err == nil && string(held) == rev {
			continue
		}
		if err := os.RemoveAll(dest); err != nil {
			return false, fmt.Errorf("clear sibling %s: %w", dest, err)
		}
		top := strings.TrimSuffix(strings.TrimSuffix(dest, sub), "/")
		if err := os.MkdirAll(top, 0o755); err != nil {
			return false, fmt.Errorf("create the sibling directory: %w", err)
		}
		args := []string{"archive", rev}
		if sub != "" {
			args = append(args, sub)
		}
		if err := extract(sibling, top, args...); err != nil {
			return false, err
		}
		if err := os.WriteFile(marker, []byte(rev), 0o644); err != nil {
			return false, fmt.Errorf("mark sibling %s: %w", dest, err)
		}
	}
	return provided, nil
}

// extract unpacks git archive of repo into dest. Historical trees may hold
// entries tar refuses (a symlink with a file body): they are skipped with
// a warning, the Go and TS sources extract.
func extract(repo, dest string, args ...string) error {
	archive, err := hist.Run(exec.Command("git", append([]string{"-C", repo}, args...)...))
	if err != nil {
		return err
	}
	tar := exec.Command("tar", "-x", "-C", dest)
	tar.Stdin = bytes.NewReader(archive)
	var stderr bytes.Buffer
	tar.Stderr = &stderr
	if err := tar.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return fmt.Errorf("tar: %w", err)
		}
		first, _, _ := strings.Cut(strings.TrimSpace(stderr.String()), "\n")
		fmt.Fprintf(os.Stderr, "warning: %s %s: tar skipped entries: %s\n", repo, strings.Join(args, " "), first)
	}
	return nil
}

func (r *replay) run(commit, tree, side string, rules, anchorTexts []string, whole bool) (*result, error) {
	lines, err := r.changedLines(commit, side)
	if err != nil {
		return nil, err
	}
	changed := map[string]map[int]bool{}
	maps.Copy(changed, lines)
	anchors := make([]anchor, 0, len(anchorTexts))
	for _, text := range anchorTexts {
		a, err := parseAnchor(text)
		if err != nil {
			return nil, err
		}
		anchors = append(anchors, a)
		set := map[int]bool{a.line: true}
		for l := range lines[a.file] {
			set[l] = true
		}
		lines[a.file] = set
	}
	if len(lines) == 0 {
		return &result{Status: "no-code-lines"}, nil
	}
	listing, err := hist.Git(r.repo, "ls-tree", "-r", "-z", "--name-only", tree)
	if err != nil {
		return nil, err
	}
	treeFiles := map[string]bool{}
	for f := range strings.SplitSeq(listing, "\x00") {
		treeFiles[f] = true
	}
	byRoot := map[string][]string{}
	for f := range lines {
		root := "."
		if !whole {
			root = moduleRoot(f, treeFiles)
		}
		byRoot[root] = append(byRoot[root], f)
	}
	roots := make([]string, 0, len(byRoot))
	for root := range byRoot {
		roots = append(roots, root)
	}
	sort.Strings(roots)

	run := &treeRun{Fired: map[string][]string{}, Hits: [][2]string{}}
	var errs []string
	fired := map[string]map[string]bool{}
	hits := map[[2]string]bool{}
	for _, root := range roots {
		report, failure, err := r.checkRoot(commit, tree, root, byRoot[root], rules, whole, treeFiles["go.mod"])
		if err != nil {
			return nil, err
		}
		if report == nil {
			errs = append(errs, failure)
			continue
		}
		run.IssuesInRoots += len(report.Issues)
		run.Skipped = max(run.Skipped, report.Stats.PackagesSkipped)
		for i := range report.Issues {
			issue := &report.Issues[i]
			rel := path.Join(root, issue.File)
			near := []int{issue.Line - 1, issue.Line, issue.Line + 1}
			if !anyIn(near, lines[rel]) {
				continue
			}
			if fired[rel] == nil {
				fired[rel] = map[string]bool{}
			}
			fired[rel][issue.Rule] = true
			if anyIn(near, changed[rel]) {
				hits[[2]string{issue.Rule, "changed"}] = true
			}
			for _, a := range anchors {
				if a.file == rel && anyIn(near, map[int]bool{a.line: true}) {
					hits[[2]string{issue.Rule, a.text}] = true
				}
			}
		}
	}
	for f := range lines {
		run.Files = append(run.Files, f)
	}
	sort.Strings(run.Files)
	for f, set := range fired {
		for rule := range set {
			run.Fired[f] = append(run.Fired[f], rule)
		}
		sort.Strings(run.Fired[f])
	}
	for h := range hits {
		run.Hits = append(run.Hits, h)
	}
	sort.Slice(run.Hits, func(i, j int) bool {
		if run.Hits[i][0] != run.Hits[j][0] {
			return run.Hits[i][0] < run.Hits[j][0]
		}
		return run.Hits[i][1] < run.Hits[j][1]
	})
	res := &result{Status: "ok", Errors: errs, treeRun: run}
	if len(errs) > 0 {
		res.Status = "partial"
	}
	return res, nil
}

func anyIn(lines []int, set map[int]bool) bool {
	for _, l := range lines {
		if set[l] {
			return true
		}
	}
	return false
}

// checkRoot extracts one root of tree and runs glint on it. A glint run
// that writes no report is a failure of that root, not of the job.
func (r *replay) checkRoot(commit, tree, root string, files, rules []string, whole, topModule bool) (*output.JSONReport, string, error) {
	// One directory per root, so that the result cache of the previous
	// commit's tree serves the files that did not change.
	dir := "top"
	if root != "." {
		dir = strings.ReplaceAll(root, "/", "__")
	}
	dest := filepath.Join(r.work, dir)
	if err := os.RemoveAll(dest); err != nil {
		return nil, "", fmt.Errorf("clear tree %s: %w", dest, err)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, "", fmt.Errorf("create tree %s: %w", dest, err)
	}
	// Files at the top of the repository come alone, not with the whole
	// tree - unless the top is a Go module, which is the whole tree.
	args := []string{"archive", tree}
	switch {
	case whole || root == "." && topModule:
	case root == ".":
		args = append(args, files...)
	default:
		args = append(args, root)
	}
	if err := extract(r.repo, dest, args...); err != nil {
		return nil, "", err
	}
	target := filepath.Join(dest, root)
	// Today's rules run without the project's configuration: its
	// exceptions would hide the very findings the replay looks for.
	for _, config := range []string{filepath.Join(dest, ".glint.yaml"), filepath.Join(target, ".glint.yaml")} {
		if err := os.Remove(config); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, "", err
		}
	}
	glintArgs := []string{"check", "--tolerate-broken-packages", "--output=json", "--min-severity=low"}
	if len(rules) > 0 {
		glintArgs = append(glintArgs, "--rule="+strings.Join(rules, ","))
	}
	// The tree before a fix was often built against sibling changes
	// committed later, up to the fix itself: when packages do not
	// type-check with the sibling of the tree's date, the sibling of the
	// fix's date is tried, and the run with fewer of them kept.
	ats := []string{tree}
	if tree != commit {
		ats = append(ats, commit)
	}
	var report *output.JSONReport
	var failure string
	for _, at := range ats {
		provided, err := r.provideSiblings(target, at)
		if err != nil {
			return nil, "", err
		}
		if !provided && at != tree {
			break
		}
		check, err := hist.RunCheck(r.glint, target, append(glintArgs, ".")...)
		if err != nil {
			return nil, "", err
		}
		if check.Report == nil {
			failure = fmt.Sprintf("%s: exit %d: %s", root, check.Exit, hist.Head(strings.TrimSpace(check.Stderr), 300))
			continue
		}
		if report == nil || check.Report.Stats.PackagesSkipped < report.Stats.PackagesSkipped {
			report = check.Report
		}
		if report.Stats.PackagesSkipped == 0 {
			break
		}
	}
	return report, failure, nil
}
