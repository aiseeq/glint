package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/output"
)

func TestReadConfigExpandsHomeAndRequiresRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumers.txt")
	if err := os.WriteFile(path, []byte("# roots\nroot ~/synthetic\nskip frozen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want, _ := filepath.Abs(filepath.Join(home, "synthetic"))
	if !reflect.DeepEqual(c.roots, []string{want}) || !c.skips["frozen"] {
		t.Fatalf("config = %+v", c)
	}
	if err := os.WriteFile(path, []byte("skip frozen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err == nil {
		t.Fatal("expected missing root error")
	}
}

func TestFindProjectsHonorsDepthAndIgnoredDirectories(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"alpha", "group/tool", "deep/level/third", "too/deep/third/fourth", "vendor/hidden", ".hidden/hidden", "node_modules/hidden"} {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findProjects(config{roots: []string{root}, skips: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root, "alpha"), filepath.Join(root, "deep/level/third"), filepath.Join(root, "group/tool")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projects = %v, want %v", got, want)
	}
}

func TestFindProjectsSkipsLinkedWorktrees(t *testing.T) {
	root := t.TempDir()
	for dir, gitEntry := range map[string]string{"main": "dir", "main-old": "file"} {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if gitEntry == "dir" {
			if err := os.Mkdir(filepath.Join(path, ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		link := []byte("gitdir: " + filepath.Join(root, "main/.git/worktrees/main-old") + "\n")
		if err := os.WriteFile(filepath.Join(path, ".git"), link, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findProjects(config{roots: []string{root}, skips: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(root, "main")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("projects = %v, want %v: a linked worktree repeats its repository's findings", got, want)
	}
}

func TestDifferenceTreatsFindingsAsMultisetAndIgnoresOtherFields(t *testing.T) {
	old := []output.JSONIssue{{Rule: "r", File: "a.go", Line: 1, Message: "same", Severity: "low"}, {Rule: "r", File: "a.go", Line: 1, Message: "same"}}
	newIssues := []output.JSONIssue{{Rule: "r", File: "a.go", Line: 1, Message: "same", Severity: "high"}, {Rule: "x", File: "b.go", Line: 2, Message: "new"}}
	added, removed := difference(old, newIssues)
	if len(added) != 1 || added[0].Rule != "x" || len(removed) != 1 || removed[0].Rule != "r" {
		t.Fatalf("difference = +%v -%v", added, removed)
	}
}

func TestOldBinaryWithoutTheNewRuleCountsAsNoFindings(t *testing.T) {
	root := t.TempDir()
	isolate(t, root)
	project := filepath.Join(root, "alpha")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, "old")
	oldScript := "#!/bin/sh\necho 'Error: unknown rule \"fresh-rule\"' >&2\nexit 1\n"
	newer := filepath.Join(root, "new")
	newScript := "#!/bin/sh\necho '{\"issues\":[{\"rule\":\"fresh-rule\",\"file\":\"a.go\",\"line\":3,\"message\":\"m\"}]}'\nexit 1\n"
	for path, script := range map[string]string{old: oldScript, newer: newScript} {
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(root, "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	code := run([]string{"-config", cfg, "-old", old, "-new", newer, "-r", "fresh-rule"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "+ a.go:3 fresh-rule") {
		t.Fatalf("code %d, stdout %q, stderr %q: want the new rule's finding as added", code, stdout.String(), stderr.String())
	}
}

// The new build keeps its result cache apart: a glint run prunes the caches of
// other builds, so a run of the new build in the shared directory would wipe
// the caches the installed glint keeps for every project.
func TestNewBinaryUsesItsOwnResultCacheDirectory(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "alpha")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	userCache := filepath.Join(root, "cache")
	t.Setenv("XDG_CACHE_HOME", userCache)
	t.Setenv("GLINT_CACHE_DIR", "")
	seen := map[string]string{}
	for _, name := range []string{"old", "new"} {
		script := "#!/bin/sh\nprintf '%s' \"$GLINT_CACHE_DIR\" > " + filepath.Join(root, name+".env") + "\necho '{\"issues\":[]}'\n"
		if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(root, "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	if code := run([]string{"-config", cfg, "-old", filepath.Join(root, "old"), "-new", filepath.Join(root, "new")}, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	for _, name := range []string{"old", "new"} {
		data, err := os.ReadFile(filepath.Join(root, name+".env"))
		if err != nil {
			t.Fatal(err)
		}
		seen[name] = string(data)
	}
	if seen["old"] != "" {
		t.Fatalf("installed glint got GLINT_CACHE_DIR %q, want the shared default", seen["old"])
	}
	if want := filepath.Join(userCache, "glint", "consumers-new"); seen["new"] != want {
		t.Fatalf("new glint got GLINT_CACHE_DIR %q, want %q", seen["new"], want)
	}
}

// A rule panic still prints the JSON of the other rules and names the panic on
// stderr: the run lost that rule's findings and counts as an error, not as a
// project without differences.
func TestRulePanicCountsAsError(t *testing.T) {
	root := t.TempDir()
	isolate(t, root)
	project := filepath.Join(root, "alpha")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, "old")
	oldScript := "#!/bin/sh\necho '{\"issues\":[]}'\n"
	newer := filepath.Join(root, "new")
	newScript := "#!/bin/sh\necho '{\"issues\":[]}'\necho 'Error: rule \"broken-rule\" panicked on a.go: boom' >&2\necho 'goroutine 1 [running]:' >&2\necho 'Error: 1 rule panic(s), the findings of these rules are missing: rule \"broken-rule\" panicked on a.go: boom' >&2\nexit 1\n"
	for path, script := range map[string]string{old: oldScript, newer: newScript} {
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(root, "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	code := run([]string{"-config", cfg, "-old", old, "-new", newer}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stdout.String(), "1 errors") || !strings.Contains(stderr.String(), "alpha: ") || strings.Count(stderr.String(), `"broken-rule" panicked`) != 1 {
		t.Fatalf("code %d, stdout %q, stderr %q: want the panic counted as an error of alpha", code, stdout.String(), stderr.String())
	}
}

// isolate keeps a test's runs off the user's caches and off a git repository
// that may hold the temporary directory.
func isolate(t *testing.T, root string) string {
	t.Helper()
	userCache := filepath.Join(root, "cache")
	t.Setenv("XDG_CACHE_HOME", userCache)
	t.Setenv("GIT_CEILING_DIRECTORIES", root)
	gitConfig := filepath.Join(root, "gitconfig")
	if err := os.WriteFile(gitConfig, []byte("[user]\n\tname = t\n\temail = t@example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", gitConfig)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	return userCache
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// countingGlint writes a test double of glint that adds a line to count on
// every run and reports issues; extra goes into the script before the report.
func countingGlint(t *testing.T, path, count, issues, extra string) {
	t.Helper()
	script := "#!/bin/sh\necho run >> " + count + "\n" + extra + "echo '{\"issues\":[" + issues + "]}'\nexit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
		t.Fatal(err)
	}
}

func runCount(t *testing.T, count string) int {
	t.Helper()
	data, err := os.ReadFile(count)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "run\n")
}

const (
	oldIssue = `{"rule":"r","file":"a.go","line":1,"message":"old"}`
	newIssue = `{"rule":"r","file":"b.go","line":2,"message":"new"}`
)

// consumersFixture is a root with one git project, alpha, and counting
// doubles of the old and the new glint, which find the same.
type consumersFixture struct {
	root, project, cfg, old, newer, oldCount, userCache string
}

func newConsumersFixture(t *testing.T, withGit bool) consumersFixture {
	t.Helper()
	root := t.TempDir()
	f := consumersFixture{root: root, project: filepath.Join(root, "alpha"), cfg: filepath.Join(root, "consumers.txt"),
		old: filepath.Join(root, "old"), newer: filepath.Join(root, "new"), oldCount: filepath.Join(root, "old.count")}
	f.userCache = isolate(t, root)
	if err := os.MkdirAll(f.project, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.project, ".glint.yaml"), "version: 1\n", 0o600)
	writeFile(t, filepath.Join(f.project, "a.go"), "package a\n", 0o600)
	if withGit {
		runGit(t, f.project, "init", "-q")
		runGit(t, f.project, "add", ".")
		runGit(t, f.project, "commit", "-q", "-m", "init")
	}
	countingGlint(t, f.old, f.oldCount, oldIssue, "")
	countingGlint(t, f.newer, filepath.Join(root, "new.count"), oldIssue, "")
	writeFile(t, f.cfg, "root "+root+"\n", 0o600)
	return f
}

// run runs consumers with extra flags and returns its stdout; the run must
// find no difference.
func (f consumersFixture) run(t *testing.T, extra ...string) string {
	t.Helper()
	var stdout, stderr strings.Builder
	args := append([]string{"-config", f.cfg, "-old", f.old, "-new", f.newer}, extra...)
	if code := run(args, &stdout, &stderr); code != 0 || strings.Contains(stdout.String(), "== ") {
		t.Fatalf("code %d, stdout %q, stderr %q: want no difference", code, stdout.String(), stderr.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr %q", stderr.String())
	}
	return stdout.String()
}

// A second run of the installed glint with the same binary over the same tree
// with the same flags is taken from the cache; a change of a tracked or an
// untracked file, of HEAD, of the flags or of the binary runs it again.
func TestOldRunIsCachedByBinaryTreeAndFlags(t *testing.T) {
	f := newConsumersFixture(t, true)
	steps := []struct {
		name   string
		change func()
		flags  []string
		runs   int
	}{
		{"first run", func() {}, nil, 1},
		{"same tree", func() {}, nil, 1},
		{"tracked file edited", func() { writeFile(t, filepath.Join(f.project, "a.go"), "package a // edited\n", 0o600) }, nil, 2},
		{"same edit", func() {}, nil, 2},
		{"tracked file edited again", func() { writeFile(t, filepath.Join(f.project, "a.go"), "package a // again\n", 0o600) }, nil, 3},
		{"untracked file", func() { writeFile(t, filepath.Join(f.project, "c.go"), "package a\n", 0o600) }, nil, 4},
		{"untracked file edited", func() { writeFile(t, filepath.Join(f.project, "c.go"), "package a // edited\n", 0o600) }, nil, 5},
		{"untracked file in a new directory", func() {
			if err := os.Mkdir(filepath.Join(f.project, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(f.project, "sub", "d.go"), "package sub\n", 0o600)
		}, nil, 6},
		{"file in the untracked directory edited", func() { writeFile(t, filepath.Join(f.project, "sub", "d.go"), "package sub // edited\n", 0o600) }, nil, 7},
		{"new HEAD", func() { runGit(t, f.project, "commit", "-q", "--allow-empty", "-m", "empty") }, nil, 8},
		{"rules flag", func() {}, []string{"-r", "r"}, 9},
		{"same rules flag", func() {}, []string{"-r", "r"}, 9},
		{"jobs flag", func() {}, []string{"-r", "r", "-j", "2"}, 10},
		{"new binary", func() { countingGlint(t, f.old, f.oldCount, oldIssue, "# rebuilt\n") }, []string{"-r", "r", "-j", "2"}, 11},
		{"same binary", func() {}, []string{"-r", "r", "-j", "2"}, 11},
	}
	var firstReport string
	for _, step := range steps {
		step.change()
		before := runCount(t, f.oldCount)
		out := f.run(t, step.flags...)
		if got := runCount(t, f.oldCount); got != step.runs {
			t.Fatalf("%s: the old glint ran %d times in all, want %d", step.name, got, step.runs)
		}
		fromCache := before == step.runs
		wantLine := "old glint: 0 of 1 projects from cache\n"
		if fromCache {
			wantLine = "old glint: 1 of 1 projects from cache\n"
		}
		if !strings.Contains(out, wantLine) {
			t.Fatalf("%s: stdout %q, want %q", step.name, out, wantLine)
		}
		report := strings.Replace(out, wantLine, "", 1)
		if firstReport == "" {
			firstReport = report
		} else if report != firstReport {
			t.Fatalf("%s: report %q, want the first run's %q", step.name, report, firstReport)
		}
	}
	entries, err := os.ReadDir(filepath.Join(f.userCache, "glint", "consumers"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "alpha-") {
		t.Fatalf("cache entries %v, want one entry of alpha and no temporary file", entries)
	}
}

// A project outside git has no tree state to compare: its old run is not cached.
func TestOldRunOutsideGitIsNotCached(t *testing.T) {
	f := newConsumersFixture(t, false)
	for want := 1; want <= 2; want++ {
		if out := f.run(t); !strings.Contains(out, "old glint: 0 of 1 projects from cache\n") {
			t.Fatalf("stdout %q", out)
		}
		if got := runCount(t, f.oldCount); got != want {
			t.Fatalf("the old glint ran %d times, want %d", got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(f.userCache, "glint", "consumers")); !os.IsNotExist(err) {
		t.Fatalf("cache directory of a project outside git: %v, want none", err)
	}
}

// A tree that changes while the old glint runs may not be the tree it read:
// that run is not cached, even under the key of the tree before the run.
func TestOldRunOverAChangingTreeIsNotCached(t *testing.T) {
	f := newConsumersFixture(t, true)
	source := filepath.Join(f.project, "a.go")
	mark := filepath.Join(f.root, "edited")
	countingGlint(t, f.old, f.oldCount, oldIssue, "if [ ! -e "+mark+" ]; then touch "+mark+"; echo '// mid-run' >> "+source+"; fi\n")
	f.run(t)
	writeFile(t, source, "package a\n", 0o600)
	f.run(t)
	if got := runCount(t, f.oldCount); got != 2 {
		t.Fatalf("the old glint ran %d times, want 2: the first run saw the tree change", got)
	}
}

// glint reads files outside the tree the cache key covers (the approved
// models list, a go.work module, a git-ignored file, tickets): when such an
// input changes, the installed glint finds what the new build finds, and the
// cached old run is stale. A difference from a cached old run is not reported
// until the installed glint, run again, still differs.
func TestCachedOldRunThatDiffersIsRunAgain(t *testing.T) {
	f := newConsumersFixture(t, true)
	input := filepath.Join(f.root, "outside")
	writeFile(t, input, oldIssue, 0o600)
	reads := "issues=$(cat " + input + ")\n"
	report := "echo '{\"issues\":['\"$issues\"']}'\nexit 1\n"
	writeFile(t, f.old, "#!/bin/sh\necho run >> "+f.oldCount+"\n"+reads+report, 0o700)
	writeFile(t, f.newer, "#!/bin/sh\n"+reads+report, 0o700)
	consumers := func() (int, string) {
		var stdout, stderr strings.Builder
		code := run([]string{"-config", f.cfg, "-old", f.old, "-new", f.newer}, &stdout, &stderr)
		if stderr.String() != "" {
			t.Fatalf("stderr %q", stderr.String())
		}
		return code, stdout.String()
	}
	if code, out := consumers(); code != 0 {
		t.Fatalf("first run: code %d, stdout %q", code, out)
	}
	writeFile(t, input, oldIssue+","+newIssue, 0o600)
	code, out := consumers()
	if code != 0 || strings.Contains(out, "b.go:2") {
		t.Fatalf("after the outside input changed: code %d, stdout %q; want no difference", code, out)
	}
	if !strings.Contains(out, "old glint: 0 of 1 projects from cache, 1 run again on a difference\n") {
		t.Fatalf("stdout %q, want the cached run counted as run again", out)
	}
	if got := runCount(t, f.oldCount); got != 2 {
		t.Fatalf("the old glint ran %d times, want 2", got)
	}
	if _, out := consumers(); !strings.Contains(out, "old glint: 1 of 1 projects from cache\n") {
		t.Fatalf("third run: stdout %q, want the fresh old run from the cache", out)
	}
}

// A difference the installed glint confirms on its run again is reported, on
// every consumers run: the entry it refreshes still differs.
func TestDifferenceFromACachedOldRunIsReported(t *testing.T) {
	f := newConsumersFixture(t, true)
	f.run(t)
	countingGlint(t, f.newer, filepath.Join(f.root, "new.count"), oldIssue+","+newIssue, "")
	for i, want := range []int{2, 3} {
		var stdout, stderr strings.Builder
		code := run([]string{"-config", f.cfg, "-old", f.old, "-new", f.newer}, &stdout, &stderr)
		out := stdout.String()
		if code != 1 || !strings.Contains(out, "+ b.go:2 r") || strings.Contains(out, "a.go:1") || stderr.String() != "" {
			t.Fatalf("run %d: code %d, stdout %q, stderr %q: want b.go:2 added", i+2, code, out, stderr.String())
		}
		if !strings.Contains(out, "old glint: 0 of 1 projects from cache, 1 run again on a difference\n") {
			t.Fatalf("run %d: stdout %q, want the cached run counted as run again", i+2, out)
		}
		if got := runCount(t, f.oldCount); got != want {
			t.Fatalf("run %d: the old glint ran %d times, want %d", i+2, got, want)
		}
	}
}
