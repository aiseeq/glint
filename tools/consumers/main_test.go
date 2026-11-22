package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/output"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
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

func TestReadConfigAcceptsBareRootPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "consumers.txt")
	if err := os.WriteFile(path, []byte(root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.roots, []string{root}) {
		t.Fatalf("roots = %v, want [%s]", c.roots, root)
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
	rulestest.IsolateUserCache(t, userCache)
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

func TestConsumerMarkersFullAndPartial(t *testing.T) {
	repo := initConsumerRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "uncommitted.txt"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeConsumerMarker(repo, "full"); err != nil {
		t.Fatal(err)
	}
	path, err := consumerMarkerPath(repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("dirty tree got marker: stat err %v", err)
	}
	if err := os.Remove(filepath.Join(repo, "uncommitted.txt")); err != nil {
		t.Fatal(err)
	}
	if err := writeConsumerMarker(repo, "full"); err != nil {
		t.Fatal(err)
	}
	path, err = consumerMarkerPath(repo)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "full\n" {
		t.Fatalf("full marker = %q, err %v", got, err)
	}
	if err := writeConsumerMarker(repo, "partial"); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != "full\n" {
		t.Fatalf("partial replaced full marker: %q, err %v", got, err)
	}
	if err := commitConsumerTreeChange(repo); err != nil {
		t.Fatal(err)
	}
	if err := writeConsumerMarker(repo, "partial"); err != nil {
		t.Fatal(err)
	}
	path, err = consumerMarkerPath(repo)
	if err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != "partial\n" {
		t.Fatalf("partial marker = %q, err %v", got, err)
	}
}

func TestRemindMarkerStates(t *testing.T) {
	repo := initConsumerRepo(t)
	var out strings.Builder
	remind(repo, &out)
	if !strings.Contains(out.String(), "graft consumers") {
		t.Fatalf("missing-marker reminder = %q", out.String())
	}
	if err := writeConsumerMarker(repo, "partial"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	remind(repo, &out)
	if !strings.Contains(out.String(), "partial") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("partial reminder = %q", out.String())
	}
	if err := writeConsumerMarker(repo, "full"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	remind(repo, &out)
	if out.Len() != 0 {
		t.Fatalf("full marker reminder = %q, want silence", out.String())
	}
}

func TestRuleTimingParseAndThreshold(t *testing.T) {
	got := parseRuleTimings("TIMING\n  RULE                                  TOTAL\n  faster-rule                            2ms\n  growing-rule                           1.2s\n  new-rule                               400ms\n  cached-rule                            <1ms\n")
	if got["growing-rule"] != 1200*time.Millisecond || got["cached-rule"] != 0 {
		t.Fatalf("parsed timings = %#v", got)
	}
	old := map[string]time.Duration{
		"growing-rule":  800 * time.Millisecond,
		"below-percent": 500 * time.Millisecond,
		"below-delta":   3 * time.Second,
		"cached-rule":   0,
	}
	newTimes := map[string]time.Duration{
		"growing-rule":  1200 * time.Millisecond, // exactly +50%, +400ms
		"below-percent": 700 * time.Millisecond,
		"below-delta":   3200 * time.Millisecond,
		"cached-rule":   2 * time.Second,
		"new-rule":      400 * time.Millisecond,
	}
	oldRules := map[string]bool{"growing-rule": true, "below-percent": true, "below-delta": true, "cached-rule": true}
	slower, fastestNew := compareRuleTimings(old, oldRules, newTimes)
	if len(slower) != 1 || slower[0].name != "growing-rule" || fastestNew.name != "new-rule" {
		t.Fatalf("comparison = slower %#v, new %#v", slower, fastestNew)
	}
}

func TestCompareTargetsReportsOnlyConfirmedSlowerRules(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "proj")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "calls.log")
	old := filepath.Join(root, "old")
	newer := filepath.Join(root, "new")
	oldScript := timingFakeScript("old", log, "alpha 1s\ndelta 1s\neps 2s", "alpha 1s\ndelta 1s\neps 2s")
	newScript := timingFakeScript("new", log, "alpha 1600ms\ndelta 2s\neps 2s", "alpha 1s\ndelta 2100ms\neps 2s")
	for path, script := range map[string]string{old: oldScript, newer: newScript} {
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
			t.Fatal(err)
		}
	}
	var stdout, stderr strings.Builder
	_, errs, projects, _ := compareTargets([]string{project}, old, newer, "", "", "", nil, &stdout, &stderr)
	if errs != 0 {
		t.Fatalf("errors = %d, stderr %q", errs, stderr.String())
	}
	printTimingComparison(&stdout, projects, slowRule{}, nil)
	got := stdout.String()
	if strings.Contains(got, "proj: alpha —") || !strings.Contains(got, "proj: delta —") {
		t.Fatalf("timing report = %q; want delta confirmed and alpha noise omitted", got)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(calls)), "\n"); len(lines) != 4 {
		t.Fatalf("calls = %q, want full old/new then confirmation new/old", calls)
	}
}

func timingFakeScript(name, log, first, second string) string {
	firstArgs := "'" + strings.ReplaceAll(first, "\n", "' '") + "'"
	secondArgs := "'" + strings.ReplaceAll(second, "\n", "' '") + "'"
	return fmt.Sprintf(`#!/bin/sh
counter=%q
call=1
if [ -f "$counter" ]; then call=2; fi
touch "$counter"
printf '%%s %%s\n' %q "$*" >> %q
echo '{"issues":[]}'
echo 'RULE TOTAL' >&2
if [ "$call" = 1 ]; then
  printf '  %%s\n' %s >&2
else
  printf '  %%s\n' %s >&2
fi
echo '  IN FLIGHT' >&2
`, log+"."+name+".count", name, log, firstArgs, secondArgs)
}

func TestParseOldRuleNames(t *testing.T) {
	got, err := parseRuleNames("glint rules\n  alpha  Detects alpha [HIGH]\n  beta  Detects beta [LOW]\n")
	if err != nil || !got["alpha"] || !got["beta"] || got["glint"] {
		t.Fatalf("rule names = %#v, err %v", got, err)
	}
}

func TestRuleTimingComparisonUsesOldRuleList(t *testing.T) {
	old := parseRuleTimings("TIMING\n  RULE TOTAL\n  alpha 5ms\n  (1 rules under 1ms)\n")
	oldRules := map[string]bool{"alpha": true, "beta": true}
	current := map[string]time.Duration{
		"beta":  40 * time.Millisecond, // Present in old rules, folded out of old timings.
		"gamma": 30 * time.Millisecond, // Absent from the old build.
	}
	slower, fastestNew := compareRuleTimings(old, oldRules, current)
	if len(slower) != 0 || fastestNew.name != "gamma" {
		t.Fatalf("comparison = slower %#v, new %#v; want no slower rules and gamma as new", slower, fastestNew)
	}
}

func initConsumerRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitTest(t, repo, "init", "-q")
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, repo, "add", "tracked.txt")
	gitTest(t, repo, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-qm", "init")
	return repo
}

func commitConsumerTreeChange(repo string) error {
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("two\n"), 0o600); err != nil {
		return fmt.Errorf("write changed tree file: %w", err)
	}
	cmd := exec.Command("git", "-C", repo, "add", "tracked.txt")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git add: %s: %w", out, err)
	}
	cmd = exec.Command("git", "-C", repo, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-qm", "next")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git commit: %s: %w", out, err)
	}
	return nil
}

func gitTest(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %s: %v", args, out, err)
	}
}

// writeConsumerRun lays out a root with the given consumer projects, an old
// and a new glint double printing script, and the configuration naming the
// root; it returns the configuration and both binaries.
func writeConsumerRun(t *testing.T, script string, projects ...string) (cfg, old, newer string) {
	t.Helper()
	root := t.TempDir()
	for _, name := range projects {
		project := filepath.Join(root, name)
		if err := os.MkdirAll(project, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bins := t.TempDir()
	old, newer = filepath.Join(bins, "old"), filepath.Join(bins, "new")
	for _, path := range []string{old, newer} {
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
			t.Fatal(err)
		}
	}
	cfg = filepath.Join(bins, "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg, old, newer
}

// A consumer whose packages fail to load makes both glints fail the same
// way; that is an error of the comparison, not "no differences".
func TestConsumerLoadFailureCountsAsError(t *testing.T) {
	loadFails := "#!/bin/sh\necho 'Error: load Go project context: could not import example.com/missing' >&2\nexit 1\n"
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cfg, old, newer := writeConsumerRun(t, loadFails, "alpha", "beta")
	var stdout, stderr strings.Builder
	code := run([]string{"-config", cfg, "-old", old, "-new", newer}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stdout.String(), "2 errors") || !strings.Contains(stderr.String(), "alpha: ") {
		t.Fatalf("code %d, stdout %q, stderr %q: want both load failures counted as errors", code, stdout.String(), stderr.String())
	}
}

// No consumer to compare - an empty root on a host without the copies, or
// -only naming a project that is not there - is an error, while the same
// root with a consumer compares clean.
func TestNoConsumerToCompareIsAnError(t *testing.T) {
	clean := "#!/bin/sh\necho '{\"issues\":[]}'\n"
	for _, tc := range []struct {
		name     string
		projects []string
		args     []string
		code     int
		stderr   string
	}{
		{"empty root", nil, nil, 2, "no consumer projects"},
		{"unknown only", []string{"alpha"}, []string{"-only", "gamma"}, 2, "-only gamma"},
		{"one consumer", []string{"alpha"}, nil, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			t.Chdir(t.TempDir()) // a clean compare writes the run marker of the current directory
			cfg, old, newer := writeConsumerRun(t, clean, tc.projects...)
			var stdout, stderr strings.Builder
			code := run(append([]string{"-config", cfg, "-old", old, "-new", newer}, tc.args...), &stdout, &stderr)
			if code != tc.code || !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("code %d, stdout %q, stderr %q: want code %d with %q", code, stdout.String(), stderr.String(), tc.code, tc.stderr)
			}
		})
	}
}
