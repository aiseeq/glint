package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
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

// fillsCache is the shell line of a glint double that leaves a result cache
// file in GLINT_CACHE_DIR when it runs with the cache, as glint does.
const fillsCache = `case " $* " in *" --no-cache "*) ;; *) [ -z "$GLINT_CACHE_DIR" ] || : > "$GLINT_CACHE_DIR/entry" ;; esac
`

// The new build keeps its result cache apart: a glint run prunes the caches of
// other builds, so a run of the new build in the shared directory would wipe
// the caches the installed glint keeps for every project. The old build fills
// a fresh directory of its own, which the cached run of the new one reads and
// which is gone after the run.
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
	for _, name := range []string{"old", "new"} {
		script := "#!/bin/sh\n" + fillsCache + "printf '%s %s\\n' \"$GLINT_CACHE_DIR\" \"$*\" >> " + filepath.Join(root, name+".env") + "\necho '{\"issues\":[]}'\n"
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
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	calls := map[string][]string{}
	for _, name := range []string{"old", "new"} {
		data, err := os.ReadFile(filepath.Join(root, name+".env"))
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.Contains(line, " check ") {
				calls[name] = append(calls[name], line)
			}
		}
	}
	if len(calls["old"]) != 1 || len(calls["new"]) != 2 {
		t.Fatalf("calls = %q", calls)
	}
	oldDir, oldArgs, _ := strings.Cut(calls["old"][0], " ")
	if filepath.Dir(oldDir) != filepath.Join(userCache, "glint") || filepath.Base(oldDir) == "results" || strings.Contains(oldArgs, "--no-cache") {
		t.Fatalf("installed glint ran as %q, want a fresh cache of its own beside the shared one", calls["old"][0])
	}
	if want := filepath.Join(userCache, "glint", "consumers-new") + " "; !strings.HasPrefix(calls["new"][0], want) || !strings.Contains(calls["new"][0], "--no-cache") {
		t.Fatalf("new glint ran first as %q, want %q without the cache", calls["new"][0], want)
	}
	if cachedDir, cachedArgs, _ := strings.Cut(calls["new"][1], " "); cachedDir != oldDir || strings.Contains(cachedArgs, "--no-cache") {
		t.Fatalf("new glint ran on the cache as %q, want the old glint's cache %s", calls["new"][1], oldDir)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("the old glint's cache is left after the run: %v", err)
	}
}

// The cached run reads the cache the old glint has just filled, not this
// machine's own: on a host without the consumer's cache, or here with none of
// its files, the comparison still runs, and a stale finding from the cache
// fails it.
func TestCachedRunDoesNotNeedTheUserCache(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cachedJSON string
		wantCode   int
		wantDiff   bool
	}{
		{name: "different", cachedJSON: `{"issues":[{"rule":"stale","file":"a.go","line":7,"message":"cached finding"}]}`, wantCode: 2, wantDiff: true},
		{name: "same", cachedJSON: `{"issues":[]}`, wantCode: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			t.Setenv("GLINT_CACHE_DIR", "")
			t.Chdir(t.TempDir())
			root := t.TempDir()
			project := filepath.Join(root, "alpha")
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(root, "old")
			newer := filepath.Join(root, "new")
			oldScript := "#!/bin/sh\n" + fillsCache + "echo '{\"issues\":[]}'\n"
			newScript := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = rules ]; then echo '  known-rule description'; exit 0; fi\ncase \" $* \" in *\" --no-cache \"*) echo '{\"issues\":[]}'; exit 0;; esac\nif [ -f \"$GLINT_CACHE_DIR/entry\" ]; then echo '%s'; else echo 'Error: no cache' >&2; exit 1; fi\n", tc.cachedJSON)
			for path, script := range map[string]string{old: oldScript, newer: newScript} {
				if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // executable test double
					t.Fatal(err)
				}
			}
			cfg := filepath.Join(root, "consumers.txt")
			if err := os.WriteFile(cfg, []byte("root "+root+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr strings.Builder
			code := run([]string{"-config", cfg, "-old", old, "-new", newer}, &stdout, &stderr)
			if code != tc.wantCode || strings.Contains(stdout.String(), "skipped (") || strings.Contains(stdout.String(), "cached findings differ") != tc.wantDiff || tc.wantDiff && !strings.Contains(stdout.String(), project) {
				t.Fatalf("code %d, stdout %q, stderr %q; want code %d and diff %v", code, stdout.String(), stderr.String(), tc.wantCode, tc.wantDiff)
			}
		})
	}
}

// An old glint that leaves no result cache would make the cached run analyze
// everything, a comparison without a cache: that is an error, not a pass.
func TestOldGlintWritingNoCacheIsAnError(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	cfg, old, newer := writeConsumerRun(t, "#!/bin/sh\necho '{\"issues\":[]}'\n", "alpha")
	var stdout, stderr strings.Builder
	code := run([]string{"-config", cfg, "-old", old, "-new", newer}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "wrote no result cache") {
		t.Fatalf("code %d, stdout %q, stderr %q: want the missing cache counted as an error", code, stdout.String(), stderr.String())
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

func TestConfirmationsUseFreshCachesAndSelectedNoCachePolicyNoCache(t *testing.T) {
	assertConfirmationCachePolicy(t, true)
}

func TestConfirmationsUseFreshCachesWithToolCachesOnNoCache(t *testing.T) {
	assertConfirmationCachePolicy(t, false)
}

func assertConfirmationCachePolicy(t *testing.T, noCache bool) {
	t.Helper()
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	var stdout, stderr strings.Builder
	cacheBase := t.TempDir()
	_, errs, projects, _ := compareTargets([]string{project}, old, newer, "", "", "", cacheBase, nil, noCache, &stdout, &stderr)
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
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != 5 {
		t.Fatalf("calls = %q, want full old/new, new on the old one's cache, then confirmation new/old", calls)
	}
	var confirmationDirs []string
	for _, line := range lines[len(lines)-2:] {
		fields := strings.SplitN(line, "|", 3)
		if len(fields) != 3 || fields[1] == "" {
			t.Fatalf("confirmation call = %q, want a fresh GLINT_CACHE_DIR", line)
		}
		gotNoCache := strings.Contains(" "+fields[2]+" ", " --no-cache ")
		if gotNoCache != noCache {
			t.Fatalf("confirmation call = %q, want --no-cache %v", line, noCache)
		}
		if _, err := os.Stat(fields[1]); !os.IsNotExist(err) {
			t.Fatalf("confirmation cache %q was not removed after the check: %v", fields[1], err)
		}
		confirmationDirs = append(confirmationDirs, fields[1])
	}
	if confirmationDirs[0] == confirmationDirs[1] {
		t.Fatalf("confirmation runs shared a cache directory: %q", confirmationDirs)
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
printf '%%s|%%s|%%s\n' %q "$GLINT_CACHE_DIR" "$*" >> %q
case " $* " in *" --no-cache "*) ;; *) [ -z "$GLINT_CACHE_DIR" ] || : > "$GLINT_CACHE_DIR/entry" ;; esac
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

func TestTouchedToolcachePackageUsesNoCache(t *testing.T) {
	stdout, calls := runNoCacheScenario(t, "v1.0.0", true, false)
	assertNoCacheChoice(t, stdout, calls, true)
}

func TestUntouchedToolcachePackagesUseFreshCacheWithoutNoCache(t *testing.T) {
	stdout, calls := runNoCacheScenario(t, "v1.0.0", false, false)
	assertNoCacheChoice(t, stdout, calls, false)
}

func TestEachProjectGetsFreshResultCacheWithoutNoCache(t *testing.T) {
	stdout, calls := runNoCacheScenarioProjects(t, "v1.0.0", false, false, 2)
	if len(calls) != 4 {
		t.Fatalf("new glint calls = %q, want two fresh and two cached runs", calls)
	}
	firstDir, firstArgs, firstEmpty := parseNoCacheCall(t, calls[0])
	secondDir, secondArgs, secondEmpty := parseNoCacheCall(t, calls[2])
	if firstDir == secondDir || firstEmpty != "yes" || secondEmpty != "yes" {
		t.Fatalf("fresh project calls = %q and %q; want distinct empty cache dirs", calls[0], calls[2])
	}
	if strings.Contains(" "+firstArgs+" ", " --no-cache ") || strings.Contains(" "+secondArgs+" ", " --no-cache ") {
		t.Fatalf("tool caches should be enabled: %q, %q (stdout %q)", calls[0], calls[2], stdout)
	}
}

func TestUnknownOldVersionUsesNoCache(t *testing.T) {
	stdout, calls := runNoCacheScenario(t, "v9.9.9", false, false)
	if !strings.Contains(stdout, "old version unknown") {
		t.Fatalf("stdout %q: want fallback reason", stdout)
	}
	assertNoCacheChoice(t, stdout, calls, true)
}

func TestForceNoCacheFlagUsesNoCache(t *testing.T) {
	stdout, calls := runNoCacheScenario(t, "v1.0.0", false, true)
	if !strings.Contains(stdout, "-no-cache forced") {
		t.Fatalf("stdout %q: want forced-choice reason", stdout)
	}
	assertNoCacheChoice(t, stdout, calls, true)
}

func TestViaPassesResolvedToolCachesOnNoCache(t *testing.T) {
	assertViaNoCacheDecision(t, false, false, "on")
}

func TestViaPassesResolvedToolCachesOffNoCache(t *testing.T) {
	assertViaNoCacheDecision(t, true, false, "off")
}

func TestViaNoCacheFlagForcesOffNoCache(t *testing.T) {
	assertViaNoCacheDecision(t, false, true, "off")
}

func assertViaNoCacheDecision(t *testing.T, touchPackage, forceNoCache bool, wantMode string) {
	t.Helper()
	repo := makeViaNoCacheRepo(t, touchPackage)
	old := filepath.Join(repo, "old")
	newer := filepath.Join(repo, "new")
	writeExec(t, old, "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'glint version v1.0.0'; exit 0; fi\n")
	writeExec(t, newer, "#!/bin/sh\necho '{\"issues\":[]}'\n")
	config := filepath.Join(repo, "consumers.txt")
	if err := os.WriteFile(config, []byte("root "+repo+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(repo, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(repo, "graft-args")
	graftScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\n"
	writeExec(t, filepath.Join(binDir, "graft"), graftScript)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(repo)
	args := []string{"-config", config, "-old", old, "-new", newer, "-via", "compare", "-no-mark"}
	if forceNoCache {
		args = append(args, "-no-cache")
	}
	var stdout, stderr strings.Builder
	if code := run(args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "printed no result line") {
		t.Fatalf("run code %d, stdout %q, stderr %q; fake graft should record args then omit its result line", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	gotArgs := string(data)
	if !strings.Contains(gotArgs, "-tool-caches="+wantMode+"\n") {
		t.Fatalf("graft args %q, want -tool-caches=%s", gotArgs, wantMode)
	}
	if !strings.Contains(gotArgs, "-tool-cache-reason=") {
		t.Fatalf("graft args %q, want the decision reason forwarded", gotArgs)
	}
	if forceNoCache && !strings.Contains(gotArgs, "-no-cache=true\n") {
		t.Fatalf("graft args %q, want the forced -no-cache flag forwarded", gotArgs)
	}
}

func TestResolvedToolCachesOnRunsWithoutGitNoCache(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "alpha")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, newer := filepath.Join(root, "old"), filepath.Join(root, "new")
	writeExec(t, old, "#!/bin/sh\nif [ \"$1\" = rules ]; then echo '  known description'; exit 0; fi\n"+fillsCache+"echo '{\"issues\":[]}'\n")
	log := filepath.Join(root, "new.log")
	writeExec(t, newer, "#!/bin/sh\nif [ \"$1\" = check ]; then printf '%s|%s\\n' \"$GLINT_CACHE_DIR\" \"$*\" >> '"+log+"'; fi\necho '{\"issues\":[]}'\n")
	config := filepath.Join(root, "consumers.txt")
	if err := os.WriteFile(config, []byte("root "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noGitDir := filepath.Join(root, "outside-git")
	if err := os.Mkdir(noGitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(noGitDir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	var stdout, stderr strings.Builder
	code := run([]string{"-config", config, "-old", old, "-new", newer, "-no-mark", "-tool-caches=on", "-tool-cache-reason=resolved outside git"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "new glint: resolved outside git") || strings.Contains(stdout.String(), "old version unknown") {
		t.Fatalf("run code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)[0]
	if strings.Contains(" "+first+" ", " --no-cache ") || !strings.Contains(first, "consumers-new-") {
		t.Fatalf("new glint call %q: want enabled tool caches and a fresh result cache", first)
	}
}

func makeViaNoCacheRepo(t *testing.T, touchPackage bool) string {
	t.Helper()
	repo := t.TempDir()
	gitRun := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	gitRun("init", "-q")
	toolPkg := filepath.Join(repo, "pkg", "rules", "external")
	if err := os.MkdirAll(toolPkg, 0o755); err != nil {
		t.Fatal(err)
	}
	toolFile := filepath.Join(toolPkg, "external.go")
	if err := os.WriteFile(toolFile, []byte("package external\nfunc f() { _ = toolcache.New(\"x\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "pkg", "toolcache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "pkg", "toolcache", "cache.go"), []byte("package toolcache\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(repo, "alpha")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun("add", ".")
	gitRun("commit", "-qm", "base")
	gitRun("tag", "v1.0.0")
	if touchPackage {
		if err := os.WriteFile(toolFile, []byte("package external\n// changed\nfunc f() { _ = toolcache.New(\"x\") }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

func writeExec(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // executable test double
		t.Fatal(err)
	}
}

// runNoCacheScenario makes an isolated tagged glint repository and uses
// executable doubles to record the new build's arguments and cache directory.
func runNoCacheScenario(t *testing.T, oldVersion string, touchPackage, force bool) (string, []string) {
	return runNoCacheScenarioProjects(t, oldVersion, touchPackage, force, 1)
}

func runNoCacheScenarioProjects(t *testing.T, oldVersion string, touchPackage, force bool, projectCount int) (string, []string) {
	t.Helper()
	repo := t.TempDir()
	gitRun := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	gitRun("init", "-q")
	toolPackage := filepath.Join(repo, "pkg", "rules", "example")
	if err := os.MkdirAll(toolPackage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolPackage, "tool.go"), []byte("package example\nfunc init() { _ = toolcache.New(\"x\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "pkg", "toolcache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "pkg", "toolcache", "cache.go"), []byte("package toolcache\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range projectCount {
		project := filepath.Join(repo, []string{"alpha", "beta"}[i])
		if err := os.MkdirAll(project, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitRun("add", ".")
	gitRun("commit", "-qm", "base")
	gitRun("tag", "v1.0.0")
	if touchPackage {
		if err := os.WriteFile(filepath.Join(toolPackage, "tool.go"), []byte("package example\n// changed\nfunc init() { _ = toolcache.New(\"x\") }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(repo)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(repo, "user-cache"))
	t.Setenv("GLINT_CACHE_DIR", "")
	log := filepath.Join(repo, "new.log")
	old := filepath.Join(repo, "old")
	newer := filepath.Join(repo, "new")
	oldScript := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'glint version %s'; exit 0; fi\n", oldVersion) + fillsCache + "echo '{\"issues\":[]}'\n"
	newScript := "#!/bin/sh\nif [ \"$1\" = rules ]; then exit 0; fi\nif [ \"$1\" = check ]; then empty=no; [ -z \"$(ls -A \"$GLINT_CACHE_DIR\" 2>/dev/null)\" ] && empty=yes; printf '%s|%s|%s\\n' \"$GLINT_CACHE_DIR\" \"$empty\" \"$*\" >> '" + log + "'; fi\necho '{\"issues\":[]} '\n"
	for path, script := range map[string]string{old: oldScript, newer: newScript} {
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // executable test double
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(repo, "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root "+repo+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-config", cfg, "-old", old, "-new", newer, "-no-mark"}
	if force {
		args = append(args, "-no-cache")
	}
	var stdout, stderr strings.Builder
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("run code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			calls = append(calls, line)
		}
	}
	return stdout.String(), calls
}

func assertNoCacheChoice(t *testing.T, stdout string, calls []string, wantNoCache bool) {
	t.Helper()
	if len(calls) < 2 {
		t.Fatalf("new glint calls = %q, want fresh and cached runs", calls)
	}
	dir, args, empty := parseNoCacheCall(t, calls[0])
	if !strings.HasPrefix(filepath.Base(dir), "consumers-new") {
		t.Fatalf("first new glint call = %q, want its fresh GLINT_CACHE_DIR", calls[0])
	}
	if !wantNoCache && empty != "yes" {
		t.Fatalf("first new glint call = %q, want empty cache on entry", calls[0])
	}
	gotNoCache := strings.Contains(" "+args+" ", " --no-cache ")
	if gotNoCache != wantNoCache {
		t.Fatalf("first new glint call = %q, want --no-cache %v (stdout %q)", calls[0], wantNoCache, stdout)
	}
}

func parseNoCacheCall(t *testing.T, line string) (dir, args, empty string) {
	t.Helper()
	fields := strings.SplitN(line, "|", 3)
	if len(fields) != 3 {
		t.Fatalf("new glint call = %q, want cache dir, emptiness, and arguments", line)
	}
	return fields[0], fields[2], fields[1]
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
	clean := "#!/bin/sh\n" + fillsCache + "echo '{\"issues\":[]}'\n"
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

// hostPathsRun runs -host-paths with the given arguments and returns the
// entries of the file it wrote, comment and empty lines left out.
func hostPathsRun(t *testing.T, args ...string) []string {
	t.Helper()
	inGlintTree(t)
	file := filepath.Join(t.TempDir(), "bin", "consumers.paths")
	var stdout, stderr strings.Builder
	if code := run(append(args, "-host-paths", file), &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var entries []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}
	return entries
}

// inGlintTree makes the current directory a repository with the new glint
// in bin/glint, as graft runs consumers from the glint tree; it returns the
// repository.
func inGlintTree(t *testing.T) string {
	t.Helper()
	repo := initConsumerRepo(t)
	if err := os.MkdirAll(filepath.Join(repo, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "bin", "glint"), []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // an executable test double
		t.Fatal(err)
	}
	t.Chdir(repo)
	return repo
}

// hostHome makes a home directory with glint's user config naming tickets as
// its tickets_dir ("" names none) and the installed glint in bin.
func hostHome(t *testing.T, tickets string) string {
	t.Helper()
	home := t.TempDir()
	hostHomeAt(t, home, tickets)
	return home
}

func hostHomeAt(t *testing.T, home, tickets string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	if err := os.MkdirAll(filepath.Join(home, ".config", "glint"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := "# user config\n"
	if tickets != "" {
		config += "tickets_dir: " + tickets + "\n"
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "glint", "config.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bin", "glint"), []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // an executable test double
		t.Fatal(err)
	}
}

func mkConsumer(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A consumer below the root of its repository goes to the host as the whole
// repository, as its git commands need: projectA/tool is projectA. A consumer
// in no repository goes as itself, and one inside it folds into it. A skipped
// consumer is not sent. The glint user config directory, the consumers config
// and the installed glint (-old's default) are sent too.
func TestHostPathsFoldNestedTargetsAndLeaveSkipped(t *testing.T) {
	home := hostHome(t, "")
	root := filepath.Join(home, "git")
	repo := filepath.Join(root, "projectA")
	mkConsumer(t, filepath.Join(repo, "tool"))
	gitTest(t, repo, "init", "-q")
	mkConsumer(t, filepath.Join(root, "plain"))
	mkConsumer(t, filepath.Join(root, "plain", "inner"))
	mkConsumer(t, filepath.Join(root, "frozen"))
	cfg := filepath.Join(home, ".config", "glint", "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root ~/git\nskip frozen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := hostPathsRun(t, "-config", cfg)
	want := []string{filepath.Join(home, ".config", "glint"), filepath.Join(home, "bin", "glint"), filepath.Join(root, "plain"), repo}
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("host paths = %q, want %q", got, want)
	}
}

// tickets_dir of the user config is read by exception-ticket-closed, so it
// goes to the host; a config without it sends none, and one inside a sent
// directory folds into it.
func TestHostPathsCarryTicketsDir(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tickets func(home string) string
		want    func(home string) []string
	}{
		{"set", func(home string) string { return filepath.Join(home, "git", "tasks", "glint") }, func(home string) []string {
			return []string{filepath.Join(home, "git", "tasks", "glint")}
		}},
		{"inside a consumer", func(home string) string { return filepath.Join(home, "git", "alpha", "tickets") }, func(string) []string { return nil }},
		{"missing directory", func(home string) string { return filepath.Join(home, "nowhere") }, func(string) []string { return nil }},
		{"unset", func(string) string { return "" }, func(string) []string { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tickets := tc.tickets(home)
			hostHomeAt(t, home, tickets)
			if tickets != "" && tc.name != "missing directory" {
				if err := os.MkdirAll(tickets, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			mkConsumer(t, filepath.Join(home, "git", "alpha"))
			cfg := filepath.Join(home, ".config", "glint", "consumers.txt")
			if err := os.WriteFile(cfg, []byte("root "+filepath.Join(home, "git")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			got := hostPathsRun(t, "-config", cfg)
			want := append([]string{filepath.Join(home, ".config", "glint"), filepath.Join(home, "bin", "glint"), filepath.Join(home, "git", "alpha")}, tc.want(home)...)
			slices.Sort(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("host paths = %q, want %q", got, want)
			}
		})
	}
}

// -old names the glint the host runs as the old one: that file is sent, not
// the default; a missing one is an error, as the comparison could not run.
func TestHostPathsCarryOldBinary(t *testing.T) {
	home := hostHome(t, "")
	mkConsumer(t, filepath.Join(home, "git", "alpha"))
	cfg := filepath.Join(home, ".config", "glint", "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root ~/git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(home, "builds", "glint-1.0")
	if err := os.MkdirAll(filepath.Dir(old), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // an executable test double
		t.Fatal(err)
	}
	got := hostPathsRun(t, "-config", cfg, "-old", old)
	if !slices.Contains(got, old) || slices.Contains(got, filepath.Join(home, "bin", "glint")) {
		t.Fatalf("host paths = %q, want %s and not the default old glint", got, old)
	}
	inGlintTree(t)
	var stdout, stderr strings.Builder
	code := run([]string{"-config", cfg, "-old", filepath.Join(home, "missing"), "-host-paths", filepath.Join(t.TempDir(), "p")}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "old binary") {
		t.Fatalf("code %d, stderr %q: want a missing -old to fail", code, stderr.String())
	}
}

// worker pc refuses a go.work use that no entry covers: a use outside the
// consumers goes to the host as its repository.
func TestHostPathsCarryGoWorkUses(t *testing.T) {
	home := hostHome(t, "")
	mkConsumer(t, filepath.Join(home, "git", "alpha"))
	shared := filepath.Join(home, "lib", "shared")
	if err := os.MkdirAll(filepath.Join(shared, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitTest(t, shared, "init", "-q")
	work := "go 1.25\n\nuse (\n\t.\n\t../../lib/shared/pkg\n)\n"
	if err := os.WriteFile(filepath.Join(home, "git", "alpha", "go.work"), []byte(work), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(home, ".config", "glint", "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root ~/git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := hostPathsRun(t, "-config", cfg)
	if !slices.Contains(got, shared) {
		t.Fatalf("host paths = %q, want the go.work use's repository %s", got, shared)
	}
}

// worker pc takes at most 64 entries.
func TestHostPathsRefuseMoreThanWorkerTakes(t *testing.T) {
	home := hostHome(t, "")
	for i := range 64 {
		mkConsumer(t, filepath.Join(home, "git", fmt.Sprintf("p%02d", i)))
	}
	cfg := filepath.Join(home, ".config", "glint", "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root ~/git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inGlintTree(t)
	var stdout, stderr strings.Builder
	code := run([]string{"-config", cfg, "-host-paths", filepath.Join(t.TempDir(), "p")}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "at most 64") {
		t.Fatalf("code %d, stderr %q: want more than 64 entries refused", code, stderr.String())
	}
}

// viaRun runs -via consumers-compare in a clean repository with a graft
// double whose body is graftBody (sh; $SUM is the new glint's SHA-256, $NEW
// its path, $REPO the repository, $LOG a file of its arguments). It returns
// the exit code, the output, the marker state ("" for none) and the log.
func viaRun(t *testing.T, graftBody string, extra ...string) (code int, stdout, stderr, marker, log string) {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	repo := initConsumerRepo(t)
	t.Chdir(repo)
	cfg, old, newer := writeConsumerRun(t, "#!/bin/sh\nexit 3\n", "alpha")
	sum, err := fileSHA256(newer)
	if err != nil {
		t.Fatal(err)
	}
	bins := t.TempDir()
	logFile := filepath.Join(bins, "graft.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + logFile + "\nSUM=" + sum + " NEW=" + newer + " REPO=" + repo + "\n" + graftBody
	if err := os.WriteFile(filepath.Join(bins, "graft"), []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
		t.Fatal(err)
	}
	t.Setenv("PATH", bins+string(os.PathListSeparator)+os.Getenv("PATH"))
	var out, errOut strings.Builder
	code = run(append([]string{"-config", cfg, "-old", old, "-new", newer, "-via", "consumers-compare"}, extra...), &out, &errOut)
	if path, err := consumerMarkerPath(repo); err == nil {
		if data, err := os.ReadFile(path); err == nil {
			marker = strings.TrimSpace(string(data))
		}
	}
	data, _ := os.ReadFile(logFile)
	return code, out.String(), errOut.String(), marker, string(data)
}

// The comparison on the host prints its result line, and the marker is
// written here for the commit and the new glint taken before it was sent;
// the flags but -via reach the task's {args}, and differences (graft fails
// with the line printed) still mark the commit and exit 1.
func TestViaMarksTheSentCommit(t *testing.T) {
	code, stdout, stderr, marker, log := viaRun(t, "echo \"consumers-result: partial $SUM\"\n", "-only", "alpha")
	if code != 0 || marker != "partial" || !strings.Contains(stdout, "consumers-result: partial") {
		t.Fatalf("code %d, marker %q, stdout %q, stderr %q: want the commit marked partial", code, marker, stdout, stderr)
	}
	if !strings.HasPrefix(log, "consumers-compare -- ") || !strings.Contains(log, "-only=alpha") || strings.Contains(log, "-via") {
		t.Fatalf("graft got %q, want consumers-compare -- <flags but -via>", log)
	}
	code, _, stderr, marker, _ = viaRun(t, "echo \"consumers-result: full $SUM\"\nexit 1\n")
	if code != 1 || marker != "full" {
		t.Fatalf("code %d, marker %q, stderr %q: want differences marked full with exit 1", code, marker, stderr)
	}
}

// Nothing is marked for a comparison that did not finish, ran another glint,
// or whose commit, tree or new glint moved while it ran.
func TestViaMarksNothingThatMoved(t *testing.T) {
	for _, tc := range []struct {
		name, body, stderr string
		code               int
	}{
		{"no result line", "echo '1 projects, 0 with differences, 1 errors'\nexit 1\n", "no result line", 2},
		{"another glint", "echo 'consumers-result: full 0123456789abcdef'\n", "ran glint 0123456789ab", 0},
		{"head moved", "echo next > \"$REPO/tracked.txt\"; git -C \"$REPO\" -c user.name=t -c user.email=t@example.com commit -qam next\necho \"consumers-result: full $SUM\"\n", "HEAD moved", 0},
		{"tree changed", "echo dirty > \"$REPO/untracked.txt\"\necho \"consumers-result: full $SUM\"\n", "tree changed", 0},
		{"glint rebuilt", "echo rebuilt >> \"$NEW\"\necho \"consumers-result: full $SUM\"\n", "changed during the comparison", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr, marker, _ := viaRun(t, tc.body)
			if code != tc.code || marker != "" || !strings.Contains(stderr, tc.stderr) {
				t.Fatalf("code %d, marker %q, stdout %q, stderr %q: want code %d, no marker and %q", code, marker, stdout, stderr, tc.code, tc.stderr)
			}
		})
	}
}

// -no-mark, the comparison the host runs, writes no marker and ends with the
// result line naming the glint it ran; without it the comparison marks the
// commit it ran in.
func TestNoMarkPrintsResultLineInsteadOfMarker(t *testing.T) {
	for _, noMark := range []bool{true, false} {
		t.Run(fmt.Sprint("no-mark ", noMark), func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			repo := initConsumerRepo(t)
			t.Chdir(repo)
			cfg, old, newer := writeConsumerRun(t, "#!/bin/sh\n"+fillsCache+"echo '{\"issues\":[]}'\n", "alpha")
			sum, err := fileSHA256(newer)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"-config", cfg, "-old", old, "-new", newer}
			if noMark {
				args = append(args, "-no-mark")
			}
			var stdout, stderr strings.Builder
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
			}
			path, err := consumerMarkerPath(repo)
			if err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(path)
			if hasLine := strings.Contains(stdout.String(), "consumers-result: full "+sum+"\n"); hasLine != noMark || os.IsNotExist(statErr) != noMark {
				t.Fatalf("stdout %q, marker stat %v: want the result line %v and the marker %v", stdout.String(), statErr, noMark, !noMark)
			}
		})
	}
}

// glint on its own tree on the host needs the tree with its .git (an entry
// equal to the root makes worker pc send it so), from whatever directory of
// the tree it starts, the user config and tickets_dir.
func TestSelfHostPathsSendTheTreeWithConfigAndTickets(t *testing.T) {
	home := t.TempDir()
	tickets := filepath.Join(home, "tasks", "glint")
	hostHomeAt(t, home, tickets)
	if err := os.MkdirAll(tickets, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := initConsumerRepo(t)
	sub := filepath.Join(repo, "tools")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	file := filepath.Join(t.TempDir(), "self.paths")
	var stdout, stderr strings.Builder
	if code := run([]string{"-self-paths", file}, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			got = append(got, line)
		}
	}
	top := strings.TrimSpace(gitOutput(t, repo, "rev-parse", "--show-toplevel"))
	want := []string{filepath.Join(home, ".config", "glint"), tickets, top}
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("self paths = %q, want %q", got, want)
	}
}

func gitOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

// A link in a consumer that leads out of it (projectA's docs/tasks to the
// tickets beside the repositories) names a path the host has only when it is
// sent, so its target is an entry; a dangling link, a link inside the tree, a
// link up to a directory holding it, one into another consumer and one out of
// home are not.
func TestHostPathsCarryTargetsOfOutwardLinks(t *testing.T) {
	home := hostHome(t, "")
	repo := filepath.Join(home, "git", "projectA")
	mkConsumer(t, repo)
	gitTest(t, repo, "init", "-q")
	mkConsumer(t, filepath.Join(home, "git", "projectB"))
	tickets := filepath.Join(home, "tasks", "projectA")
	if err := os.MkdirAll(tickets, 0o755); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(home, "notes.md")
	if err := os.WriteFile(notes, []byte("# notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "docs", "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"docs/tasks":    "../../../tasks/projectA",
		"docs/notes.md": notes,
		"docs/gone":     "../../../tasks/missing",
		"docs/here":     "inside",
		"docs/up":       "..",
		"docs/peer":     "../../projectB",
		"docs/python":   "/usr/bin",
	} {
		if err := os.Symlink(target, filepath.Join(repo, link)); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(home, ".config", "glint", "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root ~/git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := hostPathsRun(t, "-config", cfg)
	want := []string{filepath.Join(home, ".config", "glint"), filepath.Join(home, "bin", "glint"), filepath.Join(home, "git", "projectB"), notes, repo, tickets}
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("host paths = %q, want %q", got, want)
	}
}

// -new outside the glint tree is an entry; inside it, it goes with the tree.
func TestHostPathsCarryNewBinaryOutsideTheTree(t *testing.T) {
	home := hostHome(t, "")
	mkConsumer(t, filepath.Join(home, "git", "alpha"))
	cfg := filepath.Join(home, ".config", "glint", "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root ~/git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newer := filepath.Join(home, "builds", "glint-next")
	if err := os.MkdirAll(filepath.Dir(newer), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // an executable test double
		t.Fatal(err)
	}
	if got := hostPathsRun(t, "-config", cfg, "-new", newer); !slices.Contains(got, newer) {
		t.Fatalf("host paths = %q, want %s", got, newer)
	}
	if got := hostPathsRun(t, "-config", cfg); slices.ContainsFunc(got, func(p string) bool { return strings.HasSuffix(p, "/bin/glint") && !strings.HasPrefix(p, home) }) {
		t.Fatalf("host paths = %q: bin/glint of the tree goes with the tree", got)
	}
}

// worker pc clears the environment and keeps HOME: glint on the host reads
// $HOME/.config/glint whatever XDG_CONFIG_HOME is here, so that is the entry,
// and its tickets_dir is the one sent; a different XDG_CONFIG_HOME is said.
func TestHostPathsTakeTheConfigGlintOnTheHostReads(t *testing.T) {
	home := t.TempDir()
	tickets := filepath.Join(home, "tasks", "glint")
	hostHomeAt(t, home, tickets)
	if err := os.MkdirAll(tickets, 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, "glint"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "glint", "config.yaml"), []byte("tickets_dir: "+filepath.Join(elsewhere, "t")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", elsewhere)
	mkConsumer(t, filepath.Join(home, "git", "alpha"))
	cfg := filepath.Join(home, ".config", "glint", "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root ~/git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inGlintTree(t)
	file := filepath.Join(t.TempDir(), "p")
	var stdout, stderr strings.Builder
	if code := run([]string{"-config", cfg, "-host-paths", file}, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), filepath.Join(home, ".config", "glint")+"\n") || !strings.Contains(string(data), tickets+"\n") || strings.Contains(string(data), elsewhere) {
		t.Fatalf("host paths %q: want %s/.config/glint and its tickets_dir, not %s", data, home, elsewhere)
	}
	if !strings.Contains(stderr.String(), "XDG_CONFIG_HOME") {
		t.Fatalf("stderr %q: want the differing config directory said", stderr.String())
	}
}

// -via with -host-paths writes the list for the same -config, -old, -new and
// -only as the comparison gets, before graft sends it: worker pc reads the
// file when graft starts the step.
func TestViaWritesHostPathsOfItsOwnArgumentsFirst(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	repo := initConsumerRepo(t)
	t.Chdir(repo)
	cfg, old, newer := writeConsumerRun(t, "#!/bin/sh\nexit 3\n", "alpha", "beta")
	sum, err := fileSHA256(newer)
	if err != nil {
		t.Fatal(err)
	}
	paths := filepath.Join(t.TempDir(), "consumers.paths")
	bins := t.TempDir()
	logFile := filepath.Join(bins, "graft.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + logFile + "\ncat " + paths + " >> " + logFile + "\necho 'consumers-result: partial " + sum + "'\n"
	if err := os.WriteFile(filepath.Join(bins, "graft"), []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
		t.Fatal(err)
	}
	t.Setenv("PATH", bins+string(os.PathListSeparator)+os.Getenv("PATH"))
	var stdout, stderr strings.Builder
	code := run([]string{"-config", cfg, "-old", old, "-new", newer, "-only", "alpha", "-via", "consumers-compare", "-host-paths", paths}, &stdout, &stderr)
	data, _ := os.ReadFile(logFile)
	log := string(data)
	if code != 0 || strings.Contains(log, "-host-paths") || !strings.Contains(log, "/alpha\n") || strings.Contains(log, "/beta\n") || !strings.Contains(log, old+"\n") || !strings.Contains(log, newer+"\n") {
		t.Fatalf("code %d, stderr %q, graft saw %q: want the list of alpha, -old and -new written before graft, without -host-paths in its args", code, stderr.String(), log)
	}
}

func TestParseCacheReuseSumsRootsAndSkipsTheKeyLine(t *testing.T) {
	report := "result cache key: rule fingerprints (core 6ab9c93e)\n" +
		"result cache /p/alpha: 3 of 5 files unchanged, project rules 2 cached, 7 rerun\n" +
		"result cache /p/alpha/tool: 1 of 2 files unchanged, project rules 0 cached, 4 rerun\n"
	got, err := parseCacheReuse(report)
	if want := (cacheReuse{roots: 2, files: 4, analyzed: 7, rulesCached: 2, rulesRerun: 11}); err != nil || got != want {
		t.Fatalf("reuse = %+v, %v; want %+v", got, err, want)
	}
}

// A cached run that took nothing from the old glint's cache proves nothing by
// equal findings: the comparison says it is blind, without failing (a release
// that changes the core of the key misses by design); one that took files
// says how much.
func TestCachedRunSaysWhatItReused(t *testing.T) {
	for _, tc := range []struct {
		name, reuse string
		blind       bool
	}{
		{"nothing", "0 of 3 files unchanged, project rules 0 cached, 5 rerun", true},
		{"files", "3 of 3 files unchanged, project rules 0 cached, 5 rerun", false},
		{"project rules", "0 of 3 files unchanged, project rules 5 cached, 0 rerun", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			t.Chdir(t.TempDir())
			script := "#!/bin/sh\n" + fillsCache + "echo '{\"issues\":[]}'\ncase \" $* \" in *\" --no-cache \"*) ;; *) echo \"result cache $PWD: " + tc.reuse + "\" >&2;; esac\n"
			cfg, old, newer := writeConsumerRun(t, script, "alpha")
			var stdout, stderr strings.Builder
			code := run([]string{"-config", cfg, "-old", old, "-new", newer}, &stdout, &stderr)
			if code != 0 || !strings.Contains(stdout.String(), "alpha: cached run: "+tc.reuse) || strings.Contains(stdout.String(), "cache comparison blind: nothing reused") != tc.blind {
				t.Fatalf("code %d, stdout %q, stderr %q: want the reuse said and blind %v", code, stdout.String(), stderr.String(), tc.blind)
			}
		})
	}
}

// In a linked worktree the root entry is the worktree itself: worker pc sends
// a root entry's gitdir and common directory with it (pcReadGitWorktreeMetadata),
// so the main repository is no entry of its own.
func TestSelfHostPathsInLinkedWorktreeNameOnlyTheWorktree(t *testing.T) {
	home := t.TempDir()
	hostHomeAt(t, home, "")
	repo := initConsumerRepo(t)
	worktree := filepath.Join(t.TempDir(), "wt")
	gitTest(t, repo, "worktree", "add", "-q", worktree)
	t.Chdir(worktree)
	file := filepath.Join(t.TempDir(), "self.paths")
	var stdout, stderr strings.Builder
	if code := run([]string{"-self-paths", file}, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	top := strings.TrimSpace(gitOutput(t, worktree, "rev-parse", "--show-toplevel"))
	mainTop := strings.TrimSpace(gitOutput(t, repo, "rev-parse", "--show-toplevel"))
	if !strings.Contains(string(data), top+"\n") || strings.Contains(string(data), mainTop+"\n") || strings.Contains(string(data), mainTop+"/.git") {
		t.Fatalf("self paths %q: want the worktree %s and not the main repository %s", data, top, mainTop)
	}
}
