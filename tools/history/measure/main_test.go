package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/output"
)

// gitRepo makes a repository with one commit per committer date.
func gitRepo(t *testing.T, dates ...string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	git := func(env []string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(nil, "init", "-q")
	var hashes []string
	for i, date := range dates {
		file := filepath.Join(dir, "a.go")
		if err := os.WriteFile(file, []byte("package a\n"+strings.Repeat("// line\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
		env := []string{"GIT_COMMITTER_DATE=" + date, "GIT_AUTHOR_DATE=" + date,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t"}
		git(env, "add", "-A")
		git(env, "commit", "-qm", date)
		hashes = append(hashes, git(nil, "rev-parse", "HEAD"))
	}
	return dir, hashes
}

func TestSliceCommitsTakesTheLastCommitOfEachInterval(t *testing.T) {
	repo, hashes := gitRepo(t,
		"2026-01-01T10:00:00+02:00",
		"2026-01-02T10:00:00+02:00",
		"2026-01-21T10:00:00+02:00",
		"2026-01-22T10:00:00+02:00")
	slices, err := sliceCommits(repo, 14)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range slices {
		got = append(got, s.hash+" "+s.date.Format("2006-01-02"))
	}
	want := []string{hashes[1] + " 2026-01-02", hashes[3] + " 2026-01-22"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("slices = %v, want %v", got, want)
	}
}

func TestSummarizeCountsNonTestGoFindings(t *testing.T) {
	report := &output.JSONReport{
		Stats: output.JSONStats{PackagesSkipped: 2, RulesRun: 9},
		Issues: []output.JSONIssue{
			{Rule: "b", Category: "patterns", Severity: "high", File: "x.go"},
			{Rule: "a", Category: "patterns", Severity: "low", File: "x.go"},
			{Rule: "c", Category: "security", Severity: "critical", File: "y.go"},
			{Rule: "a", Category: "patterns", Severity: "low", File: "y.go"},
			{Rule: "b", Category: "patterns", Severity: "high", File: "y.go"},
			{Rule: "z", Category: "patterns", Severity: "high", File: "x_test.go"},
			{Rule: "z", Category: "patterns", Severity: "high", File: "web/app.ts"},
		},
	}
	m := summarize(report, 7)
	got, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// Ties keep the order rules first appear in; 3 heavy findings in 7
	// lines are 428.571... per kloc.
	want := `{"total_go":5,"by_severity":{"critical":1,"high":2,"low":2,"medium":0},` +
		`"by_category":{"patterns":4,"security":1},"top_rules":{"b":2,"a":2,"c":1},` +
		`"packages_skipped":2,"rules_run":9,"per_kloc_total":714.29,"per_kloc_crit_high":428.57}`
	if string(got) != want {
		t.Errorf("summary\n got %s\nwant %s", got, want)
	}
	if m := summarize(report, 0); m.PerKlocTotal != nil || m.PerKlocCritHigh != nil {
		t.Error("a tree without Go lines has no per-kloc values")
	}
}

func TestTopRulesKeepsFifteen(t *testing.T) {
	var r rankedCounts
	for i := range 20 {
		r = r.add(string(rune('a' + i)))
	}
	r = r.add("t")
	top := r.top(15)
	if len(top) != 15 || top[0].rule != "t" || top[1].rule != "a" {
		t.Errorf("top = %v", top)
	}
}

func TestCountLinesCountsALastLineWithoutNewline(t *testing.T) {
	for in, want := range map[string]int{"": 0, "a\n": 1, "a\nb": 2, "\n\n": 2} {
		if got := countLines([]byte(in)); got != want {
			t.Errorf("countLines(%q) = %d, want %d", in, got, want)
		}
	}
}

// A rule that crashes glint on a slice is disabled for that slice, and the
// slice is measured without it.
func TestAnalyzeSliceDisablesACrashingRule(t *testing.T) {
	repo, hashes := gitRepo(t, "2026-01-01T10:00:00Z")
	report := `{"stats":{"rulesRun":3},"issues":[{"rule":"ok-rule","category":"patterns","severity":"high","file":"a.go","line":1}]}`
	glint := filepath.Join(t.TempDir(), "glint")
	script := `#!/bin/sh
if [ "$1" = rules ]; then printf '[naming]\n  bad-rule   crashes [LOW]\n'; exit 0; fi
grep -q 'bad-rule:' .glint.yaml 2>/dev/null || { echo 'panic: rule "bad-rule" crashed' >&2; exit 3; }
echo '` + report + `'
`
	if err := os.WriteFile(glint, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	rec, err := analyzeSlice(repo, hashes[0], glint)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.DisabledRules) != 1 || rec.DisabledRules[0] != "bad-rule" || rec.Error != "" {
		t.Fatalf("record = %+v", rec)
	}
	if rec.metrics == nil || rec.TotalGo != 1 || rec.BySeverity["high"] != 1 || rec.Sloc != 1 {
		t.Errorf("metrics = %+v", rec.metrics)
	}
}

func TestAnalyzeSliceRecordsAFailedRun(t *testing.T) {
	repo, hashes := gitRepo(t, "2026-01-01T10:00:00Z")
	glint := filepath.Join(t.TempDir(), "glint")
	if err := os.WriteFile(glint, []byte("#!/bin/sh\necho broken; exit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec, err := analyzeSlice(repo, hashes[0], glint)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Error != "json_parse_failed" || rec.StderrTail != "broken\n" || rec.GlintExit != 2 || rec.metrics != nil {
		t.Errorf("record = %+v", rec)
	}
}
