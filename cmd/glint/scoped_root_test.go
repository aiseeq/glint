package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// Paths under one .glint.yaml form one root walked over scopes; a path that no
// configuration governs stays a root of its own.
func TestAnalysisRootsGroupPathsByConfiguration(t *testing.T) {
	parent := t.TempDir()
	project := filepath.Join(parent, "project")
	writeModuleFile(t, project, ".glint.yaml", "version: 1\n")
	for _, dir := range []string{"cmd/a", "cmd/b", "internal/x", "internal/x/y"} {
		writeModuleFile(t, project, dir+"/f.go", "package f\n")
	}
	loose := filepath.Join(parent, "loose")
	writeModuleFile(t, loose, "f.go", "package f\n")

	roots, err := analysisRoots([]string{
		filepath.Join(project, "cmd/a"), filepath.Join(project, "internal/x/y"), loose,
		filepath.Join(project, "internal/x"), filepath.Join(project, "cmd/b"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(roots))
	for _, r := range roots {
		got = append(got, fmt.Sprintf("%s %v", r.dir, r.walkScopes()))
	}
	want := []string{
		fmt.Sprintf("%s [%s %s %s]", project, filepath.Join(project, "cmd/a"), filepath.Join(project, "internal/x"), filepath.Join(project, "cmd/b")),
		loose + " []",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	whole, err := analysisRoots([]string{filepath.Join(project, "cmd/a"), project})
	if err != nil {
		t.Fatal(err)
	}
	if len(whole) != 1 || whole[0].walkScopes() != nil {
		t.Fatalf("the configuration directory itself must widen the walk to the whole root, got %+v", whole)
	}
}

// Repro from a real project: make glint passed every package directory as its
// own path. Each was a root of its own: findings named files relative to the
// path ("main.go" twelve times), and a project rule judging one path did not
// see the tests of another that call its exports.
func TestScopedRootNamesFilesFromConfigurationAndSeesEveryPath(t *testing.T) {
	project := t.TempDir()
	writeModuleFile(t, project, "go.mod", "module example.com/scoped\n\ngo 1.22\n")
	writeModuleFile(t, project, ".glint.yaml", "version: 1\n")
	writeModuleFile(t, project, "internal/harness/harness.go", `package harness

// Run replays a window for a test.
func Run() error { return nil }

// Dead is called by nobody.
func Dead() error { return nil }
`)
	writeModuleFile(t, project, "bot/bot.go", "package bot\n\n// Name is the bot's name.\nfunc Name() string { return \"b\" }\n")
	writeModuleFile(t, project, "bot/bot_test.go", `package bot

import (
	"testing"

	"example.com/scoped/internal/harness"
)

func TestRun(t *testing.T) {
	if err := harness.Run(); err != nil {
		t.Fatal(err)
	}
	_ = Name()
}
`)
	withFlags(t, "", "unused-internal-export")
	roots, err := analysisRoots([]string{filepath.Join(project, "internal/harness"), filepath.Join(project, "bot")})
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 {
		t.Fatalf("got %d roots, want one", len(roots))
	}
	cfg, enabledRules, err := loadConfig(roots[0].dir)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), roots[0], cfg, enabledRules, false)
	if err != nil {
		t.Fatal(err)
	}
	rules.ResetState(enabledRules)
	violations, err := analyzeProject(prepared.contexts, enabledRules, cfg, prepared.project, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, v := range violations {
		found = append(found, fmt.Sprintf("%s:%d %s", v.File, v.Line, v.Context["symbol"]))
	}
	sort.Strings(found)
	if want := []string{"internal/harness/harness.go:7 Dead"}; strings.Join(found, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", found, want)
	}
}

// instructionSizeFiles runs instruction-size on the paths as glint check
// would and returns the files it reports.
func instructionSizeFiles(t *testing.T, paths ...string) []string {
	t.Helper()
	withFlags(t, "", "instruction-size")
	roots, err := analysisRoots(paths)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, root := range roots {
		cfg, enabledRules, err := loadConfig(root.dir)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), root, cfg, enabledRules, false)
		if err != nil {
			t.Fatal(err)
		}
		rules.ResetState(enabledRules)
		violations, err := analyzeProject(prepared.contexts, enabledRules, cfg, prepared.project, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range violations {
			found = append(found, v.File)
		}
	}
	sort.Strings(found)
	return found
}

// The instruction files of a home directory are no project: glint check
// walks a directory with no .glint.yaml and no git into its hidden .claude,
// and takes a single file as the one file to judge, even one .gitignore
// leaves out.
func TestCheckTakesInstructionFilesOutsideAProject(t *testing.T) {
	big := strings.Repeat("a", 30000)
	home := t.TempDir()
	writeModuleFile(t, home, ".claude/CLAUDE.md", big)
	writeModuleFile(t, home, ".claude/rules/api/db.md", big)
	writeModuleFile(t, home, ".claude/skills/deploy/SKILL.md", big)
	writeModuleFile(t, home, ".claude/notes.md", big)
	if got, want := instructionSizeFiles(t, filepath.Join(home, ".claude")), []string{"CLAUDE.md", "rules/api/db.md", "skills/deploy/SKILL.md"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}

	work := t.TempDir()
	writeModuleFile(t, work, "CLAUDE.md", big)
	writeModuleFile(t, work, "other/CLAUDE.md", big)
	if got := instructionSizeFiles(t, filepath.Join(work, "CLAUDE.md")); strings.Join(got, ",") != "CLAUDE.md" {
		t.Fatalf("a named file must be the only file judged, got %v", got)
	}

	repo := t.TempDir()
	writeModuleFile(t, repo, ".git/HEAD", "ref: refs/heads/main\n")
	writeModuleFile(t, repo, ".gitignore", "CLAUDE.local.md\n")
	writeModuleFile(t, repo, "CLAUDE.local.md", big)
	if got := instructionSizeFiles(t, filepath.Join(repo, "CLAUDE.local.md")); strings.Join(got, ",") != "CLAUDE.local.md" {
		t.Fatalf("a named file is judged even when .gitignore leaves it out, got %v", got)
	}
}

// Repro from a real project: a commit gate passed glint the changed files
// only, and a rule comparing a file with the rest of the project saw just
// them — the middleware reading the bearer token was not among them, so a
// test sending one was reported against a cookie-only server. The rules
// see every file of the root; only the run's files are reported.
func TestScopedRunComparesWithTheWholeRoot(t *testing.T) {
	project := t.TempDir()
	writeModuleFile(t, project, "go.mod", "module example.com/scoped\n\ngo 1.22\n")
	writeModuleFile(t, project, ".glint.yaml", "version: 1\n")
	writeModuleFile(t, project, "mw/auth.go", `package mw

import "net/http"

// Session reads the session cookie.
func Session(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}
`)
	writeModuleFile(t, project, "mw/auth_test.go", `package mw

import (
	"net/http/httptest"
	"testing"
)

func TestSession(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer token")
	if _, err := Session(req); err == nil {
		t.Fatal("no cookie")
	}
}
`)
	bearer := `package mw

import "net/http"

// Bearer reads the token of the Authorization header.
func Bearer(r *http.Request) string { return r.Header.Get("Authorization") }
`
	withFlags(t, "", "test-auth-scheme-drift")
	run := func() []string {
		roots, err := analysisRoots([]string{filepath.Join(project, "mw/auth.go"), filepath.Join(project, "mw/auth_test.go")})
		if err != nil {
			t.Fatal(err)
		}
		cfg, enabledRules, err := loadConfig(roots[0].dir)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), roots[0], cfg, enabledRules, false)
		if err != nil {
			t.Fatal(err)
		}
		rules.ResetState(enabledRules)
		violations, _, err := analyzePrepared(prepared, enabledRules, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var found []string
		for _, v := range violations {
			found = append(found, fmt.Sprintf("%s:%d", v.File, v.Line))
		}
		return found
	}

	if found := run(); strings.Join(found, ",") != "mw/auth_test.go:10" {
		t.Fatalf("a cookie-only server: got %v, want mw/auth_test.go:10", found)
	}
	writeModuleFile(t, project, "mw/bearer.go", bearer)
	if found := run(); len(found) != 0 {
		t.Fatalf("the server reads the header outside the run: got %v, want nothing", found)
	}
}

// Repro from a real project: glint run on one package reported its exports
// as unused, and the tests of another package using them were not in the run.
// The project rules analyze the whole root; only the run's files are
// reported.
func TestScopedRunAnalyzesTheProjectAsAWhole(t *testing.T) {
	project := t.TempDir()
	writeModuleFile(t, project, "go.mod", "module example.com/scoped\n\ngo 1.22\n")
	writeModuleFile(t, project, ".glint.yaml", "version: 1\n")
	writeModuleFile(t, project, "internal/money/money.go", `package money

// Cents converts an amount to cents.
func Cents(amount int64) int64 { return amount * 100 }

// Dead is called by nobody.
func Dead() int64 { return 0 }
`)
	writeModuleFile(t, project, "internal/billing/billing.go", `package billing

// Dead is called by nobody either.
func Dead() int64 { return 1 }
`)
	writeModuleFile(t, project, "internal/billing/billing_test.go", `package billing

import (
	"testing"

	"example.com/scoped/internal/money"
)

func TestCents(t *testing.T) {
	if money.Cents(3) != 300 {
		t.Fatal("cents")
	}
}
`)
	withFlags(t, "", "unused-internal-export")
	roots, err := analysisRoots([]string{filepath.Join(project, "internal/money")})
	if err != nil {
		t.Fatal(err)
	}
	cfg, enabledRules, err := loadConfig(roots[0].dir)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), roots[0], cfg, enabledRules, false)
	if err != nil {
		t.Fatal(err)
	}
	rules.ResetState(enabledRules)
	violations, _, err := analyzePrepared(prepared, enabledRules, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, v := range violations {
		found = append(found, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	if want := "internal/money/money.go:7"; strings.Join(found, ",") != want {
		t.Fatalf("got %v, want %s", found, want)
	}
}

// A rule that gathered the root file by file would see only the run's files
// when glint runs on some of them: every rule that keeps state across files
// learns the root up front.
func TestStatefulRulesLearnTheRootUpFront(t *testing.T) {
	for _, rule := range rules.All() {
		if _, stateful := rule.(rules.StatefulRule); !stateful {
			continue
		}
		if _, projectFiles := rule.(rules.ProjectFilesRule); !projectFiles {
			t.Errorf("rule %s keeps state across files without UseProjectFiles", rule.Name())
		}
	}
}

// Repro from a real project: the root keeps snapshots of old programs as a
// module of their own that no longer builds, and a run over the packages of
// the main module failed loading it. A run loads only the modules its Go
// files are in.
func TestScopedRunLoadsOnlyTheModulesOfTheRun(t *testing.T) {
	project := t.TempDir()
	writeModuleFile(t, project, "go.mod", "module example.com/scoped\n\ngo 1.22\n")
	writeModuleFile(t, project, ".glint.yaml", "version: 1\n")
	writeModuleFile(t, project, "internal/money/money.go", "package money\n\n// Dead is called by nobody.\nfunc Dead() int64 { return 0 }\n")
	writeModuleFile(t, project, "old/go.mod", "module old.invalid\n\ngo 1.22\n")
	writeModuleFile(t, project, "old/bot/bot.go", "package bot\n\nimport \"example.org/gone/lib\"\n\nfunc Run() { lib.Start() }\n")
	withFlags(t, "", "unused-internal-export")
	roots, err := analysisRoots([]string{filepath.Join(project, "internal/money")})
	if err != nil {
		t.Fatal(err)
	}
	cfg, enabledRules, err := loadConfig(roots[0].dir)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), roots[0], cfg, enabledRules, false)
	if err != nil {
		t.Fatal(err)
	}
	rules.ResetState(enabledRules)
	violations, _, err := analyzePrepared(prepared, enabledRules, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 || violations[0].File != "internal/money/money.go" {
		t.Fatalf("got %v, want the unused export of the run", violations)
	}
}
