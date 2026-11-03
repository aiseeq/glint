package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// A path outside a repository is a state the caller has to react to, not a
// failure: reporting it as an error made `glint fix` unusable there.
func TestUnrecoverableTargetsOutsideRepository(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n"), 0o644))

	targets, err := NewEngine(NewRegistry(), true).UnrecoverableTargets(root, []*Fix{{File: "a.go"}})
	require.NoError(t, err)
	assert.Equal(t, Unrecoverable{Untracked: []string{"a.go"}}, targets)
}

func gitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "glint@example.com"},
		{"config", "user.name", "glint"},
		{"add", "-A"},
		{"commit", "--allow-empty", "-m", "base"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		require.NoError(t, cmd.Run(), "git %v", args)
	}
	return root
}

// git runs with its own identity: a submodule clone has no local config, and
// the machine's global one may be missing.
func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.email=glint@example.com", "-c", "user.name=glint"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

// A nested repository or a submodule answers for its own files: the outer
// repository sees the nested file as part of an untracked directory, and a
// submodule's edit only as a changed submodule.
func TestUnrecoverableTargetsAsksTheRepositoryHoldingTheFile(t *testing.T) {
	inner := gitRepo(t, map[string]string{"i.go": "package i\n"})
	sub := gitRepo(t, map[string]string{"s.go": "package s\n"})
	root := gitRepo(t, map[string]string{"a.go": "package a\n"})
	require.NoError(t, os.Rename(inner, filepath.Join(root, "inner")))
	git(t, root, "-c", "protocol.file.allow=always", "submodule", "add", sub, "sm")
	git(t, root, "commit", "-m", "submodule")
	for _, name := range []string{"inner/i.go", "sm/s.go"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte("package x\n\nvar UserWork = 1\n"), 0o644))
	}

	engine := NewEngine(NewRegistry(), false)
	targets, err := engine.UnrecoverableTargets(root, []*Fix{{File: "inner/i.go"}, {File: "sm/s.go"}, {File: "a.go"}})
	require.NoError(t, err)
	assert.Equal(t, Unrecoverable{Uncommitted: []string{"inner/i.go", "sm/s.go"}}, targets)

	git(t, filepath.Join(root, "inner"), "commit", "-am", "work")
	git(t, filepath.Join(root, "sm"), "commit", "-am", "work")
	targets, err = engine.UnrecoverableTargets(root, []*Fix{{File: "inner/i.go"}, {File: "sm/s.go"}})
	require.NoError(t, err)
	assert.Equal(t, Unrecoverable{}, targets, "committed in their own repositories, the files can be given back")
}

// Any uncommitted file used to stop every fix, so a ticket being written in
// docs/tasks kept fixes to clean, committed code from being applied.
func TestUnrecoverableTargetsNamesOnlyFilesTheFixesChange(t *testing.T) {
	root := gitRepo(t, map[string]string{
		"clean.go":    "package a\n",
		"edited.go":   "package a\n",
		"staged.go":   "package a\n",
		"docs/old.md": "ticket\n",
	})
	write := func(name, content string) {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	write("edited.go", "package a\n\nvar x = 1\n")
	write("staged.go", "package a\n\nvar y = 1\n")
	write("sub dir/new*.go", "package b\n")
	write("docs/old.md", "ticket, edited\n")
	write("docs/tasks/new.md", "ticket\n")
	// A user who hides untracked files from status still has them guarded.
	for _, args := range [][]string{{"add", "staged.go"}, {"config", "status.showUntrackedFiles", "no"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		require.NoError(t, cmd.Run(), "git %v", args)
	}

	engine := NewEngine(NewRegistry(), false)
	fixes := []*Fix{
		{File: filepath.Join(root, "clean.go")},
		{File: filepath.Join(root, "edited.go")},
		{File: "staged.go"},
		{File: filepath.Join(root, "sub dir", "new*.go")},
	}
	targets, err := engine.UnrecoverableTargets(root, fixes)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{filepath.Join(root, "edited.go"), "staged.go", filepath.Join(root, "sub dir", "new*.go")}, targets.Uncommitted)
	assert.Empty(t, targets.Untracked)

	targets, err = engine.UnrecoverableTargets(root, fixes[:1])
	require.NoError(t, err)
	assert.Equal(t, Unrecoverable{}, targets)
}

// A project root below the repository top names targets as its fixes do:
// relative ones from the root, not from the top git prints paths from.
func TestUnrecoverableTargetsFromNestedRoot(t *testing.T) {
	root := gitRepo(t, map[string]string{"svc/a.go": "package a\n", "svc/b.go": "package a\n"})
	for _, name := range []string{"a.go", "b.go"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, "svc", name), []byte("package a\n\nvar x = 1\n"), 0o644))
	}

	targets, err := NewEngine(NewRegistry(), false).UnrecoverableTargets(filepath.Join(root, "svc"), []*Fix{{File: filepath.Join(root, "svc", "a.go")}, {File: "b.go"}})
	require.NoError(t, err)
	assert.Equal(t, Unrecoverable{Uncommitted: []string{filepath.Join(root, "svc", "a.go"), "b.go"}}, targets)
}

// A fix writes through a symlink: the committed link looked clean to git
// while the file it leads to held uncommitted work, or lay outside the
// repository where git cannot give it back at all.
func TestUnrecoverableTargetsFollowsSymlinks(t *testing.T) {
	root := gitRepo(t, map[string]string{"other/real.go": "package a\n", "mod/clean.go": "package a\n"})
	outside := filepath.Join(t.TempDir(), "outside.go")
	require.NoError(t, os.WriteFile(outside, []byte("package a\n"), 0o644))
	require.NoError(t, os.Symlink("../other/real.go", filepath.Join(root, "mod", "inner.go")))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "mod", "outer.go")))
	require.NoError(t, os.Symlink("clean.go", filepath.Join(root, "mod", "relinked.go")))
	cmd := exec.Command("git", "add", "-A")
	cmd.Dir = root
	require.NoError(t, cmd.Run())
	cmd = exec.Command("git", "commit", "-m", "links")
	cmd.Dir = root
	require.NoError(t, cmd.Run())

	require.NoError(t, os.WriteFile(filepath.Join(root, "other", "real.go"), []byte("package a\n\nvar UserWork = 1\n"), 0o644))
	require.NoError(t, os.Remove(filepath.Join(root, "mod", "relinked.go")))
	require.NoError(t, os.Symlink("../other/real.go", filepath.Join(root, "mod", "relinked.go")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "other", "real.go"), []byte("package a\n"), 0o644))

	mod := filepath.Join(root, "mod")
	engine := NewEngine(NewRegistry(), false)
	targets, err := engine.UnrecoverableTargets(mod, []*Fix{{File: "outer.go"}, {File: "relinked.go"}, {File: "clean.go"}})
	require.NoError(t, err)
	assert.Equal(t, Unrecoverable{Uncommitted: []string{"relinked.go"}, Untracked: []string{"outer.go"}}, targets, "a retargeted link and a target outside the repository")

	require.NoError(t, os.WriteFile(filepath.Join(root, "other", "real.go"), []byte("package a\n\nvar UserWork = 1\n"), 0o644))
	targets, err = engine.UnrecoverableTargets(mod, []*Fix{{File: "inner.go"}})
	require.NoError(t, err)
	assert.Equal(t, Unrecoverable{Uncommitted: []string{"inner.go"}}, targets, "a committed link to a file with uncommitted work")
}

// Target names reach git literally: a clean "x*.go" is not dirtied by an
// edited xy.go its name would match as a pattern.
func TestUnrecoverableTargetsMatchesNamesLiterally(t *testing.T) {
	root := gitRepo(t, map[string]string{"x*.go": "package a\n", "xy.go": "package a\n", "old.go": "package a\n"})
	require.NoError(t, os.WriteFile(filepath.Join(root, "xy.go"), []byte("package a\n\nvar x = 1\n"), 0o644))
	cmd := exec.Command("git", "mv", "old.go", "renamed.go")
	cmd.Dir = root
	require.NoError(t, cmd.Run())
	require.NoError(t, os.WriteFile(filepath.Join(root, "old.go"), []byte("package a\n"), 0o644))

	targets, err := NewEngine(NewRegistry(), false).UnrecoverableTargets(root, []*Fix{{File: "x*.go"}, {File: "renamed.go"}, {File: "old.go"}})
	require.NoError(t, err)
	assert.Equal(t, Unrecoverable{Uncommitted: []string{"old.go", "renamed.go"}}, targets, "both sides of a staged rename are uncommitted, a pattern-like name is literal")
}

func interfaceAnyViolation(line, column int) *core.Violation {
	return &core.Violation{Rule: "interface-any", File: "rule.go", Line: line, Column: column}
}

func TestInterfaceAnyFixer(t *testing.T) {
	ctx := fixerContext(t, `package sample

func foo(x interface{}) {}

var data map[string]interface{}

func bar() interface{} { return "interface{}" }

func baz(a interface{}, b interface{ }) {}
`)

	tests := []struct {
		name         string
		line, column int
		oldText      string
	}{
		{"parameter", 3, 12, "interface{}"},
		{"map value", 5, 21, "interface{}"},
		{"result", 7, 12, "interface{}"},
		{"second of a line", 9, 27, "interface{ }"},
	}

	fixer := NewInterfaceAnyFixer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixes := fixer.GenerateFix(ctx, interfaceAnyViolation(tt.line, tt.column))
			require.Len(t, fixes, 1)
			assert.Equal(t, tt.oldText, fixes[0].OldText)
			assert.Equal(t, "any", fixes[0].NewText)
			assert.Equal(t, tt.column, fixes[0].StartCol)
		})
	}

	// The column of the string literal holds no interface type.
	assert.Empty(t, fixer.GenerateFix(ctx, interfaceAnyViolation(7, 33)))
}

func TestInterfaceAnyFixerCanFix(t *testing.T) {
	fixer := NewInterfaceAnyFixer()

	tests := []struct {
		name      string
		violation *core.Violation
		expected  bool
	}{
		{"interface-any rule", interfaceAnyViolation(1, 5), true},
		{"no column", &core.Violation{Rule: "interface-any", Line: 1}, false},
		{"other rule", &core.Violation{Rule: "other-rule", Line: 1, Column: 5}, false},
		{"empty rule", &core.Violation{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fixer.CanFix(tt.violation); got != tt.expected {
				t.Errorf("CanFix() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func boolCompareViolation(line, column int) *core.Violation {
	return &core.Violation{Rule: "bool-compare", File: "rule.go", Line: line, Column: column}
}

func TestBoolCompareFixer(t *testing.T) {
	ctx := fixerContext(t, `package sample

type user struct{ IsActive bool }

func f(x, isEnabled, trueSeen bool, u user, n int, p *bool) {
	_ = x == true
	_ = x == false
	_ = true == x
	_ = false == x
	_ = x != true
	_ = x != false
	_ = isEnabled == true
	_ = u.IsActive == true
	_ = x == trueSeen || isEnabled == false
	_ = n > 0 == false
	_ = *p == false
	_ = !x == false
}
`)

	tests := []struct {
		name         string
		line, column int
		expectedOld  string
		expectedNew  string
	}{
		{"x == true", 6, 6, "x == true", "x"},
		{"x == false", 7, 6, "x == false", "!x"},
		{"true == x", 8, 6, "true == x", "x"},
		{"false == x", 9, 6, "false == x", "!x"},
		{"x != true", 10, 6, "x != true", "!x"},
		{"x != false", 11, 6, "x != false", "x"},
		{"isEnabled == true", 12, 6, "isEnabled == true", "isEnabled"},
		{"u.IsActive == true", 13, 6, "u.IsActive == true", "u.IsActive"},
		{"name starting with true", 14, 23, "isEnabled == false", "!isEnabled"},
		{"operator operand", 15, 6, "n > 0 == false", "!(n > 0)"},
		{"dereference", 16, 6, "*p == false", "!*p"},
		{"negation undone", 17, 6, "!x == false", "x"},
	}

	fixer := NewBoolCompareFixer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixes := fixer.GenerateFix(ctx, boolCompareViolation(tt.line, tt.column))
			require.Len(t, fixes, 1)
			assert.Equal(t, tt.expectedOld, fixes[0].OldText)
			assert.Equal(t, tt.expectedNew, fixes[0].NewText)
		})
	}

	// x == trueSeen compares two variables: nothing to simplify.
	assert.Empty(t, fixer.GenerateFix(ctx, boolCompareViolation(14, 6)))
}

func TestRegistry(t *testing.T) {
	registry := NewRegistry()

	// Test empty registry
	if _, ok := registry.Get("interface-any"); ok {
		t.Error("Expected Get to return false for empty registry")
	}

	// Register a fixer
	fixer := NewInterfaceAnyFixer()
	registry.Register(fixer)

	// Test Get
	if got, ok := registry.Get("interface-any"); !ok {
		t.Error("Expected Get to return true after registration")
	} else if got != fixer {
		t.Error("Expected Get to return registered fixer")
	}

	// Test All
	all := registry.All()
	if len(all) != 1 {
		t.Errorf("Expected 1 fixer, got %d", len(all))
	}
}

func TestDefaultRegistry(t *testing.T) {
	// Test that default registry has all fixers registered
	fixers := []string{"interface-any", "deprecated-ioutil", "bool-compare"}

	for _, name := range fixers {
		if _, ok := DefaultRegistry.Get(name); !ok {
			t.Errorf("Expected fixer '%s' to be registered in DefaultRegistry", name)
		}
	}
}

func TestEnginePreview(t *testing.T) {
	engine := NewEngine(DefaultRegistry, true)

	fixes := []*Fix{
		{
			File:      "/test/file.go",
			StartLine: 10,
			OldText:   "interface{}",
			NewText:   "any",
			RuleName:  "interface-any",
		},
		{
			File:      "/test/file.go",
			StartLine: 20,
			OldText:   "ioutil.ReadFile",
			NewText:   "os.ReadFile",
			RuleName:  "deprecated-ioutil",
		},
	}

	preview := engine.Preview(fixes)

	if preview == "" {
		t.Error("Expected non-empty preview")
	}

	// Check that preview contains expected content
	if !contains(preview, "PROPOSED FIXES") {
		t.Error("Expected preview to contain 'PROPOSED FIXES'")
	}
	if !contains(preview, "interface{}") {
		t.Error("Expected preview to contain 'interface{}'")
	}
	if !contains(preview, "any") {
		t.Error("Expected preview to contain 'any'")
	}
}

func TestEnginePreviewEmpty(t *testing.T) {
	engine := NewEngine(DefaultRegistry, true)

	preview := engine.Preview(nil)

	if preview != "No fixes available.\n" {
		t.Errorf("Expected 'No fixes available.\\n', got '%s'", preview)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
