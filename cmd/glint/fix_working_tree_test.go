package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixableSource = "package a\n\nfunc F(x interface{}) {}\n"

// fixRepo commits a module with one interface-any finding and selects that
// fixer with --dry-run=false, as `glint fix --dry-run=false -r interface-any`.
func fixRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/a\n\ngo 1.22\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte(fixableSource), 0o644))
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "glint@example.com"},
		{"config", "user.name", "glint"},
		{"add", "-A"},
		{"commit", "-m", "base"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		require.NoError(t, cmd.Run(), "git %v", args)
	}
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	prevDryRun, prevForce, prevRules := flagDryRun, flagForce, flagFixRules
	flagDryRun, flagForce, flagFixRules = false, false, []string{"interface-any"}
	t.Cleanup(func() { flagDryRun, flagForce, flagFixRules = prevDryRun, prevForce, prevRules })
	return root
}

func readSource(t *testing.T, root string) string {
	t.Helper()
	return readFile(t, filepath.Join(root, "a.go"))
}

// A ticket being written next to the code made glint fix refuse every fix and
// fall back to a dry run, though no fix touched the ticket.
func TestFixAppliesBesideUnrelatedUncommittedFile(t *testing.T) {
	root := fixRepo(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs", "tasks"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "tasks", "ticket.md"), []byte("ticket\n"), 0o644))

	output, err := captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.NoError(t, err)
	assert.NotContains(t, output, "WARNING")
	assert.Equal(t, "package a\n\nfunc F(x any) {}\n", readSource(t, root))
}

// A refusal used to fall back to a dry run that exited 0 and ended with "Run
// with --dry-run=false", the flag the caller had already passed.
func TestFixKeepsUncommittedTargetAndNamesIt(t *testing.T) {
	root := fixRepo(t)
	edited := fixableSource + "\nvar Edited = 1\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte(edited), 0o644))

	output, err := captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "files to fix have uncommitted changes: "+filepath.Join(relativeToCwd(t, root), "a.go"))
	assert.Contains(t, err.Error(), "nothing was changed")
	assert.NotContains(t, output, "--dry-run=false")
	assert.Equal(t, edited, readSource(t, root))
}

func relativeToCwd(t *testing.T, path string) string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	rel, err := filepath.Rel(cwd, path)
	require.NoError(t, err)
	return rel
}

// The roots after a refusing one are still fixed, and the run fails.
func TestFixRefusalLeavesOtherRootsFixed(t *testing.T) {
	dirty, clean := fixRepo(t), fixRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(dirty, "a.go"), []byte(fixableSource+"\nvar Edited = 1\n"), 0o644))
	prev := flagChdir
	flagChdir = nil
	t.Cleanup(func() { flagChdir = prev })

	_, err := captureRuleOutput(t, func() error { return runFix(nil, []string{dirty, clean}) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), dirty)
	assert.Equal(t, "package a\n\nfunc F(x any) {}\n", readSource(t, clean))
}

// An explicit dry run said to apply with --dry-run=false, which then refused.
func TestFixExplicitDryRunNamesUncommittedTargets(t *testing.T) {
	root := fixRepo(t)
	flagDryRun = true
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte(fixableSource+"\nvar Edited = 1\n"), 0o644))

	output, err := captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.NoError(t, err)
	assert.Contains(t, output, "NOTE: files to fix have uncommitted changes: "+filepath.Join(relativeToCwd(t, root), "a.go"))
	assert.NotContains(t, output, "Run with --dry-run=false to apply changes.")
}

// Outside git --dry-run=false refuses like for an uncommitted file: it used to
// fall back to a dry run that exited 0 and advised the flag already passed.
func TestFixOutsideGitRefuses(t *testing.T) {
	root := fixRepo(t)
	require.NoError(t, os.RemoveAll(filepath.Join(root, ".git")))

	output, err := captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "files to fix are outside any git repository: "+filepath.Join(relativeToCwd(t, root), "a.go"))
	assert.NotContains(t, output, "--dry-run=false")
	assert.Equal(t, fixableSource, readSource(t, root))
}

// A default dry run outside git previews the fixes and says why applying
// them needs --force, rather than failing on the git query.
func TestFixDryRunOutsideGitPreviews(t *testing.T) {
	root := fixRepo(t)
	flagDryRun = true
	require.NoError(t, os.RemoveAll(filepath.Join(root, ".git")))

	output, err := captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.NoError(t, err)
	assert.Contains(t, output, "PROPOSED FIXES")
	assert.Contains(t, output, "NOTE: files to fix are outside any git repository")
}

// Overlapping fixes take a second pass over the file the first one fixed:
// the run's own edit must not read as uncommitted work.
func TestFixSecondPassAcceptsFilesTheRunFixed(t *testing.T) {
	root := fixRepo(t)
	flagFixRules = []string{"bool-compare"}
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n\nfunc F(x bool) bool { return (x == true) == false }\n"), 0o644))
	commitAll(t, root)

	output, err := captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.NoError(t, err, output)
	assert.Equal(t, "package a\n\nfunc F(x bool) bool { return !(x) }\n", readSource(t, root))
}

// A file that turns dirty while the run goes on is refused in the pass that
// reaches it. The git wrapper edits b.go on the run's first status query.
func TestFixLaterPassRefusesNewlyUncommittedTarget(t *testing.T) {
	root := fixRepo(t)
	flagFixRules = []string{"bool-compare", "interface-any"}
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n\nfunc F(x bool) bool { return (x == true) == false }\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "b.go"), []byte("package a\n"), 0o644))
	commitAll(t, root)

	realGit, err := exec.LookPath("git")
	require.NoError(t, err)
	bin := t.TempDir()
	wrapper := "#!/bin/sh\n" +
		"if [ \"$1\" = --literal-pathspecs ] && [ ! -e \"$GLINT_TEST_MARK\" ]; then\n" +
		"  touch \"$GLINT_TEST_MARK\"\n" +
		"  printf 'func G(v interface{}) {}\\n' >> \"$GLINT_TEST_EDIT\"\n" +
		"fi\n" +
		"exec \"$GLINT_TEST_GIT\" \"$@\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(bin, "git"), []byte(wrapper), 0o755))
	t.Setenv("GLINT_TEST_GIT", realGit)
	t.Setenv("GLINT_TEST_MARK", filepath.Join(bin, "mark"))
	t.Setenv("GLINT_TEST_EDIT", filepath.Join(root, "b.go"))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err = captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pass 2: files to fix have uncommitted changes: "+filepath.Join(relativeToCwd(t, root), "b.go"))
	assert.Equal(t, "package a\nfunc G(v interface{}) {}\n", readFile(t, filepath.Join(root, "b.go")))
}

func commitAll(t *testing.T, root string) {
	t.Helper()
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-m", "next"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		require.NoError(t, cmd.Run(), "git %v", args)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

func TestFixForceAppliesToUncommittedTarget(t *testing.T) {
	root := fixRepo(t)
	flagForce = true
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte(fixableSource+"\nvar Edited = 1\n"), 0o644))

	_, err := captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.NoError(t, err)
	assert.Equal(t, "package a\n\nfunc F(x any) {}\n\nvar Edited = 1\n", readSource(t, root))
}

func TestFixExplicitDryRunAdvisesTheFlag(t *testing.T) {
	root := fixRepo(t)
	flagDryRun = true

	output, err := captureRuleOutput(t, func() error { return fixProjectRoot(root) })
	require.NoError(t, err)
	assert.Contains(t, output, "Run with --dry-run=false to apply changes.")
	assert.Equal(t, fixableSource, readSource(t, root))
}
