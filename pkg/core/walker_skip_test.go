package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
}

func walkPaths(t *testing.T, root string, cfg *Config) []string {
	t.Helper()
	contexts, errs := NewWalker(root, cfg).WalkSync()
	require.Empty(t, errs)
	paths := make([]string, 0, len(contexts))
	for _, ctx := range contexts {
		paths = append(paths, filepath.ToSlash(ctx.RelPath))
	}
	return paths
}

// The skip list was hard-coded, so a Go package named build/ or out/ was
// silently never analyzed and no configuration could bring it back.
func TestSkipDirsAreConfigurable(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"build/pipeline.go":       "package build\n",
		"node_modules/pkg/app.js": "export const a = 1\n",
		"main.go":                 "package main\n",
	})

	cfg := DefaultConfig()
	assert.NotContains(t, walkPaths(t, root, cfg), "build/pipeline.go",
		"build/ stays skipped by default for compatibility")

	cfg.Settings.SkipDirs = []string{"node_modules"}
	paths := walkPaths(t, root, cfg)
	assert.Contains(t, paths, "build/pipeline.go", "a configured skip list must be honored verbatim")
	assert.Contains(t, paths, "main.go")
	assert.NotContains(t, paths, "node_modules/pkg/app.js")
}

func TestDefaultSkipDirsStillApply(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".git/hooks/pre-commit.go": "package hooks\n",
		"vendor/dep/dep.go":        "package dep\n",
		"pkg/app.go":               "package pkg\n",
	})

	paths := walkPaths(t, root, DefaultConfig())
	assert.Equal(t, []string{"pkg/app.go"}, paths)
}

func TestDefaultArtifactDirsWalkTrackedGitSources(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"pkg/build/x.go": "package build\n",
		"build/out.go":   "package build\n",
	})
	gitTestCommand(t, root, "init", "-q")
	gitTestCommand(t, root, "add", "pkg/build/x.go")

	paths := walkPaths(t, root, DefaultConfig())
	assert.Contains(t, paths, "pkg/build/x.go", "tracked source in a default artifact directory must be analyzed")
	assert.NotContains(t, paths, "build/out.go", "untracked content in a default artifact directory must remain skipped")

	outsideGit := t.TempDir()
	writeTree(t, outsideGit, map[string]string{"build/x.go": "package build\n"})
	assert.NotContains(t, walkPaths(t, outsideGit, DefaultConfig()), "build/x.go",
		"default artifact directories outside git must remain skipped")

	config := DefaultConfig()
	config.Settings.SkipDirs = []string{"build"}
	assert.NotContains(t, walkPaths(t, root, config), "pkg/build/x.go",
		"an explicit skip_dirs list must continue to hide tracked sources")
}

func gitTestCommand(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, output)
}

func TestRequiredFileWalkKeepsGitignoreBehavior(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".gitignore":        "ignored/\n",
		"ignored/CLAUDE.md": "ignored instructions\n",
		"visible/CLAUDE.md": "visible instructions\n",
		"visible/other.go":  "package visible\n",
		"visible/other.md":  "not an instruction\n",
	})

	contexts, errs := NewWalker(root, DefaultConfig()).
		WithRequiredFilePredicate(func(path string) bool { return InstructionKindOf(path) != NotInstruction }).
		WalkSync()
	require.Empty(t, errs)
	require.Len(t, contexts, 1)
	assert.Equal(t, filepath.Join("visible", "CLAUDE.md"), contexts[0].RelPath)
}

// Walking twice used to panic on closing already-closed channels.
func TestWalkerCanRunTwice(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.go": "package a\n", "b.go": "package b\n"})

	walker := NewWalker(root, DefaultConfig())
	first, errs := walker.WalkSync()
	require.Empty(t, errs)
	require.Len(t, first, 2)
	require.Equal(t, 2, walker.Stats().TotalFiles)

	second, errs := walker.WalkSync()
	require.Empty(t, errs)
	require.Len(t, second, 2, "a second walk must produce the same files")
	assert.Equal(t, 2, walker.Stats().TotalFiles, "statistics describe the last walk, not the sum")
}
