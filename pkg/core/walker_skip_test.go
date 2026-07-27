package core

import (
	"os"
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
