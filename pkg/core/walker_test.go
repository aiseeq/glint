package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkerVisitFileReportsFilesystemErrorAndContinues(t *testing.T) {
	walker := NewWalker(t.TempDir(), DefaultConfig())
	walkErr := errors.New("permission denied")
	walkErrors := make(chan error, 1)

	// Returning the error would abort the whole filepath.Walk; it must go to
	// the error channel instead so the rest of the tree is still discovered.
	err := walker.visitPath(make(chan string, 1), walkErrors, "blocked", nil, walkErr)
	require.NoError(t, err)
	require.Len(t, walkErrors, 1)
	require.ErrorIs(t, <-walkErrors, walkErr)
}

func TestWalkerContinuesPastUnreadableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	tmpDir := t.TempDir()
	blocked := filepath.Join(tmpDir, "aaa")
	require.NoError(t, os.MkdirAll(blocked, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, "hidden.go"), []byte("package aaa\n"), 0644))
	require.NoError(t, os.Chmod(blocked, 0))
	t.Cleanup(func() { _ = os.Chmod(blocked, 0755) })
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "zzz"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "zzz", "z.go"), []byte("package zzz\n"), 0644))

	contexts, errs := NewWalker(tmpDir, DefaultConfig()).WalkSync()

	require.Len(t, errs, 1, "the unreadable directory must surface as an error")
	require.Len(t, contexts, 1, "files after the unreadable directory must still be discovered")
	assert.Equal(t, filepath.Join("zzz", "z.go"), contexts[0].RelPath)
}

func TestWalkerReportsGoParseError(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "invalid.go"), []byte("package"), 0644))

	contexts, errs := NewWalker(tmpDir, DefaultConfig()).WalkSync()
	require.Len(t, contexts, 1, "regex rules should still analyze the invalid file")
	require.Len(t, errs, 1)
}

func TestNewWalker(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DefaultConfig()

	walker := NewWalker(tmpDir, cfg)
	assert.NotNil(t, walker)
}

func TestNewWalkerUsesSharedParser(t *testing.T) {
	// Rules that parse sibling files rely on hitting the same content-keyed
	// cache the walker fills; a private parser per walker breaks that sharing.
	walker := NewWalker(t.TempDir(), DefaultConfig())
	assert.Same(t, SharedParser(), walker.parser)
}

func TestWalkSyncHandlesMoreErrorsThanChannelBuffer(t *testing.T) {
	// The internal walk() channels are buffered at 100; a consumer that read
	// them sequentially would deadlock here. WalkSync must drain both
	// concurrently and return every error.
	tmpDir := t.TempDir()
	const files = 150
	for i := 0; i < files; i++ {
		path := filepath.Join(tmpDir, fmt.Sprintf("broken%03d.go", i))
		require.NoError(t, os.WriteFile(path, []byte("package broken\nfunc {"), 0644))
	}

	contexts, errs := NewWalker(tmpDir, DefaultConfig()).WalkSync()

	assert.Len(t, errs, files)
	assert.Len(t, contexts, files, "regex rules still analyze files that fail Go parsing")
}

func TestWalkerAnalyzesNginxConfig(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "nginx.conf"), []byte("server {}"), 0644))

	contexts, errs := NewWalker(tmpDir, DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	require.Len(t, contexts, 1)
	assert.Equal(t, "nginx.conf", contexts[0].RelPath)
}

func TestWalkerWalkSync(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create some Go files
	goDir := filepath.Join(tmpDir, "pkg")
	err := os.MkdirAll(goDir, 0755)
	require.NoError(t, err)

	files := map[string]string{
		"main.go":          "package main\n\nfunc main() {}\n",
		"pkg/util.go":      "package pkg\n\nfunc Util() {}\n",
		"pkg/util_test.go": "package pkg\n\nfunc TestUtil() {}\n",
	}

	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		dir := filepath.Dir(path)
		if dir != tmpDir {
			err := os.MkdirAll(dir, 0755)
			require.NoError(t, err)
		}
		err := os.WriteFile(path, []byte(content), 0644)
		require.NoError(t, err)
	}

	cfg := DefaultConfig()
	walker := NewWalker(tmpDir, cfg)

	contexts, errors := walker.WalkSync()

	assert.Empty(t, errors)
	assert.Len(t, contexts, 3)

	// Verify stats
	stats := walker.Stats()
	assert.Equal(t, 3, stats.TotalFiles)
	assert.Equal(t, 0, stats.SkippedFiles)
}

func TestWalkerExcludesVendor(t *testing.T) {
	tmpDir := t.TempDir()

	// Create vendor directory
	vendorDir := filepath.Join(tmpDir, "vendor", "pkg")
	err := os.MkdirAll(vendorDir, 0755)
	require.NoError(t, err)

	// Create files
	mainFile := filepath.Join(tmpDir, "main.go")
	vendorFile := filepath.Join(vendorDir, "lib.go")

	err = os.WriteFile(mainFile, []byte("package main"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(vendorFile, []byte("package pkg"), 0644)
	require.NoError(t, err)

	cfg := DefaultConfig()
	walker := NewWalker(tmpDir, cfg)

	contexts, errors := walker.WalkSync()

	assert.Empty(t, errors)
	assert.Len(t, contexts, 1) // Only main.go, vendor excluded

	// Verify the only file is main.go
	assert.Contains(t, contexts[0].Path, "main.go")
}

func TestWalkerExcludesNodeModules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create node_modules directory
	nodeDir := filepath.Join(tmpDir, "node_modules", "pkg")
	err := os.MkdirAll(nodeDir, 0755)
	require.NoError(t, err)

	// Create files
	appFile := filepath.Join(tmpDir, "app.ts")
	nodeFile := filepath.Join(nodeDir, "index.js")

	err = os.WriteFile(appFile, []byte("export const x = 1"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(nodeFile, []byte("module.exports = {}"), 0644)
	require.NoError(t, err)

	cfg := DefaultConfig()
	walker := NewWalker(tmpDir, cfg)

	contexts, errors := walker.WalkSync()

	assert.Empty(t, errors)
	assert.Len(t, contexts, 1) // Only app.ts, node_modules excluded
}

func TestWalkerExcludesGitDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .git directory
	gitDir := filepath.Join(tmpDir, ".git", "objects")
	err := os.MkdirAll(gitDir, 0755)
	require.NoError(t, err)

	// Create files
	mainFile := filepath.Join(tmpDir, "main.go")
	gitFile := filepath.Join(gitDir, "pack")

	err = os.WriteFile(mainFile, []byte("package main"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(gitFile, []byte("binary"), 0644)
	require.NoError(t, err)

	cfg := DefaultConfig()
	walker := NewWalker(tmpDir, cfg)

	contexts, errors := walker.WalkSync()

	assert.Empty(t, errors)
	assert.Len(t, contexts, 1) // Only main.go, .git excluded
}

func TestWalkerWithWorkers(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tmpDir, "main.go")
	err := os.WriteFile(testFile, []byte("package main"), 0644)
	require.NoError(t, err)

	cfg := DefaultConfig()
	walker := NewWalker(tmpDir, cfg).WithWorkers(2)

	contexts, errors := walker.WalkSync()

	assert.Empty(t, errors)
	assert.Len(t, contexts, 1)
}

func TestWalkerOnlyAnalyzesCodeFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create various file types
	files := map[string]string{
		"main.go":     "package main",
		"app.ts":      "export const x = 1",
		"script.js":   "const y = 2",
		"readme.md":   "# README",
		"config.yaml": "version: 1",
		"data.json":   "{}",
	}

	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		err := os.WriteFile(path, []byte(content), 0644)
		require.NoError(t, err)
	}

	cfg := DefaultConfig()
	walker := NewWalker(tmpDir, cfg)

	contexts, _ := walker.WalkSync()

	// Should only include Go, TypeScript, JavaScript, and Markdown files
	assert.Len(t, contexts, 4)

	var extensions []string
	for _, ctx := range contexts {
		extensions = append(extensions, ctx.Extension())
	}

	assert.Contains(t, extensions, ".go")
	assert.Contains(t, extensions, ".ts")
	assert.Contains(t, extensions, ".js")
	assert.Contains(t, extensions, ".md")
}

func TestWalkerParsesGoFiles(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "main.go")
	content := `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`
	err := os.WriteFile(testFile, []byte(content), 0644)
	require.NoError(t, err)

	cfg := DefaultConfig()
	walker := NewWalker(tmpDir, cfg)

	contexts, _ := walker.WalkSync()

	require.Len(t, contexts, 1)
	ctx := contexts[0]

	assert.True(t, ctx.HasGoAST())
	assert.NotNil(t, ctx.GoAST)
	assert.NotNil(t, ctx.GoFileSet)
	assert.Equal(t, "main", ctx.GoPackage)
	assert.Contains(t, ctx.GoImports, "fmt")
}

func TestWalkerWithGoParsingDisabledLeavesGoASTForProjectLoader(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644))

	contexts, errs := NewWalker(tmpDir, DefaultConfig()).WithGoParsing(false).WalkSync()

	require.Empty(t, errs)
	require.Len(t, contexts, 1)
	assert.Nil(t, contexts[0].GoAST)
	assert.Nil(t, contexts[0].GoFileSet)
}
