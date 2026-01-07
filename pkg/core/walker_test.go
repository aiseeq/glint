package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWalker(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DefaultConfig()

	walker := NewWalker(tmpDir, cfg)
	assert.NotNil(t, walker)
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

	// Should only include Go, TypeScript, and JavaScript files
	assert.Len(t, contexts, 3)

	var extensions []string
	for _, ctx := range contexts {
		extensions = append(extensions, ctx.Extension())
	}

	assert.Contains(t, extensions, ".go")
	assert.Contains(t, extensions, ".ts")
	assert.Contains(t, extensions, ".js")
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
