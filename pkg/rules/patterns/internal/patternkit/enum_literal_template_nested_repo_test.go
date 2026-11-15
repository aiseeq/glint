package patternkit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func filesWithExtUnder(t *testing.T, root string, files map[string]string) []string {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	paths, err := TemplateFiles(root, true)
	require.NoError(t, err)
	var rels []string
	for _, path := range paths {
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		rels = append(rels, filepath.ToSlash(rel))
	}
	return rels
}

// The templates of a checkout of another repository below the project (a
// submodule, a cloned library, named without a dot) are its own: the run
// does not walk it. A plain directory of the project keeps its templates.
func TestTemplateFilesLeaveOutNestedRepository(t *testing.T) {
	got := filesWithExtUnder(t, t.TempDir(), map[string]string{
		".git/HEAD":                          "ref: refs/heads/main\n",
		"web/templates/page.html":            "{{.Title}}",
		"third_party/lib/.git/HEAD":          "ref: refs/heads/main\n",
		"third_party/lib/templates/x.tmpl":   "{{.Other}}",
		"third_party/plain/templates/y.tmpl": "{{.Plain}}",
	})
	assert.Equal(t, []string{"third_party/plain/templates/y.tmpl", "web/templates/page.html"}, got)
}

// The templates of a directory git ignores are the project's only when the
// run walks that directory: with settings.respect_gitignore off.
func TestTemplateFilesReadIgnoredDirectoryOnlyWithoutRespectGitignore(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		".git/HEAD":               "ref: refs/heads/main\n",
		".gitignore":              "/build-out/\n",
		"web/templates/page.html": "{{.Title}}",
		"build-out/page.html":     "{{.Built}}",
	}
	assert.Equal(t, []string{"web/templates/page.html"}, filesWithExtUnder(t, root, files))
	paths, err := TemplateFiles(root, false)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "build-out/page.html"), filepath.Join(root, "web/templates/page.html")}, paths)
}

// Run in a linked worktree of the project, its own templates count.
func TestTemplateFilesReadWorktreeRoot(t *testing.T) {
	got := filesWithExtUnder(t, t.TempDir(), map[string]string{
		".git":                    "gitdir: /elsewhere/.git/worktrees/wt\n",
		"web/templates/page.html": "{{.Title}}",
	})
	assert.Equal(t, []string{"web/templates/page.html"}, got)
}
