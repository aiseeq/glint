package deadcode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func templateNamesUnder(t *testing.T, root string, files map[string]string) map[string]bool {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	names, err := templateSelectorNames(&core.GoProjectContext{ProjectRoot: root})
	require.NoError(t, err)
	return names
}

// A template of a checkout of another repository below the project (a
// submodule, a cloned library, named without a dot) does not keep a method
// of the project alive: the run does not walk it. A plain directory of the
// project keeps its templates.
func TestTemplateSelectorNamesLeaveOutNestedRepository(t *testing.T) {
	got := templateNamesUnder(t, t.TempDir(), map[string]string{
		".git/HEAD":                          "ref: refs/heads/main\n",
		"web/templates/page.html":            "{{.Title}}",
		"third_party/lib/.git/HEAD":          "ref: refs/heads/main\n",
		"third_party/lib/templates/x.tmpl":   "{{.Other}}",
		"third_party/plain/templates/y.tmpl": "{{.Plain}}",
	})
	assert.Equal(t, map[string]bool{"Title": true, "Plain": true}, got)
}

// Run in a linked worktree of the project, its own templates count.
func TestTemplateSelectorNamesReadWorktreeRoot(t *testing.T) {
	got := templateNamesUnder(t, t.TempDir(), map[string]string{
		".git":                    "gitdir: /elsewhere/.git/worktrees/wt\n",
		"web/templates/page.html": "{{.Title}}",
	})
	assert.Equal(t, map[string]bool{"Title": true}, got)
}
