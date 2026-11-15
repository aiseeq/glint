package frontendrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const typecheckPackage = `{"scripts": {"typecheck": "tsc --noEmit"}}`

func checkedTSConfigPaths(t *testing.T, root string, files map[string]string) []string {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	scopes, err := checkedTSConfigs(root)
	require.NoError(t, err)
	var paths []string
	for _, scope := range scopes {
		rel, err := filepath.Rel(root, scope.path)
		require.NoError(t, err)
		paths = append(paths, filepath.ToSlash(rel))
	}
	return paths
}

// A checkout of another repository below the project (a submodule, a cloned
// library) has a name without a dot; its package.json type-checks its own
// code, not the project's, and the run does not walk it.
func TestCheckedTSConfigsLeaveOutNestedRepository(t *testing.T) {
	got := checkedTSConfigPaths(t, t.TempDir(), map[string]string{
		".git/HEAD":                       "ref: refs/heads/main\n",
		"web/package.json":                typecheckPackage,
		"web/tsconfig.json":               "{}",
		"third_party/lib/.git":            "gitdir: /elsewhere/.git/modules/lib\n",
		"third_party/lib/package.json":    typecheckPackage,
		"third_party/lib/tsconfig.json":   "{}",
		"third_party/plain/package.json":  typecheckPackage,
		"third_party/plain/tsconfig.json": "{}",
	})
	assert.Equal(t, []string{"third_party/plain/tsconfig.json", "web/tsconfig.json"}, got)
}

// Run in a linked worktree of the project, its own package.json counts.
func TestCheckedTSConfigsReadWorktreeRoot(t *testing.T) {
	got := checkedTSConfigPaths(t, t.TempDir(), map[string]string{
		".git":              "gitdir: /elsewhere/.git/worktrees/wt\n",
		"web/package.json":  typecheckPackage,
		"web/tsconfig.json": "{}",
	})
	assert.Equal(t, []string{"web/tsconfig.json"}, got)
}
