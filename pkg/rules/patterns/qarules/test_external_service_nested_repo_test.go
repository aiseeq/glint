package qarules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeEnvTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
}

// The env files of an agent's worktree and of a checkout of another
// repository below the project are not the project's environment: the run
// does not walk them, and their keys do not mix with the project's. A
// plain directory of the project keeps its env file.
func TestEnvFileKeysLeaveOutNestedRepositories(t *testing.T) {
	root := t.TempDir()
	writeEnvTree(t, root, map[string]string{
		".git/HEAD":                      "ref: refs/heads/main\n",
		".env":                           "DB_HOST=localhost\n",
		"deploy/.env.example":            "DEPLOY_TOKEN=\n",
		".claude/worktrees/agent-1/.git": "gitdir: /elsewhere/.git/worktrees/agent-1\n",
		".claude/worktrees/agent-1/.env": "COPY_ONLY_KEY=1\n",
		"thirdparty/.git/HEAD":           "ref: refs/heads/main\n",
		"thirdparty/.env":                "OTHER_REPO_KEY=1\n",
	})
	keys, err := envFileKeys(root)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"DB_HOST": true, "DEPLOY_TOKEN": true}, keys)
}

// Run in a linked worktree of the project, the worktree's own env files are
// the project's.
func TestEnvFileKeysReadWorktreeRoot(t *testing.T) {
	root := t.TempDir()
	writeEnvTree(t, root, map[string]string{
		".git":                "gitdir: /elsewhere/.git/worktrees/wt\n",
		".env":                "DB_HOST=localhost\n",
		"deploy/.env.example": "DEPLOY_TOKEN=\n",
	})
	keys, err := envFileKeys(root)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"DB_HOST": true, "DEPLOY_TOKEN": true}, keys)
}
