package qarules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
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
	keys, err := envFileKeys(root, true)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"DB_HOST": true, "DEPLOY_TOKEN": true}, keys)
}

func TestEnvFileKeysRespectSkipDirs(t *testing.T) {
	root := t.TempDir()
	writeEnvTree(t, root, map[string]string{".env": "VISIBLE=1\n", "generated/.env": "HIDDEN=1\n"})
	keys, err := envFileKeys(root, false, "generated")
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"VISIBLE": true}, keys)
	keys, err = envFileKeys(root, false)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"VISIBLE": true, "HIDDEN": true}, keys)
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
	keys, err := envFileKeys(root, true)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"DB_HOST": true, "DEPLOY_TOKEN": true}, keys)
}

// With settings.respect_gitignore off the run walks the directories git
// ignores, and the env file of one is part of the project's environment: the
// credential gate on its key is reported, as it is not while .gitignore is
// respected.
func TestTestExternalServiceReadsIgnoredEnvFileOnlyWithoutRespectGitignore(t *testing.T) {
	files := map[string]string{
		"vault/live_test.go": `package vault

import (
	"os"
	"testing"
)

func TestLiveVault(t *testing.T) {
	if os.Getenv("LIVE_VAULT_TOKEN") == "" {
		t.Skip("live vault check needs LIVE_VAULT_TOKEN")
	}
}
`,
		".git/HEAD":          "ref: refs/heads/main\n",
		".gitignore":         "/local/\n",
		"local/.env.example": "LIVE_VAULT_TOKEN=\n",
	}
	violations, err := rulestest.WithoutGitignore(t, NewTestExternalServiceRule()).AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.Len(t, violations, 1, "%v", messages(violations))
	assert.Equal(t, "LIVE_VAULT_TOKEN", violations[0].Context["env"])

	violations, err = NewTestExternalServiceRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations, "%v", messages(violations))
}

// The same for a TypeScript test: a flag the env file of an ignored
// directory sets opens the gate in every run only when the run walks that
// directory.
func TestJSTestExternalServiceReadsIgnoredEnvFileOnlyWithoutRespectGitignore(t *testing.T) {
	root := t.TempDir()
	writeEnvTree(t, root, map[string]string{
		".git/HEAD":  "ref: refs/heads/main\n",
		".gitignore": "/local/\n",
		"local/.env": "RATES_LIVE=1\n",
	})
	code := "test('x', async () => {\n  test.skip(!process.env.RATES_LIVE, 'live only')\n  await fetch('https://api.ratesbank.io/v1/daily')\n})\n"
	ctx := core.NewFileContext(filepath.Join(root, "src/rates.test.ts"), root, []byte(code), nil)
	assert.Empty(t, NewJSTestExternalServiceRule().AnalyzeFile(ctx))
	assert.Len(t, rulestest.WithoutGitignore(t, NewJSTestExternalServiceRule()).AnalyzeFile(ctx), 1)
}
