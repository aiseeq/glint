package dbrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func writeProjectFiles(t *testing.T, ctx *core.FileContext, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(ctx.ProjectRoot, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
}

// A directory git ignores holds a migration that adds the column the query
// names. With settings.respect_gitignore off the run walks it, as its
// migration rules do, and the schema has the column; respecting .gitignore,
// neither the run nor the schema reads it.
func TestSQLUnknownColumnReadsIgnoredMigrationsOnlyWithoutRespectGitignore(t *testing.T) {
	source := "package storage\n\n" +
		"const byRef = \"SELECT id FROM ledger WHERE chain_ref = $1\"\n"
	files := map[string]string{
		".git/HEAD":                           "ref: refs/heads/main\n",
		".gitignore":                          "/gen/\n",
		"gen/migrations/002_chain_ref.up.sql": "ALTER TABLE ledger ADD COLUMN chain_ref TEXT;\n",
	}
	ctx := sqlSchemaProject(t, sqlSchemaMigration, source)
	writeProjectFiles(t, ctx, files)
	assert.Empty(t, sqlRuleLines(t, rulestest.WithoutGitignore(t, NewSQLUnknownColumnRule()), ctx))

	respecting := sqlSchemaProject(t, sqlSchemaMigration, source)
	writeProjectFiles(t, respecting, files)
	assert.Equal(t, []int{3}, sqlRuleLines(t, NewSQLUnknownColumnRule(), respecting))

	// The result cache tells the two apart by the migrations each reads.
	all, err := rulestest.WithoutGitignore(t, NewSQLUnknownColumnRule()).CacheInputs(respecting.ProjectRoot)
	require.NoError(t, err)
	some, err := NewSQLUnknownColumnRule().CacheInputs(respecting.ProjectRoot)
	require.NoError(t, err)
	assert.NotEqual(t, some, all)
}

// A worktree of the project below it holds a copy one migration ahead,
// which adds the very column the query names. The run does not walk
// the worktree, and its migrations do not silence the finding the project's
// own schema gives.
func TestSQLUnknownColumnIgnoresMigrationsOfNestedWorktree(t *testing.T) {
	source := "package storage\n\n" +
		"const byRef = \"SELECT id FROM ledger WHERE chain_ref = $1\"\n"
	ctx := sqlSchemaProject(t, sqlSchemaMigration, source)
	files := map[string]string{
		".git/HEAD":              "ref: refs/heads/main\n",
		"worktrees/agent-1/.git": "gitdir: /elsewhere/.git/worktrees/agent-1\n",
		"worktrees/agent-1/storage/migrations/001_init.up.sql":      sqlSchemaMigration,
		"worktrees/agent-1/storage/migrations/002_chain_ref.up.sql": "ALTER TABLE ledger ADD COLUMN chain_ref TEXT;\n",
	}
	writeProjectFiles(t, ctx, files)
	assert.Equal(t, []int{3}, sqlRuleLines(t, NewSQLUnknownColumnRule(), ctx))
}
