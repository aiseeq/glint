package dbrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	for name, content := range files {
		path := filepath.Join(ctx.ProjectRoot, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	assert.Equal(t, []int{3}, sqlRuleLines(t, NewSQLUnknownColumnRule(), ctx))
}
