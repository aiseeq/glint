package sqlschema

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nestedRepoInit = "CREATE TABLE accounts (id UUID PRIMARY KEY, email TEXT NOT NULL);\n"

// An agent's worktree of the project (a .git file) and a checkout of another
// repository (a .git directory) below the project hold migrations of their
// own: a copy one step ahead, a schema of something else. The run does not
// walk them, so they are not the project's schema either.
func TestLoadLeavesOutMigrationsOfNestedRepositories(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{ // graft:leak-ok generic helper of this package, schema_test.go:12
		".git/HEAD":                          "ref: refs/heads/main\n",
		"storage/migrations/001_init.up.sql": nestedRepoInit,
		".claude/worktrees/agent-1/.git":     "gitdir: /elsewhere/.git/worktrees/agent-1\n",
		".claude/worktrees/agent-1/storage/migrations/001_init.up.sql":  nestedRepoInit,
		".claude/worktrees/agent-1/storage/migrations/002_note.up.sql":  "ALTER TABLE accounts ADD COLUMN note TEXT;\n",
		"third_party/billing/.git/HEAD":                                 "ref: refs/heads/main\n",
		"third_party/billing/migrations/001_invoices.up.sql":            "CREATE TABLE invoices (id UUID PRIMARY KEY);\n",
		"third_party/billing/migrations/002_accounts_extra.up.sql":      "ALTER TABLE accounts ADD COLUMN plan TEXT;\n",
		"services/reports/migrations/001_report_runs.up.sql":            "CREATE TABLE report_runs (id UUID PRIMARY KEY);\n",
		"services/reports/migrations/002_report_runs_account_id.up.sql": "ALTER TABLE report_runs ADD COLUMN account_id UUID;\n",
	})
	dirs, err := findMigrationDirs(root, true)
	require.NoError(t, err)
	assert.Equal(t, []string{
		filepath.Join(root, "services/reports/migrations"),
		filepath.Join(root, "storage/migrations"),
	}, dirs)

	schema, err := Load(root, nil, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"id", "email"}, schema.Table("accounts").Columns())
	assert.Nil(t, schema.Table("invoices"))
	assert.NotNil(t, schema.Table("report_runs").Column("account_id"))
}

func TestMigrationDirsRespectSkipDirs(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{ // graft:leak-ok generic helper of this package, schema_test.go:12
		"app/migrations/001_init.up.sql":       "CREATE TABLE kept (id INT);\n",
		"generated/migrations/001_init.up.sql": "CREATE TABLE hidden (id INT);\n",
	})
	got, err := findMigrationDirs(root, false, "generated")
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "app/migrations")}, got)
	got, err = findMigrationDirs(root, false)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "app/migrations"), filepath.Join(root, "generated/migrations")}, got)
}

func TestLoadKeepsMigrationDirectoryOrder(t *testing.T) {
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{ // graft:leak-ok generic helper of this package, schema_test.go:12
		"generated/migrations/002_chain_ref.up.sql": "ALTER TABLE ledger ADD COLUMN chain_ref TEXT;\n",
		"storage/migrations/001_init.up.sql":        "CREATE TABLE ledger (id INT);\n",
	})
	schema, err := Load(root, nil, false)
	require.NoError(t, err)
	assert.NotEmpty(t, schema.Faults)
}

// Run in a linked worktree of the project, whose top holds a .git file, the
// project's migrations are found as in the main checkout; outside any
// repository a directory with a .git is what the run was pointed at.
func TestLoadFindsMigrationsOfWorktreeRootAndOutsideRepository(t *testing.T) {
	worktree := t.TempDir()
	writeMigrations(t, worktree, map[string]string{ // graft:leak-ok generic helper of this package, schema_test.go:12
		".git":                               "gitdir: /elsewhere/.git/worktrees/wt\n",
		"storage/migrations/001_init.up.sql": nestedRepoInit,
	})
	dirs, err := findMigrationDirs(worktree, true)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(worktree, "storage/migrations")}, dirs)

	outside := t.TempDir()
	writeMigrations(t, outside, map[string]string{ // graft:leak-ok generic helper of this package, schema_test.go:12
		"app/.git/HEAD":                          "ref: refs/heads/main\n",
		"app/storage/migrations/001_init.up.sql": nestedRepoInit,
	})
	dirs, err = findMigrationDirs(outside, true)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(outside, "app/storage/migrations")}, dirs)
}

// A directory git ignores is not the project's: a database volume the
// container writes as its own user cannot even be listed, and finding the
// migrations does not open it.
func TestLoadSkipsUnreadableIgnoredDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	root := t.TempDir()
	writeMigrations(t, root, map[string]string{ // graft:leak-ok generic helper of this package, schema_test.go:12
		".git/HEAD":                          "ref: refs/heads/main\n",
		".gitignore":                         "/pgdata/\n",
		"storage/migrations/001_init.up.sql": nestedRepoInit,
		"pgdata/base/migrations/1.up.sql":    "CREATE TABLE stray (id INT);\n",
	})
	locked := filepath.Join(root, "pgdata")
	require.NoError(t, os.Chmod(locked, 0))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	dirs, err := findMigrationDirs(root, true)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "storage/migrations")}, dirs)
}
