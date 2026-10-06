package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// projectFileFindings runs a rule that reads the project's files over a
// module the way the check flow does: every file first, then each one.
func projectFileFindings(t *testing.T, rule interface {
	UseProjectFiles([]*core.FileContext)
	AnalyzeFile(*core.FileContext) []*core.Violation
}, files map[string]string) []string {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	return foundLines(violations)
}

const pgDumpHeader = `SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;

CREATE TABLE public.orders (id uuid PRIMARY KEY);
`

// A schema squashed from pg_dump keeps its header: the first migration
// empties search_path for the session, and the migrator runs the next
// migration on the same pooled connection - unqualified names there no
// longer resolve and an empty database never comes up. A migrator that
// resets the session after each migration, or a transaction-local setting,
// is fine.
func TestMigrationSessionSettingsLeak(t *testing.T) {
	files := map[string]string{
		"storage/migrations/000001_init.up.sql":   pgDumpHeader,
		"storage/migrations/000001_init.down.sql": "DROP TABLE public.orders;\n",
		"storage/migrations/000002_items.up.sql": "SELECT set_config('search_path', '', true);\n" +
			"SET LOCAL search_path = '';\nCREATE TABLE items (id uuid PRIMARY KEY);\n",
		"cmd/migrate/main.go": "package main\n\nfunc main() {}\n",
	}
	assert.Equal(t, []string{"storage/migrations/000001_init.up.sql:3"}, projectFileFindings(t, NewMigrationSessionSettingsLeakRule(), files))

	files["cmd/migrate/main.go"] = "package main\n\ntype DB interface{ Exec(q string) error }\n\nfunc reset(db DB) error { return db.Exec(\"RESET ALL\") }\n\nfunc main() {}\n"
	assert.Empty(t, projectFileFindings(t, NewMigrationSessionSettingsLeakRule(), files))
}
