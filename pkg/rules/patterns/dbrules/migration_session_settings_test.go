package dbrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
)

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
	assert.Equal(t, []string{"storage/migrations/000001_init.up.sql:3"}, patterntest.ProjectFileFindings(t, NewMigrationSessionSettingsLeakRule(), files))

	files["cmd/migrate/main.go"] = "package main\n\ntype DB interface{ Exec(q string) error }\n\nfunc reset(db DB) error { return db.Exec(\"RESET ALL\") }\n\nfunc main() {}\n"
	assert.Empty(t, patterntest.ProjectFileFindings(t, NewMigrationSessionSettingsLeakRule(), files))
}
