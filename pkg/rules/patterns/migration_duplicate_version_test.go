package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func analyzeMigrationFile(rule *MigrationDuplicateVersionRule, path string) []*core.Violation {
	ctx := core.NewFileContext(path, filepath.Dir(path), []byte("-- sql"), nil)
	return rule.AnalyzeFile(ctx)
}

// writeMigrations creates real migration files (checkPairing uses os.Stat)
// and returns their paths in creation order.
func writeMigrations(t *testing.T, dir string, names ...string) []string {
	t.Helper()
	paths := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("-- sql"), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func TestMigrationDuplicateVersionRule(t *testing.T) {
	t.Run("duplicate version with different names", func(t *testing.T) {
		rule := NewMigrationDuplicateVersionRule()
		paths := writeMigrations(t, t.TempDir(),
			"000029_client_number.down.sql",
			"000029_client_number.up.sql",
			"000029_support_conversations.down.sql",
			"000029_support_conversations.up.sql",
		)
		var total []*core.Violation
		for _, path := range paths {
			total = append(total, analyzeMigrationFile(rule, path)...)
		}
		if len(total) != 2 {
			t.Fatalf("want 2 violations (one per duplicate-name file), got %d: %+v", len(total), total)
		}
		if total[0].Severity != core.SeverityCritical {
			t.Errorf("want critical severity, got %v", total[0].Severity)
		}
	})

	t.Run("up down pair of the same migration is fine", func(t *testing.T) {
		rule := NewMigrationDuplicateVersionRule()
		paths := writeMigrations(t, t.TempDir(),
			"000030_add_index.up.sql",
			"000030_add_index.down.sql",
			"000031_other.up.sql",
			"000031_other.down.sql",
		)
		var total []*core.Violation
		for _, path := range paths {
			total = append(total, analyzeMigrationFile(rule, path)...)
		}
		if len(total) != 0 {
			t.Fatalf("want 0 violations, got %d: %+v", len(total), total)
		}
	})

	t.Run("same version in different directories is fine", func(t *testing.T) {
		rule := NewMigrationDuplicateVersionRule()
		var total []*core.Violation
		total = append(total, analyzeMigrationFile(rule,
			writeMigrations(t, t.TempDir(), "000001_init.up.sql", "000001_init.down.sql")[0])...)
		total = append(total, analyzeMigrationFile(rule,
			writeMigrations(t, t.TempDir(), "000001_bootstrap.up.sql", "000001_bootstrap.down.sql")[0])...)
		if len(total) != 0 {
			t.Fatalf("want 0 violations, got %d: %+v", len(total), total)
		}
	})

	t.Run("non-migration sql files are ignored", func(t *testing.T) {
		rule := NewMigrationDuplicateVersionRule()
		violations := analyzeMigrationFile(rule, "/repo/queries/report.sql")
		if len(violations) != 0 {
			t.Fatalf("want 0 violations, got %d", len(violations))
		}
	})
}

func TestMigrationDuplicateVersionRule_Pairing(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("-- sql"), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	pairedUp := write("000030_add_index.up.sql")
	write("000030_add_index.down.sql")
	lonelyUp := write("000031_orphan.up.sql")

	rule := NewMigrationDuplicateVersionRule()
	if got := analyzeMigrationFile(rule, pairedUp); len(got) != 0 {
		t.Fatalf("paired migration must be clean, got: %+v", got)
	}
	got := analyzeMigrationFile(rule, lonelyUp)
	if len(got) != 1 {
		t.Fatalf("missing down must be flagged, got %d: %+v", len(got), got)
	}
	if got[0].Severity != core.SeverityHigh {
		t.Errorf("pairing violation must be HIGH, got %v", got[0].Severity)
	}
}
