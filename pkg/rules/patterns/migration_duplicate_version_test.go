package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func analyzeMigrationFile(rule *MigrationDuplicateVersionRule, path string) []*core.Violation {
	ctx := core.NewFileContext(path, "/repo", []byte("-- sql"), nil)
	return rule.AnalyzeFile(ctx)
}

func TestMigrationDuplicateVersionRule(t *testing.T) {
	t.Run("duplicate version with different names", func(t *testing.T) {
		rule := NewMigrationDuplicateVersionRule()
		var total []*core.Violation
		for _, path := range []string{
			"/repo/migrations/000029_client_number.down.sql",
			"/repo/migrations/000029_client_number.up.sql",
			"/repo/migrations/000029_support_conversations.down.sql",
			"/repo/migrations/000029_support_conversations.up.sql",
		} {
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
		var total []*core.Violation
		for _, path := range []string{
			"/repo/migrations/000030_add_index.up.sql",
			"/repo/migrations/000030_add_index.down.sql",
			"/repo/migrations/000031_other.up.sql",
			"/repo/migrations/000031_other.down.sql",
		} {
			total = append(total, analyzeMigrationFile(rule, path)...)
		}
		if len(total) != 0 {
			t.Fatalf("want 0 violations, got %d: %+v", len(total), total)
		}
	})

	t.Run("same version in different directories is fine", func(t *testing.T) {
		rule := NewMigrationDuplicateVersionRule()
		var total []*core.Violation
		for _, path := range []string{
			"/repo/serviceA/migrations/000001_init.up.sql",
			"/repo/serviceB/migrations/000001_bootstrap.up.sql",
		} {
			total = append(total, analyzeMigrationFile(rule, path)...)
		}
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
