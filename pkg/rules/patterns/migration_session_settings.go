package patterns

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMigrationSessionSettingsLeakRule())
}

// MigrationSessionSettingsLeakRule detects a migration that empties
// search_path for the whole session - the header pg_dump writes:
//
//	SELECT pg_catalog.set_config('search_path', '', false);
//
// The migrator runs the next migration, and its own journal queries, on the
// same connection: unqualified names stop resolving (relation does not
// exist, no schema has been selected to create in), and an empty database
// never comes up. The rule is silent when the project's Go code resets the
// session (RESET ALL, DISCARD ALL) - a migrator that does it after each
// migration keeps the setting inside it. set_config(..., true) and SET LOCAL
// last only to the end of the transaction.
type MigrationSessionSettingsLeakRule struct {
	*rules.BaseRule
	// resets marks a project whose Go code resets a session.
	resets bool
}

// NewMigrationSessionSettingsLeakRule creates the rule
func NewMigrationSessionSettingsLeakRule() *MigrationSessionSettingsLeakRule {
	return &MigrationSessionSettingsLeakRule{BaseRule: rules.NewBaseRule(
		"migration-session-settings-leak",
		"patterns",
		"Detects a migration emptying search_path for the session (pg_dump's set_config('search_path', '', false)) in a project whose code never resets the session — the next migration on the connection no longer resolves unqualified names",
		core.SeverityHigh,
	)}
}

var (
	sessionSearchPathCleared = regexp.MustCompile(`(?i)\bset_config\s*\(\s*'search_path'\s*,\s*''\s*,\s*false\s*\)|^\s*SET\s+(?:SESSION\s+)?search_path\s*(?:=|TO)\s*''`)
	sessionReset             = regexp.MustCompile(`(?i)\b(?:RESET|DISCARD)\s+ALL\b`)
)

// UseProjectFiles records whether the Go code resets a session.
func (r *MigrationSessionSettingsLeakRule) UseProjectFiles(files []*core.FileContext) {
	r.resets = slices.ContainsFunc(files, func(ctx *core.FileContext) bool {
		return ctx.IsGoFile() && !ctx.IsTestFile() && sessionReset.Match(ctx.Content)
	})
}

// ResetState forgets the previous root.
func (r *MigrationSessionSettingsLeakRule) ResetState() { r.resets = false }

// AnalyzeFile reports the session-wide search_path changes of a migration.
func (r *MigrationSessionSettingsLeakRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.resets || !isUpMigration(ctx.RelPath) {
		return nil
	}
	var violations []*core.Violation
	for i, line := range ctx.Lines {
		if strings.HasPrefix(strings.TrimSpace(line), "--") || !sessionSearchPathCleared.MatchString(line) || ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		violations = append(violations, sqlViolation(r.BaseRule, ctx, i+1,
			"The migration empties search_path for the whole session — the migrator runs the next migration on the same connection, where unqualified names no longer resolve",
			"Drop the pg_dump header lines, or make them transaction-local (set_config(..., true), SET LOCAL); a migrator can also RESET ALL after each migration"))
	}
	return violations
}

// isUpMigration reports a SQL file of a migrations directory that is not a
// down migration.
func isUpMigration(path string) bool {
	if !strings.HasSuffix(path, ".sql") || strings.HasSuffix(path, ".down.sql") {
		return false
	}
	return slices.ContainsFunc(strings.Split(filepath.ToSlash(filepath.Dir(path)), "/"), func(dir string) bool {
		return dir == "migrations" || dir == "migration"
	})
}
