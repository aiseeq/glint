package patterns

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMigrationDuplicateVersionRule())
}

// migrationFileRe matches golang-migrate style names: 000029_name.up.sql
var migrationFileRe = regexp.MustCompile(`^(\d+)_(.+)\.(up|down)\.sql$`)

// MigrationDuplicateVersionRule detects two different migrations sharing one
// version number in the same directory:
//
//	000029_client_number.up.sql
//	000029_support_conversations.up.sql   // same version, different migration!
//
// Versions are compared as numbers, the way golang-migrate parses them: 029_a
// and 29_b are one version too. Version-keyed migrators (maps, golang-migrate)
// either fail on the duplicate or silently keep only one of them — a fresh
// database ends up missing the other migration's schema. Every migration must
// own a unique version number, and the migrator itself should fail on
// duplicates (defense-in-depth: this rule catches the problem at lint time).
//
// The rule also requires every migration to come as an up/down pair, so that
// each one can be rolled back. golang-migrate itself does not require down
// files; a project that does not keep them turns this check off with the
// require_pairs: false setting.
type MigrationDuplicateVersionRule struct {
	*rules.BaseRule

	// pairsRequired enables the up/down pair check (setting require_pairs).
	pairsRequired bool

	// Cross-file state, same pattern as cross-file-duplicate.
	mu   sync.Mutex
	seen map[string]map[string]migrationID // dir -> numeric version -> first migration
}

// migrationID is a migration file name without its direction.
type migrationID struct {
	version string // as written, leading zeros included
	name    string
}

// NewMigrationDuplicateVersionRule creates the rule
func NewMigrationDuplicateVersionRule() *MigrationDuplicateVersionRule {
	return &MigrationDuplicateVersionRule{
		BaseRule: rules.NewBaseRule(
			"migration-duplicate-version",
			"patterns",
			"Detects two different migrations sharing one version number, and migrations without an up/down pair (require_pairs, on by default)",
			core.SeverityCritical,
		),
		pairsRequired: true,
		seen:          make(map[string]map[string]migrationID),
	}
}

// Configure reads require_pairs: whether every migration must have both an
// .up.sql and a .down.sql file.
func (r *MigrationDuplicateVersionRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.pairsRequired = true
	raw, ok := settings["require_pairs"]
	if !ok {
		return nil
	}
	required, ok := raw.(bool)
	if !ok {
		return fmt.Errorf("configure migration-duplicate-version: require_pairs must be a boolean, got %T", raw)
	}
	r.pairsRequired = required
	return nil
}

// ResetState clears the migrations seen so far, so that a project root never
// inherits versions registered while analyzing a previous root.
func (r *MigrationDuplicateVersionRule) ResetState() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = make(map[string]map[string]migrationID)
}

// numericVersion is the version as golang-migrate reads it: the number, so
// leading zeros do not make two versions different. Trimming the zeros keeps
// the digits exact however long the version is.
func numericVersion(version string) string {
	trimmed := strings.TrimLeft(version, "0")
	if trimmed == "" {
		return "0"
	}
	return trimmed
}

// AnalyzeFile registers migration files and reports duplicate versions
func (r *MigrationDuplicateVersionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !strings.HasSuffix(ctx.Path, ".sql") {
		return nil
	}
	m := migrationFileRe.FindStringSubmatch(filepath.Base(ctx.Path))
	if m == nil {
		return nil
	}
	dir := filepath.Dir(ctx.Path)
	id := migrationID{version: m[1], name: m[2]}

	var violations []*core.Violation
	if r.pairsRequired {
		if v := r.checkPairing(ctx, m[3]); v != nil {
			violations = append(violations, v)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	byVersion, ok := r.seen[dir]
	if !ok {
		byVersion = make(map[string]migrationID)
		r.seen[dir] = byVersion
	}
	key := numericVersion(id.version)
	existing, ok := byVersion[key]
	if !ok {
		byVersion[key] = id
		return violations
	}
	if existing == id {
		return violations // the up/down pair of the same migration
	}

	v := r.CreateViolation(ctx.RelPath, 1,
		"Duplicate migration version "+key+": '"+existing.version+"_"+existing.name+"' and '"+id.version+"_"+id.name+
			"' — version-keyed migrators fail on the duplicate or silently drop one of them")
	v.WithSuggestion("Renumber this migration to the next free version and record the applied version on existing environments")
	return append(violations, v)
}

// checkPairing reports a missing up/down counterpart of the migration file:
// without the down file the migration cannot be rolled back, and a down file
// without its up belongs to no migration.
func (r *MigrationDuplicateVersionRule) checkPairing(ctx *core.FileContext, direction string) *core.Violation {
	counterpartDir := map[string]string{"up": "down", "down": "up"}[direction]
	counterpart := strings.TrimSuffix(ctx.Path, direction+".sql") + counterpartDir + ".sql"
	if _, err := os.Stat(counterpart); err == nil {
		return nil
	}
	message := "Migration has no paired .down.sql — it cannot be rolled back"
	if direction == "down" {
		message = "Down migration has no paired .up.sql — it rolls back a migration that does not exist"
	}
	v := r.CreateViolation(ctx.RelPath, 1, message)
	v.Severity = core.SeverityHigh
	v.WithSuggestion("Create the missing ." + counterpartDir + ".sql (an empty rollback is still an explicit file), " +
		"or set require_pairs: false if the project does not keep down migrations")
	return v
}
