package patterns

import (
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
// Version-keyed migrators (maps, golang-migrate) silently keep only one of
// them — a fresh database ends up missing the other migration's schema.
// Every migration must own a unique version number, and the migrator itself
// should fail on duplicates (defense-in-depth: this rule catches the problem
// at lint time).
type MigrationDuplicateVersionRule struct {
	*rules.BaseRule

	// Cross-file state, same pattern as cross-file-duplicate.
	mu   sync.Mutex
	seen map[string]map[string]string // dir -> version -> migration name
}

// NewMigrationDuplicateVersionRule creates the rule
func NewMigrationDuplicateVersionRule() *MigrationDuplicateVersionRule {
	return &MigrationDuplicateVersionRule{
		BaseRule: rules.NewBaseRule(
			"migration-duplicate-version",
			"patterns",
			"Detects two different migrations sharing one version number",
			core.SeverityCritical,
		),
		seen: make(map[string]map[string]string),
	}
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
	dir, version, name := filepath.Dir(ctx.Path), m[1], m[2]

	r.mu.Lock()
	defer r.mu.Unlock()

	byVersion, ok := r.seen[dir]
	if !ok {
		byVersion = make(map[string]string)
		r.seen[dir] = byVersion
	}
	existing, ok := byVersion[version]
	if !ok {
		byVersion[version] = name
		return nil
	}
	if existing == name {
		return nil // the up/down pair of the same migration
	}

	v := r.CreateViolation(ctx.RelPath, 1,
		"Duplicate migration version "+version+": '"+existing+"' and '"+name+"' — version-keyed migrators silently drop one of them")
	v.WithSuggestion("Renumber this migration to the next free version and record the applied version on existing environments")
	return []*core.Violation{v}
}
