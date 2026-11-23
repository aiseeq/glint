package qarules

import "github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"

// CacheInputs identifies the migration bytes used by the rule.
func (r *TestFixtureWriteOverriddenByDBTriggerRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}

// ReadsOtherFiles reports that the rule reads the migrations besides the file
// it checks, so its cached findings are keyed by CacheInputs.
func (*TestFixtureWriteOverriddenByDBTriggerRule) ReadsOtherFiles() bool { return true }
