package qarules

import "github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"

// CacheInputs identifies the migration bytes used by the rule.
func (r *TestFixtureWriteOverriddenByDBTriggerRule) CacheInputs(root string) (string, error) {
	return patternkit.SchemaInputsHash(root, r.BaseRule)
}
